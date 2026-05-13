import struct
import binascii
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519

# Captured Packet (Identity Announce)
# Hex string from debug log
HEX_DATA = "0101070000019c54a4c40502004e030a5822fec820f60109616e6f6e796d6f75730220030a5822fec820f622e96d74116496030959828236d39695669f649bfba432920320fd9098e986c75125950007823f66810c950d877f3e8b090e434de548842af5858ee42f9fb8442be7e17426174a713998782fe31e08920958db82e75e921dcdfc8b06c55cc5e2e3077e68205f25bf6083049ab46362547071"

def verify_sig():
    print("--- Verifying Signature with TLV Parsing & Padding ---")
    data = bytes.fromhex(HEX_DATA)
    
    # 1. Parse Header
    # Header size: 14 bytes
    header = data[:14]
    
    # Header Fields
    # Ver(1) Type(1) TTL(1) Time(8) Flags(1) Len(2)
    ver = header[0]
    m_type = header[1]
    ttl = header[2]
    # Time (8 bytes)
    flags = header[11]
    p_len = struct.unpack(">H", header[12:14])[0]
    
    print(f"Header: Ver={ver} Type={m_type} TTL={ttl} Flags={flags:02x} Len={p_len}")

    # 2. Parse Packet Body
    cursor = 14
    sender_id = data[cursor : cursor+8]
    cursor += 8
    
    # Payload
    payload = data[cursor : cursor+p_len]
    cursor += p_len
    
    # Signature
    signature = data[cursor : cursor+64]
    cursor += 64
    
    print(f"SenderID: {sender_id.hex()}")
    print(f"Payload Len: {len(payload)}")
    print(f"Signature Len: {len(signature)}")

    # 3. Parse TLV (Best Effort / Truncated)
    print("\n--- Parsing TLV (Best Effort) ---")
    noise_key = None
    signing_key = None
    
    # We expect Nick(11) + Noise(34) + Sign(34) = 79.
    # We have 78 bytes.
    # Missing 1 byte at end?
    
    # Nickname
    if payload[0] == 0x01:
        n_len = payload[1]
        nick = payload[2:2+n_len].decode('utf-8')
        print(f"Nickname: {nick}")
        offset = 2+n_len # 11
    
    # Noise Key
    if payload[offset] == 0x02: # Tag
        # Len is payload[offset+1] (0x20)
        offset += 2
        noise_key = payload[offset : offset+32]
        print(f"Noise Key: {noise_key.hex()}")
        offset += 32 # 11+2+32 = 45
        
    # Signing Key (Likely Truncated)
    if offset < len(payload) and payload[offset] == 0x03:
        offset += 2
        # We expect 32 bytes, but might have 31
        signing_key_fragment = payload[offset:]
        print(f"Signing Key Fragment ({len(signing_key_fragment)} bytes): {signing_key_fragment.hex()}")
        
        if len(signing_key_fragment) == 31:
             print("Key is truncated by 1 byte. Attempting Brute Force...")
             
             # Try all 256 possibilities for last byte
             found = False
             for i in range(256):
                 missing_byte = bytes([i])
                 candidate_key = signing_key_fragment + missing_byte
                 candidate_payload = payload + missing_byte
                 
                 # Reconstruct Packet with Candidate Payload
                 header_signing = bytearray(header)
                 header_signing[2] = 0x00 # TTL=0
                 header_signing[11] = header_signing[11] & ~0x02 & ~0x10
                 
                 unsigned_packet =  header_signing + sender_id + candidate_payload
                 
                 # Pad to 256
                 # Len 14+8+79 = 101.
                 # Pad needed: 256 - 101 = 155 (0x9B)
                 pad_len = 256 - len(unsigned_packet)
                 padding = bytes([pad_len] * pad_len)
                 signed_blob = unsigned_packet + padding
                 
                 try:
                     verify_key = ed25519.Ed25519PublicKey.from_public_bytes(candidate_key)
                     verify_key.verify(signature, bytes(signed_blob))
                     print(f"\n[!!! SUCCESS !!!] Verified with missing byte: 0x{i:02x}")
                     print(f"Full Signing Key: {candidate_key.hex()}")
                     found = True
                     break
                 except:
                     continue
            
             if not found:
                 print("\n[FAIL] Brute force failed.")
             return

    # Fallback if no truncation logic triggered
    if not noise_key or not signing_key:
        print("[FAIL] Keys parsing failed (not truncated?)")
        return

if __name__ == "__main__":
    verify_sig()
