import struct
import binascii

# The HEX string captured from the iPhone TX (RX on bridge)
RX_HEX = "0102070000019c549d90e3020002baf2dbd7c3bd952f596f72370b5f5dbdcf11380ef2206864bd9549f87d31d844d16c78c560c1b032c2f2826925a93154c8b9308b1db009f6beb25227540c542667d7170948a932016106"

def analyze():
    print(f"Total Bytes: {len(RX_HEX) // 2}")
    data = bytes.fromhex(RX_HEX)
    
    # Hypothesis: 13 Byte Header
    # 0:Ver, 1:Type, 2:TTL, 3-10:Time, 11-12:Len
    hdr_len = 13
    hdr = data[:hdr_len]
    ver, type_byte, ttl, ts, p_len = struct.unpack(">BBBQH", hdr)
    
    print(f"\n--- Header (13 bytes) ---")
    print(f"Ver: {ver}")
    print(f"Type: {type_byte}")
    print(f"TTL: {ttl}")
    print(f"Time: {ts} (ms) -> {(ts/1000):.2f}s")
    print(f"Payload Len Field: {p_len} (0x{p_len:04x})")
    
    # Check Sender ID (8 bytes)
    sender_id = data[hdr_len : hdr_len + 8]
    print(f"Sender ID: {sender_id.hex()}")
    
    # Check Payload + Signature
    # Payload starts at 13 + 8 = 21
    remaining = data[21:]
    print(f"Remaining Data Len: {len(remaining)}")
    print(f"Remaining Hex: {remaining.hex()}")
    
    # Let's inspect the payload
    # It starts with "59 6f" ("Yo")? 
    # Wait, the hex dump has "59 6f" at index ... ?
    # 01 02 07 ... e3 02 00 02 ba ... 2f 59 6f
    # 02 ba ... is Sender ID? No. Sender ID is 8 bytes.
    # 02 00 is Length.
    # Next byte: 02 ?? (Wait, 02 00 02 ??)
    
    # Let's assume 14 byte header:
    # 01 02 07 ... e3 02 00 (Flags?) 02 (Len?)
    # If 14-byte header:
    # Flags = 02 (Signed)
    # Len = 00 02 (Big Endian) -> 2 ?? Or Little Endian 02 00 -> 512??
    
    # Let's re-examine index 11, 12, 13
    # Bytes: ... e3 (10), 02 (11), 00 (12), 02 (13), ba (14) ...
    # If Header is 13 bytes:
    # Len = 02 00 (512).
    # SenderID starts at 13: 02 ba f2 db d7 c3 bd 95 (8 bytes)?
    # Then Payload starts at 21: 2f 59 6f ...
    # 2f = '/' ?? 
    # 59 6f = 'Yo'.
    # This looks plausible! sender ID starting with 02ba...
    
    # Let's look closer at the inner payload (Chat Struct)
    # Payload[0] = 2f ??
    # Bitchat Chat Struct: Flags(1) Time(8) UUIDLen(1) UUID...
    # If 2f is Flags, that's weird (usually 0x00).
    # If SenderID was actually at 14? (14-byte header)
    # Header 14 bytes.
    # 13: 02 (Len LSB, sending 2 bytes??)
    # SenderID starts at 14: ba f2 db ...
    # Payload starts at 22: 2f 59 6f...
    
    # Wait, 2f 59 6f = "/Yo" ?
    # Did the user type "/Yo"? Or just "Yo"?
    # User said: "[RX]: Yo"
    
    # Let's verify standard Bitchat Chat Struct again.
    # [Flags(1)][Time(8)][UUIDLen(1)] ...
    
    # Hypothesis: 13-Byte Header is CORRECT.
    # Header: 13 bytes.
    # SenderID: 8 bytes (Indices 13-20).
    # Payload Starts: Index 21.
    
    sender_id_13 = data[13:21]
    print(f"\n--- Assuming 13-Byte Header ---")
    print(f"Sender ID: {sender_id_13.hex()}")
    
    payload_start = 21
    payload = data[payload_start:]
    print(f"Payload (Raw): {payload.hex()}")
    print(f"Payload (First 10 bytes): {payload[:10].hex()}")
    print(f"Payload (UTF-8 attempt): {payload.decode('utf-8', errors='replace')}")
    
    # Check first byte of payload
    first_byte = payload[0]
    print(f"First Byte: 0x{first_byte:02x} ({chr(first_byte)})")
    
    # If First Byte is '/', maybe it's a command?
    # User sent "Yo".
    # Payload starts with `2f` ('/').
    # Then `59 6f` ('Yo').
    # Then `72 37` ('r7').
    # Then `0b` ...
    
    # Hypothesis: The first byte IS a flag/type.
    # Bitchat Message Struct: [Flags(1)] ...
    # 0x2f = 0010 1111.
    # Flags: IsRelay(1), IsPrivate(2), HasOriginalSender(4), HasRecipient(8)...
    # This seems like a lot of flags set for a simple "Yo".
    
    # Alternative: First byte is part of a UUID?
    # Message Struct: [Flags][Time][UUIDLen][UUID]
    # If 0x2f is Flags, next 8 bytes is Time?
    # `59 6f 72 37 0b 5f 5d bd` -> 0x596f72370b5f5dbd.
    # This is a huge number.
    # Time usually starts with 00 00 01... (for recent years)
    # UNLESS it's Little Endian?
    # `bd 5d 5f 0b 37 72 6f 59` -> 1.36... x 10^19. Still huge.
    
    # Maybe the Payload is DIFFERENT for Type 2?
    # Or maybe the Header length field (0x0200) implies something else?
    
    pass

if __name__ == "__main__":
    analyze()
