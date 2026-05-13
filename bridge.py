import asyncio
import os
import json
import struct
import time
import hashlib
import uuid
from dotenv import load_dotenv, set_key
from bleak import BleakClient, BleakScanner

# Cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

# --- CONFIGURATION ---
ENV_FILE = ".env"
load_dotenv(ENV_FILE)
KEY_FILE = "mac_identity.json"
CHUNK_SIZE = 20

# --- PROTOCOL CONSTANTS ---
TYPE_IDENTITY = 0x01
TYPE_CHAT     = 0x02
TYPE_REQUEST  = 0x20
TYPE_REQUEST  = 0x20
TYPE_ACK      = 0x21

# Bitchat Service UUID
SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"

# --- HELPER CLASSES ---

class MessagePadding:
    """
    Implements Bitchat's privacy padding (PKCS#7 style to optimal block size).
    Reference: MessagePadding.swift
    """
    BLOCK_SIZES = [256, 512, 1024, 2048]

    @staticmethod
    def pad(data: bytes) -> bytes:
        length = len(data)
        # Account for encryption overhead (approx 16 bytes for AES-GCM tag in Bitchat)
        total_size = length + 16
        
        target_size = length # fallback
        for bs in MessagePadding.BLOCK_SIZES:
            if total_size <= bs:
                target_size = bs
                break
        
        if target_size == length:
            return data

        padding_needed = target_size - length
        if padding_needed <= 0 or padding_needed > 255:
            return data
            
        # PKCS#7: All pad bytes are equal to the pad length
        return data + bytes([padding_needed] * padding_needed)

    @staticmethod
    def unpad(data: bytes) -> bytes:
        if not data: return data
        pad_len = data[-1]
        if pad_len == 0 or pad_len > len(data): return data
        
        # Verify padding? Bitchat swift checks if all bytes match.
        padding = data[-pad_len:]
        for b in padding:
            if b != pad_len: return data # Invalid padding
            
        return data[:-pad_len]

class AnnouncementPacket:
    """
    TLV Encoded Announcement Packet.
    """
    TYPE_NICKNAME = 0x01
    TYPE_NOISE_KEY = 0x02
    TYPE_SIGN_KEY = 0x03
    TYPE_NEIGHBORS = 0x04

    def __init__(self, nickname, noise_pub, sign_pub):
        self.nickname = nickname
        self.noise_pub = noise_pub
        self.sign_pub = sign_pub

    def encode(self) -> bytes:
        data = bytearray()
        
        # TLV Nickname
        nick_bytes = self.nickname.encode('utf-8')[:255]
        data.append(self.TYPE_NICKNAME)
        data.append(len(nick_bytes))
        data.extend(nick_bytes)
        
        # TLV Noise Key
        data.append(self.TYPE_NOISE_KEY)
        data.append(len(self.noise_pub))
        data.extend(self.noise_pub)
        
        # TLV Signing Key
        data.append(self.TYPE_SIGN_KEY)
        data.append(len(self.sign_pub))
        data.extend(self.sign_pub)
        
        return bytes(data)

class PrivateMessagePacket:
    """
    TLV Encoded Private Message Packet (Inner Payload).
    Reference: Packets.swift
    """
    TYPE_MSG_ID = 0x00
    TYPE_CONTENT = 0x01
    
    def __init__(self, msg_id, content):
        self.msg_id = msg_id
        self.content = content
        
    def encode(self) -> bytes:
        data = bytearray()
        
        # TLV Msg ID
        mid_bytes = self.msg_id.encode('utf-8')[:255]
        data.append(self.TYPE_MSG_ID)
        data.append(len(mid_bytes))
        data.extend(mid_bytes)
        
        # TLV Content
        txt_bytes = self.content.encode('utf-8')[:255]
        data.append(self.TYPE_CONTENT)
        data.append(len(txt_bytes))
        data.extend(txt_bytes)
        
        return bytes(data)

class IdentityManager:
    def __init__(self):
        self.load_keys()
    
    def load_keys(self):
        if not os.path.exists(KEY_FILE):
            self._gen_new()
        else:
            try:
                with open(KEY_FILE, "r") as f:
                    data = json.load(f)
                    self.sign_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["sign"]))
                    self.enc_key = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(data["enc"]))
            except:
                self._gen_new()

        self.sign_pub = self.sign_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.enc_pub = self.enc_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        digest = hashlib.sha256(self.sign_pub).digest()
        self.sender_id = digest[:8] 
        self.node_id_hex = f"!{self.sender_id.hex()}"
        print(f"[KEY] Identity: {self.node_id_hex}")

    def _gen_new(self):
        print(f"[INFO] Generating New Keys and saving to {KEY_FILE}...")
        self.sign_key = ed25519.Ed25519PrivateKey.generate()
        self.enc_key = x25519.X25519PrivateKey.generate()
        with open(KEY_FILE, "w") as f:
            json.dump({
                "sign": self.sign_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()).hex(),
                "enc": self.enc_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()).hex()
            }, f)

    def sign(self, data: bytes) -> bytes:
        return self.sign_key.sign(data)

class BitchatProtocol:
    def __init__(self, identity):
        self.id = identity

    def encode_chat(self, text):
        """
        Constructs Chat Payload:
        PrivateMessagePacket (TLV)
        """
        # Generate random message ID
        msg_id = str(uuid.uuid4())
        packet = PrivateMessagePacket(msg_id, text)
        return self._packet(TYPE_CHAT, packet.encode())

    def encode_identity(self):
        name = os.getenv("BITCHAT_NICKNAME", "Bridge")
        # Ensure we send the keys correctly
        packet = AnnouncementPacket(
            nickname=name,
            noise_pub=self.id.enc_pub,
            sign_pub=self.id.sign_pub
        )
        return self._packet(TYPE_IDENTITY, packet.encode())

    def _packet(self, type_byte, payload):
        ts = int(time.time()*1000)
        
        # 1. LIVE HEADER (TTL = 7, Flags = 0x02 for HasSignature)
        # Reverted to 14-Byte Header (Ver, Type, TTL, Time, Flags, Len)
        live_hdr = struct.pack(">BBBQBH", 1, type_byte, 7, ts, 0x02, len(payload))
        
        # 2. SIGNING LOGIC
        # We must sign the "Canonical" serialization of the packet.
        # Rule 1: TTL is 0.
        # Rule 2: Signature Flag (0x02) is cleared.
        # Rule 3: RSR Flag (0x10) is cleared (we aren't setting it anyway).
        
        sign_hdr = struct.pack(">BBBQBH", 1, type_byte, 0, ts, 0x00, len(payload))
        
        # Unsigned Blob: Header(Modified) + SenderID + Payload
        unsigned_blob = sign_hdr + self.id.sender_id + payload
        
        # Rule 4: PADDING
        # The signature is calculated over the PADDED blob.
        padded_blob = MessagePadding.pad(unsigned_blob)
        
        # Sign
        sig = self.id.sign(padded_blob)
        
        # 3. Construct Final Wire Packet
        # Live Header + SenderID + Payload + Signature
        # Note: The wire packet itself is NOT padded for these message types.
        final_packet = live_hdr + self.id.sender_id + payload + sig
        
        return final_packet

    @staticmethod
    def decode(data: bytes):
        # DEBUG: Print Raw Hex
        # print(f"[DEBUG] RX HEX: {data.hex()}")
        
        if len(data) < 22: return ""
        try:
            m_type = data[1]
            # Reverted to 14-byte header offsets (Len at 12:14)
            p_len = struct.unpack(">H", data[12:14])[0]
            
            if len(data) < 22 + p_len: return ""
            payload = data[22 : 22 + p_len]
            
            if m_type == TYPE_IDENTITY: return "[Type 1] (Identity)"
            if m_type == TYPE_REQUEST:  return "[Type 32] (Request)"
            if m_type == TYPE_ACK:      return "[Ack]"
            
            if m_type == TYPE_CHAT:
                # Try to decode TLV PrivateMessagePacket
                try:
                    # Quick TLV parser for MsgID(00) and Content(01)
                    cursor = 0
                    content = ""
                    while cursor + 2 <= len(payload):
                        t_type = payload[cursor]
                        t_len = payload[cursor+1]
                        cursor += 2
                        if cursor + t_len > len(payload): break
                        val = payload[cursor : cursor+t_len]
                        cursor += t_len
                        
                        if t_type == 0x01: # Content
                            content = val.decode('utf-8')
                            
                    if content:
                        return f"Message: {content}"
                        
                    # Fallback to old format if needed?
                    return "(Private Message)"
                except:
                    return payload.decode('utf-8', errors='ignore')

            return f"[Type {m_type}]"
        except Exception as e:
            print(f"[ERR] Decode: {e}")
            return ""

class BitchatBridge:
    def __init__(self):
        self.uuid = os.getenv("BITCHAT_UUID")
        self._orig_w_uuid = os.getenv("WRITE_UUID")
        self._orig_n_uuid = os.getenv("NOTIFY_UUID")
        
        self.w_uuid = self._orig_w_uuid
        self.n_uuid = self._orig_n_uuid
        
        # If config has standard UUIDs (0000...), ignore them to force rescan
        # BUT keep them as fallback in _orig_*
        if self.w_uuid and self.w_uuid.startswith("0000"): self.w_uuid = None
        if self.n_uuid and self.n_uuid.startswith("0000"): self.n_uuid = None
        
        self.cli = None
        self.proto = BitchatProtocol(IdentityManager())
        self.send_queue = asyncio.Queue()

    async def ble_worker(self):
        while True:
            pkt = await self.send_queue.get()
            if self.cli and self.cli.is_connected:
                for i in range(0, len(pkt), CHUNK_SIZE):
                    chunk = pkt[i:i+CHUNK_SIZE]
                    try: 
                        # Try with response=True first
                        await self.cli.write_gatt_char(self.w_uuid, chunk, response=True)
                    except: 
                        # Fallback to response=False (Write Without Response)
                        try: await self.cli.write_gatt_char(self.w_uuid, chunk, response=False)
                        except Exception as e: 
                            print(f"\n[WARN] Write Err: {e}")
                            pass
                    await asyncio.sleep(0.015) 
            self.send_queue.task_done()

    async def queue_packet(self, pkt):
        await self.send_queue.put(pkt)

    async def notify(self, s, d):
        # Debug: Print raw packet to verify reception
        msg = BitchatProtocol.decode(d)
        if msg:
            if "[Type 1]" in msg:
                # Gossip Identity back
                print(f"[RX] Peer Announce")
                await self.queue_packet(self.proto.encode_identity())
            elif "[Type 32]" in msg:
                print("[TX] Answered Identity Request")
                await self.queue_packet(self.proto.encode_identity())
            elif "[Ack]" in msg:
                pass 
            else:
                # If we see our own message echoed back (Loopback), filter it or print it
                my_nick = os.getenv("BITCHAT_NICKNAME", "Bridge")
                if my_nick in msg:
                    print(f"\r[RX-Echo]: {msg}")
                else:
                    print(f"\r[RX]: {msg}")
                
                print("[INPUT] Type to send: ", end="", flush=True)

    async def input_loop(self):
        print("\n[INFO] Bridge Ready.")
        print("[INPUT] Type to send: ", end="", flush=True)
        while True:
            t = await asyncio.to_thread(input)
            if t.strip() == "exit": break
            if self.cli and self.cli.is_connected:
                await self.queue_packet(self.proto.encode_chat(t))
                print(f"   [dt_queue] (Queued)")
                print("[INPUT] Type to send: ", end="", flush=True)

    async def start(self):
        print("--- [Meshtastic-Bitchat Bridge Experiment] ---")

        # 0. Ensure .env exists and is valid
        env_path = os.path.abspath(ENV_FILE)
        print(f"[INFO] Loading Config from: {env_path}")

        if not os.path.exists(ENV_FILE) or os.path.getsize(ENV_FILE) == 0:
            print(f"[INFO] {ENV_FILE} missing or empty. Creating default...")
            with open(ENV_FILE, "w") as f:
                f.write("BITCHAT_UUID=\n")
                f.write("BITCHAT_NICKNAME=MacBridge\n")
                f.write("# Optional: Manually set Write/Notify UUIDs if auto-discovery fails\n")
                f.write("# WRITE_UUID=\n")
                f.write("# NOTIFY_UUID=\n")
            
        # Reload to pick up defaults
        load_dotenv(ENV_FILE)
        # Re-read UUID
        self.uuid = os.getenv("BITCHAT_UUID")
        
        # Scan for devices if UUID is missing or generic
        if not self.uuid:
             print("[INFO] BITCHAT_UUID not set in .env. Scanning for Bitchat devices...")
             # Inspect script found this service UUID: f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c
             
             # Use return_adv=True to get RSSI reliably
             devices = await BleakScanner.discover(service_uuids=[SERVICE_UUID], timeout=5.0, return_adv=True)
             
             if devices:
                 # devices is a dict: address -> (device, advertisement_data)
                 # Sort by RSSI (strongest signal first)
                 target_pair = sorted(devices.values(), key=lambda p: p[1].rssi, reverse=True)[0]
                 target_device = target_pair[0]
                 
                 print(f"[INFO] Found Device: {target_device.name} ({target_device.address})")
                 self.uuid = target_device.address
                 
                 # Save to .env
                 set_key(ENV_FILE, "BITCHAT_UUID", self.uuid)
                 
                 # Set default nickname if missing
                 if not os.getenv("BITCHAT_NICKNAME"):
                     set_key(ENV_FILE, "BITCHAT_NICKNAME", "MacBridge")
                     print(f"[INFO] Set default nickname: MacBridge")
             else:
                 print("[WARN] No Bitchat devices found via BLE Scan.")
                 print(f"[INFO] Please manually configure {ENV_FILE} with your BITCHAT_UUID if known.")
                 return

        print(f"[INFO] Connecting to {self.uuid}...")

        async with BleakClient(self.uuid) as client:
            self.cli = client
            print("[INFO] Connected!")
            
            # Smart Discovery: Find the best characteristic (Write + Notify)
            if not self.w_uuid or not self.n_uuid:
                print(f"[INFO] Auto-discovering services...")
                best_char = None
                best_score = -1

                for s in client.services:
                    for c in s.characteristics:
                        score = 0
                        props = c.properties
                        
                        # HUGE Bonus if it belongs to the known Bitchat Service
                        if str(s.uuid) == SERVICE_UUID:
                            score += 100
                        
                        # Penalize standard/system services to avoid false positives
                        if str(c.uuid).startswith("0000"):
                            score -= 5
                        
                        # Bonus for custom UUIDs (likely the target)
                        if not str(c.uuid).startswith("0000"):
                            score += 10

                        if "write" in props or "write-without-response" in props:
                            score += 10
                        if "notify" in props:
                            score += 10
                        
                        # Perfect match: Write + Notify
                        if ("write" in props or "write-without-response" in props) and "notify" in props:
                            score += 20

                        if score > best_score:
                            best_score = score
                            best_char = c

                if best_char:
                    print(f"[INFO] Found Best Characteristic: {best_char.uuid} (Score: {best_score})")
                    self.w_uuid = best_char.uuid
                    self.n_uuid = best_char.uuid
                    
                    # Persist to .env
                    set_key(ENV_FILE, "WRITE_UUID", str(self.w_uuid))
                    set_key(ENV_FILE, "NOTIFY_UUID", str(self.n_uuid))
                else:
                    print("[WARN] Could not find a suitable characteristic.")

            # Fallback to .env values if scan failed
            
            # Fallback to .env values if scan failed
            if not self.w_uuid and self._orig_w_uuid:
                print(f"[WARN] Scan failed for Write Char, using .env: {self._orig_w_uuid}")
                self.w_uuid = self._orig_w_uuid

            if not self.n_uuid and self._orig_n_uuid:
                print(f"[WARN] Scan failed for Notify Char, using .env: {self._orig_n_uuid}")
                self.n_uuid = self._orig_n_uuid
            
            # Critical check before crashing
            if not self.n_uuid:
                print("[ERROR] No Notify Characteristic found! Check device or .env configuration.")
                return
            
            await client.start_notify(self.n_uuid, self.notify)
            
            worker_task = asyncio.create_task(self.ble_worker())
            
            # Announce
            print("[TX] Sending Identity Announce...")
            await self.queue_packet(self.proto.encode_identity())
            await asyncio.sleep(0.5)
            await self.queue_packet(self.proto.encode_identity())
            
            try:
                await self.input_loop()
            finally:
                worker_task.cancel()

if __name__ == "__main__":
    try: asyncio.run(BitchatBridge().start())
    except KeyboardInterrupt: print("\n[INFO] Stopped")