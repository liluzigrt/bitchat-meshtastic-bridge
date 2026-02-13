import asyncio
import os
import json
import struct
import time
import hashlib
import uuid
from dotenv import load_dotenv, set_key
from bleak import BleakClient
from bleak import BleakClient

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
TYPE_ACK      = 0x21

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
        print("[INFO] Generating New Keys...")
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

    def pkcs7_pad(self, data: bytes) -> bytes:
        """STRICT PKCS#7 Padding."""
        length = len(data)
        if length < 256: target = 256
        elif length < 512: target = 512
        else: target = 1024
        
        padding_len = target - length
        pad_byte = padding_len if padding_len < 256 else 0x00 
        return data + bytes([pad_byte] * padding_len)

    def encode_chat(self, text):
        """
        Constructs Chat Struct:
        [Flags(1)][Time(8)][UUIDLen(1)][UUIDString][NickLen(1)][Nick][MsgLen(2)][Msg]
        """
        flags = 0x00 
        ts = int(time.time() * 1000)
        
        msg_uuid_str = str(uuid.uuid4()).encode('utf-8')
        uuid_len = len(msg_uuid_str)
        
        nickname = os.getenv("BITCHAT_NICKNAME", "Bridge").encode('utf-8')
        nick_len = len(nickname)
        
        content = text.encode('utf-8')
        content_len = len(content)

        inner = struct.pack("<BQ", flags, ts)
        inner += struct.pack("B", uuid_len) + msg_uuid_str
        inner += struct.pack("B", nick_len) + nickname
        inner += struct.pack("<H", content_len) + content
        
        return self._packet(TYPE_CHAT, inner)

    def encode_identity(self):
        name = os.getenv("BITCHAT_NICKNAME", "Bridge").encode('utf-8')
        tlv = b'\x01' + bytes([len(name)]) + name
        tlv += b'\x02\x20' + self.id.sign_pub
        tlv += b'\x03\x20' + self.id.enc_pub
        return self._packet(TYPE_IDENTITY, tlv)

    def _packet(self, type_byte, payload):
        ts = int(time.time()*1000)
        
        # 1. LIVE HEADER (TTL = 7) - This goes on the wire
        # Header: Ver(1) Type(x) TTL(7) Time(8) Flags(2=Signed) Len(2)
        live_hdr = struct.pack(">BBBQBH", 1, type_byte, 7, ts, 0x02, len(payload))
        
        # 2. SIGNING
        # FIX: The iPhone might be expecting the specific wire bytes to be signed 
        # since it's a direct connection. We will sign the LIVE header.
        base_for_sig = live_hdr + self.id.sender_id + payload
        sig = self.id.sign(base_for_sig)
        
        # 4. Construct Final Packet
        final_packet = live_hdr + self.id.sender_id + payload + sig
        
        return self.pkcs7_pad(final_packet)

    @staticmethod
    def decode(data: bytes):
        if len(data) < 22: return ""
        try:
            m_type = data[1]
            p_len = struct.unpack(">H", data[12:14])[0]
            if len(data) < 22 + p_len: return ""
            payload = data[22 : 22 + p_len]
            
            if m_type == TYPE_IDENTITY: return "[Type 1] (Identity)"
            if m_type == TYPE_REQUEST:  return "[Type 32] (Request)"
            if m_type == TYPE_ACK:      return "[Ack]"
            
            if m_type == TYPE_CHAT:
                try:
                    cursor = 9
                    uuid_len = payload[cursor]
                    cursor += 1 + uuid_len
                    nick_len = payload[cursor]
                    cursor += 1
                    nick = payload[cursor:cursor+nick_len].decode('utf-8')
                    cursor += nick_len
                    msg_len = struct.unpack("<H", payload[cursor:cursor+2])[0]
                    cursor += 2
                    msg = payload[cursor:cursor+msg_len].decode('utf-8')
                    return f"{nick}: {msg}"
                except:
                    return payload.decode('utf-8', errors='ignore')

            return f"[Type {m_type}]"
        except: return ""

class BitchatBridge:
    def __init__(self):
        self.uuid = os.getenv("BITCHAT_UUID")
        self.w_uuid = os.getenv("WRITE_UUID")
        self.n_uuid = os.getenv("NOTIFY_UUID")
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
        
        # Scan for devices if UUID is missing or generic
        if not self.uuid:
             print("[ERROR] BITCHAT_UUID not set in .env")
             return

        print(f"[INFO] Connecting to {self.uuid}...")

        async with BleakClient(self.uuid) as client:
            self.cli = client
            print("[INFO] Connected!")
            
            if not self.w_uuid:
                for s in client.services:
                    for c in s.characteristics:
                        if "write" in c.properties: 
                            self.w_uuid = c.uuid
                            set_key(ENV_FILE, "WRITE_UUID", self.w_uuid)
                            print(f"Found Write Char: {self.w_uuid}")
                        if "notify" in c.properties: 
                            self.n_uuid = c.uuid
                            set_key(ENV_FILE, "NOTIFY_UUID", self.n_uuid)
                            print(f"Found Notify Char: {self.n_uuid}")
            
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