from bridge import BitchatProtocol, IdentityManager
import binascii

def debug_packet():
    print("--- Debugging TX Packet ---")
    
    # Initialize Identity (mocks if file missing, but bridge.py handles that)
    id_mgr = IdentityManager()
    proto = BitchatProtocol(id_mgr)
    
    # Generate a chat packet
    text = "Hello World"
    packet = proto.encode_chat(text)
    
    print(f"Generated Packet (Hex): {binascii.hexlify(packet).decode('utf-8')}")
    print(f"Packet Length: {len(packet)}")
    
    # Decode attempt (loopback check)
    decoded = BitchatProtocol.decode(packet)
    print(f"Decode Result: {decoded}")

if __name__ == "__main__":
    debug_packet()
