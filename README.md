# Bitchat-Meshtastic Bridge Experiment

![Vibecoded with Antigravity](https://img.shields.io/badge/Vibecoded%20with-Antigravity-bc14ff)

An experimental project to bridge the **Meshtastic** mesh network with **Bitchat** (a P2P secured chat for iOS/macOS).

## Background

### What is this?
This project aims to act as a bridge, allowing Bitchat users (typically on iPhones via BLE) to communicate over long distances using the Meshtastic LoRa mesh network. By running this bridge on a Mac (or eventually a Raspberry Pi), local Bitchat messages can be forwarded to the mesh and vice versa.

- **Meshtastic**: An open source, off-grid, decentralized, mesh networking project built to run on affordable, low-power devices.
- **Bitchat**: A secure, peer-to-peer, offline chat application for iOS/macOS that uses Bluetooth Low Energy (BLE) and Wi-Fi for local communication.

## Project Status

**Testing & Development**

- **Current Capabilities**:
    - ✅ **BLE Scanning**: Automatically finds Bitchat devices (iPhone/Mac) advertising the service.
    - ✅ **Identity Generation**: Creates and persists cryptographic keys (`mac_identity.json`) for the bridge.
    - ✅ **RX (Receive)**: Successfully connects and receives signed messages from Bitchat.
    - ✅ **Smart Discovery**: Auto-detects the best Write/Notify characteristics if standard ones fail.
    - ✅ **TX (Transmit)**: Successfully reverse-engineered the iOS signature padding rules and TLV packet structure. The bridge can now send verified, encrypted private messages to Bitchat.
    - ❌ **Meshtastic Integration**: Not yet implemented. This script currently only bridges Bitchat <-> Python (Host).

- **Next Steps**:
    - Integrate `meshtastic` python library to forward messages to the mesh.
    - Expand support for group chat messages and media types.

## Setup & Usage

### 1. Prerequisites
- Python 3.10+
- A Bitchat-compatible device (e.g., iPhone)

### 2. Installation
```bash
git clone <your-repo-url>
cd bridge
pip install -r requirements.txt
```

### 3. Configuration (Optional)
**Zero-Config Mode**: 
The bridge is designed to be plug-and-play. On first run:
1. It scans for any BLE device advertising the Bitchat service.
2. It automatically negotiates the best "Write" and "Notify" characteristics (Smart Discovery).
3. It saves the found device UUID and characteristics to `.env`.

**Manual Configuration**:
If you prefer to configure it manually or if auto-discovery fails:
1. Run the script once to generate the `.env` file.
2. Edit `.env` and fill in your device details:
```env
BITCHAT_UUID=<Your iPhone UUID>
BITCHAT_NICKNAME=MacBridge
```
*Note: You can find your iPhone's UUID using a BLE scanner app (like LightBlue or nRF Connect).*


### 4. Running
```bash
python3 bridge.py
```

### 5. Identity & Keys
The script uses cryptographic keys to identify itself on the mesh/chat.
- **`mac_identity.json`**: This file stores your **Ed25519** (Signing) and **X25519** (Encryption) keys. 
- **Auto-Generation**: If this file does not exist, `bridge.py` will automatically generate a fresh identity on the first run.
- **Resetting Identity**: If you wish to generate a new identity, simply delete `mac_identity.json` and run the script again.
- **Security**: Do not commit this file to GitHub! It is already excluded by `.gitignore`.

### 6. Troubleshooting

**"Permission Denied" or No Devices Found on macOS**:
- macOS requires apps to have explicit permission to use Bluetooth.
- If running from **Terminal**, you must grant Terminal access to Bluetooth in **System Settings > Privacy & Security > Bluetooth**.
- If running from VS Code, grant VS Code permission.

**Connection Failed**:
- Ensure Bitchat is open and in the foreground on the iPhone.
- Try toggling Bluetooth on the Mac.
- Delete `.env` to force a fresh scan if you changed devices.

## Contributing
Contributions are welcome! Specifically looking for help integrating the `meshtastic` python library to complete the bridge and route messages over the LoRa mesh network.
