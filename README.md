# Bitchat-Meshtastic Bridge Experiment

![Vibecoded with Antigravity](https://img.shields.io/badge/Vibecoded%20with-Antigravity-bc14ff)

An experimental project to bridge the **Meshtastic** mesh network with **Bitchat** (a P2P secured chat for iOS/macOS).

## Background

### What is this?
This project aims to act as a bridge, allowing Bitchat users (typically on iPhones via BLE) to communicate over long distances using the Meshtastic LoRa mesh network. By running this bridge on a Mac (or eventually a Raspberry Pi), local Bitchat messages can be forwarded to the mesh and vice versa.

- **Meshtastic**: An open source, off-grid, decentralized, mesh networking project built to run on affordable, low-power devices.
- **Bitchat**: A secure, peer-to-peer, offline chat application for iOS/macOS that uses Bluetooth Low Energy (BLE) and Wi-Fi for local communication.

## Project Status

**⚠️ Experimental / Work in Progress**

This project is currently in an experimental state.

- **Tested Environment**: 
    - Apple Silicon Mac (M2) running the bridge script.
    - iPhone running Bitchat.
- **Current Functionality**:
    - ✅ **RX (Receive)**: The Mac bridge successfully connects to the iPhone via BLE and receives messages sent from the Bitchat app.
    - ❌ **TX (Transmit)**: The Mac bridge can *send* packets to the iPhone, but the iPhone currently does not display them. This is likely due to strict packet signature or TTL validation logic in the Bitchat app that needs further reverse engineering.

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

### 3. Configuration
Copy the example environment file:
```bash
cp .env.example .env
```
Edit `.env` and fill in your device details:
```env
BITCHAT_UUID=<Your iPhone UUID>
BITCHAT_NICKNAME=MacBridge
```
*Note: You can find your iPhone's UUID using a BLE scanner app, or the script may help identify it.*

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

## Contributing
If you are interested in helping fix the TX (Transmit) issue, please submit a PR! We suspect the issue lies in how the `TTL` field is handled in the packet signature verification on the Receiving (iPhone) side.
