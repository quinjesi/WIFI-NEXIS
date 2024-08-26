# Wi-Fi Nexis

## Overview

**Wi-Fi Nexis** is a Python-based tool designed to analyze and improve the security of your Wi-Fi network. It scans for common vulnerabilities such as weak encryption, WPS availability, and unencrypted HTTP traffic. The tool provides actionable recommendations to enhance the security of your network.

## Features

- **Network Connection Detection**: Automatically detects the connected Wi-Fi network and performs security checks.
- **HTTP Traffic Analysis**: Captures and analyzes HTTP packets on your network to identify unencrypted traffic.
- **WPS Vulnerability Detection**: Scans the network to determine if WPS (Wi-Fi Protected Setup) is enabled.
- **Encryption Protocol Check**: Inspects the encryption protocol used by the network to ensure it's secure (e.g., WPA2/WPA3).
- **Security Recommendations**: Provides detailed suggestions to improve the security of your Wi-Fi network.

## Installation

To run this script, you'll need Python 3 and a few additional packages installed on your system. 

## Prerequisites

- **Python 3**
- **Scapy**: `pip install scapy`
- **PyFiglet**: `pip install pyfiglet`
- **Network Management Tools**: `nmcli`, `iw`, `iwconfig`

### Installation Steps

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/your-username/wifi-nexis.git
    cd wifi-nexis
    ```

2. **Install Required Packages**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the Script**:
   ```bash
   python wifi_nexis.py

2. **Follow On-Screen Instructions**:
   - The script will automatically detect your network connection and Wi-Fi interface.
   - It will perform several security checks and display recommendations based on the results.
   - You can choose to rerun the script or exit.

3. **Output Files**:
   - HTTP Packets: Captured packets are stored in `http_packets.pcap`.
   - WPS Scan Results: WPS-related information is saved in `scan_results.txt`.
   - Encryption Information: Details about the network's encryption protocol are saved in `encryption_info.txt`.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

Special thanks to the developers of the tools and libraries used in this project, including Scapy and PyFiglet.


   
