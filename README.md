# Wi-Fi Jammer

<p align="center">
  <img src="assets/no-wifi.ico" />
</p>

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)  ![Kali](https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)

A Python script to perform a de-authentication attack on a Wi-Fi network using Scapy.


## Introduction
This Python script utilizes Scapy to perform a de-authentication attack on a Wi-Fi network. The de-authentication attack can be targeted towards a specific Access Point (AP) and its associated clients. This script is intended for educational and research purposes only.

## Requirements
- Python 3.0 or later
- Scapy library

## Usage

```console
python3 jammer.py <count> <options> <interface>
```

## Options
`count`: Number of de-authentication frames to send. Use 0 to keep sending infinitely.
`-a`, `--bssid`: Set the Access Point MAC address.
`-c`, `--client`: Set the Destination MAC address (client).
`-i`, `--interval`: Set the time between each frame. Example: -i 0.7 (default is 0.0).
`interface`: Interface name in monitor mode.

## Key Features

- **De-authentication Attack**: Sends de-authentication frames to disconnect clients from a targeted Access Point.

- **Customization**: Allows users to specify the number of de-authentication frames, target AP MAC address, client MAC address, time interval between frames, and the network interface in monitor mode.

- **Infinitely Looping Attack**: Optionally, the script can be configured to continuously send de-authentication frames until manually interrupted.

- **Real-time Information**: Displays relevant information during the attack, such as target BSSID, client MAC, number of de-authentication packets, working wireless card, and the current time.

## Example
```bash
python3 jammer.py 77 -a qw:er:ty:ui:op:77 -c as:df:gh:jk:07:08 -i 0.5 wlan0
```
## Screenshot
![](screenshots\Screenshot_2023-12-09_212651.png)

## Disclaimer
This script is provided for educational and research purposes only. It is crucial to respect the laws and regulations governing network security in your jurisdiction. Unauthorized access to computer networks is illegal and unethical.
