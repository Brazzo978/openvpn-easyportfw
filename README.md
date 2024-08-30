# Openvpn installer for Gaming / having public ip behind cgnat

**This project is a bash script that aims to setup a Openvpn server that is specified for PERSONAL gaming or torrenting use. It supports only ONE client!**


The script **Port Forwards** the local port 1-65521 (also icmp) to the corresponding ports on the server side. These ports covered most of the ports used by any games. **Please make sure that there is no other application using these ports on the server, otherwise It will deafen any application that listens to these ports.** I highly suggest running this script on an new empty system. 

## The script will move ssh to port 65522 for not losing access to the server after installation.

The script supports both IPv4 and IPv6, but its preferred to use ipv4 as connection to the server.

## Gaming Improvement

For a better gaming experience, the server should be close to your living region and has a low ping value. You should ping the provider's looking glass datacenter IP first before purchasing a VPS. also look if the ip of the provider are in some blacklist that might impact your navigation.

## Requirements

Supported distributions:

- Ubuntu >= 18.04
- Debian > 10

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest. For most VPS providers, you can just enter through all the questions.

```bash
wget https://raw.githubusercontent.com/Brazzo978/openvpn-easyportfw/main/openvpn-setup.sh
chmod +x openvpn-setup.sh
./openvpn-setup.sh
```

## Stop / Restart / Uninstal

Run the script again will give you these options!
