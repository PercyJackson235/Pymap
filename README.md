# Pymap

## Concept
This is a little Network Scanner written in python.

### Why
* It is mostly an exercise in progamming, different computer communication protocols, projecting, and learning some of what is possible.
* This tool won't be beating out tools like Nmap or the others, but that isn't it's job.

### What it does
- This is eventually going to be a full network scanning tool.
  - currently has the ability to ping multiple hosts on the network.
  - is able to discover TCP ports.

  
## Requirements
- Currently only supported on linux
- This tool depends on icmplib, scapy, ldap3, and impacket
  - Packages can be installed with `pip3 install -r requirements.txt`.
- This tool also needs to be run as root or with sudo because it create raw packets.
- Leans on the Impacket Library for SMB Connections. That is not my own creation.
  - Impacket Library is included with Pymap as impacketEngine, mostly because I was having
    problems pip installing it properly, and the preferred way to install Impacket includes the
    installing of the example tools onto your system, which is a little intrusive for this tool.

## Similar applications
- I have not made anything like this before, but this project was partially inspired by Nmap.
