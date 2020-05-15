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
- Needs python3.7
- This tool depends on icmplib and scapy
  - Both packages can be install with `pip3 install icmplib scapy`.
  - Packages can be installed with `pip3 install -r requirements.txt`.
- This tool also needs to be run as root or with sudo because it create raw packets.

## Similar applications
- I have not made anything like this before, but this project was partially inspired by Nmap.
