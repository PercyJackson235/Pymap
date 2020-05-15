#!/usr/bin/env python3
from pyping import pyping, create_list
from scapy.all import IP, TCP, sr1
import concurrent.futures

class Scanner:
    def __init__(self, targets, threads=None, ports=None, pings=False, no_scan=False):
        self.targets = targets
        self.threads = threads
        self.ports = ports
        self.ping = pings
        self.no_scan = no_scan
        self.results = {}

    def portlister(self):
        '''Takes in an string of comma delemited ports and 
        returns a list of ports as integers. If ports are
        dashed (i.e., 19-25), it will be converted into a 
        list of integers with a range of the starting port
        and ending port (i.e. [19, 20, 21, 22, 23, 24, 25])'''
        ports = self.ports.split(',')
        portlist = []
        for i in ports:
            if '-' in i:
                fst, lst = i.split('-')
                portlist.extend([a for a in range(int(fst),int(lst)+1)])
            else:
                portlist.extend([int(i)])
        self.ports = portlist

    def portscan(self, target):
        '''A port scanner powered by scapy. Allows us to create 
        packets how ever we like. Takes a target and a list of
        ports, and returns a list of ports that resonded with a
        SYN-ACK.'''
        packets = [ i for i in IP(dst=target)/TCP(dport=self.ports,flags="S") ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            scan = executor.map(self.packetsend,packets)
        scan = [ i for i in scan if i != None ]
        return [ i for i in scan if i[TCP].flags.value == 18 ]

    def packetsend(self, packet):
        response = sr1(packet, verbose=0, timeout=.1)
        return response

    def start(self):
        '''This function starts the Scanner Object'''
        if self.ping:
            self.targets = pyping(self.targets, self.threads)
        else:
            hosts = []
            for i in self.targets:
                hosts.extend(create_list(i))
            self.targets = hosts
        if not self.no_scan:
            self.portlister()
            for target in self.targets:
                result = self.portscan(target)
                self.results[target] = result
            for key in self.results.keys():
                if key != None:
                    print(f'Host:{key:>22}')
                    if len(self.results[key]) != 0:
                        if self.results.get(key) != None:
                            ports = sorted([int(i[TCP].sport) for i in self.results[key] ])
                            ports = [ str(i) for i in ports ]
                            for port in ports:
                                state = 'open'
                                port += '/tcp'
                                print(f'{port:<10}{state:>10}')
                    print()


