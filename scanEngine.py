#!/usr/bin/env python3
from pyping import pyping, create_list, dnsnames
from scapy.all import IP, TCP, sr1
import concurrent.futures
import random
from serviceEngine import serviceScanner
from itertools import chain

class Scanner:
    def __init__(self, targets, threads=None, ports=None, pings=False, no_scan=False, service_scan=False):
        self.targets = targets
        self.threads = threads
        self.ports = ports
        self.ping = pings
        self.no_scan = no_scan
        self.results = {}
        self.DomainNames = dnsnames
        self.service_scan = service_scan
        self.servicepool = ''

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
        random.shuffle(portlist)
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
        return target,[ i for i in scan if i.getlayer(TCP) != None if i[TCP].flags.value == 18 ]

    def packetsend(self, packet):
        response = sr1(packet, verbose=0, timeout=.1)
        return response

    def start(self):
        '''This function starts the Scanner Object'''
        if self.ping:
            self.targets = pyping(self.targets, self.threads)
            target_len = len(self.targets)
        else:
            # self.targets = (create_list(i) for i in self.targets)
            target_len = 0
            temp_targets = []
            for target in self.targets:
                target, num = create_list(target)
                target_len += num
                temp_targets.append(target)
            self.targets = chain.from_iterable(temp_targets)
            del temp_targets, num
        if not self.no_scan:
            self.portlister()
            # if len(self.targets) == 1:  # Going to have to find this, generators != len()
            if target_len == 1:
                for target in self.targets:
                    print(target)
                    _,result = self.portscan(target)
                    self.results[target] = result
            else:
                with concurrent.futures.ProcessPoolExecutor() as executor:
                    scanpool = executor.map(self.portscan, self.targets)
                    for target,result in scanpool:
                        self.results[target] = result
            for key in self.results.keys():
                if key != None:
                    if len(self.results[key]) != 0:
                        if self.results.get(key) != None:
                            ports = sorted([int(i[TCP].sport) for i in self.results[key] ])
                            if self.service_scan:
                                servicelister = serviceScanner((key,ports))
                                self.servicepool = servicelister.start()
                            ports = [ str(i) for i in ports ]
                            print(f'Host:{key:>22}')
                            for port in ports:
                                sport = int(port)
                                state = 'open'
                                port += '/tcp'
                                if self.service_scan and self.servicepool[sport] != None:
                                    if len(self.servicepool[sport]) != 0 and self.servicepool[sport] != None:
                                        print(f'{port:<10}{state:>10}')
                                        #if type(self.servicepool[sport][0]) == type(tuple()):
                                        if isinstance(self.servicepool[sport][0], tuple):
                                            print(self.servicepool[sport][0][0])
                                            print(self.servicepool[sport][0][1])
                                        else:
                                            print(self.servicepool[sport][0])
                                else:
                                    print(f'{port:<10}{state:>10}')
                    else:
                        print(f'Host:{key:>22}')
                        print('No Open Ports'.center(27))
                    print()
