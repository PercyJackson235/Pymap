#!/usr/bin/env python3
'''A network ping tool written in python'''
import socket
from icmplib import multiping
import re
import ipaddress
import argparse
from datetime import datetime
from decimal import Decimal

def create_list(hosts):
    '''Creates a list of valid ip addresses to ping.
    Takes a list of hosts as an argument and returns
    a list of valid ip addresses or stops execution
    and tells you the invalid hostname.'''
    ip_regex = re.compile(r'((\d{1,3}\.){3}\d{1,3})(/\d{,2})?')
    try:
        match = ip_regex.search(hosts)
        host = match.group(1)
        mask = match.group(3)
        mask = mask.lstrip('/')
    except AttributeError:
        if '/' in hosts:
            host = hosts.split('/')[0]
            mask = hosts.split('/')[1]
        else:
            host = hosts
            mask = None
            if bool(host.isdigit()):
                print(f'Host {host} is not valid because it is all digits.')
                exit(0)
        try:
            host = socket.gethostbyname(host)
        except:
            print(f'Host {host} is not valid.')
            exit(0)
    if mask == None:
        return [host]
    else:
        return [ str(i) for i in ipaddress.ip_network(host+'/'+mask, strict=False)]
        
def pyping(host_list=None, thr=300):
    '''Heart of pyping. This takes a list of hosts as an
    argument and returns a list of responding hosts. We 
    will ping all the hosts and return a list of hosts 
    that responded.'''
    a = datetime.now()
    targets = []
    results = []
    for i in host_list:
        targets.extend(create_list(i))
    try:
        targets = multiping(targets, max_threads=thr)
    except:
        print("Something Went Wrong!")
        exit(1)
    for target in targets:
        if target.is_alive:
            print(f'Host {target.address} is alive!')
            results.append(target)
    b = datetime.now() - a
    print(f'Scan took {str(b).split(":")[2]} seconds.')
    t = Decimal(str(b).split(':')[2])/len(targets)
    print(f'Each host took about {t:.2f} seconds.\nScanned {len(targets)} targets.')
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Just a Python Ping Tool.")
    parser.add_argument("targets", nargs='+', help="Hosts and/or Networks")
    parser.add_argument("-t","--threads", type=int, default=300, help="The amount of threads for pyping to use. Default is 300.")
    args = parser.parse_args()
    pyping(args.targets, args.threads)
