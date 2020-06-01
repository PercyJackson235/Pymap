#!/usr/bin/python3
import ftplib
import http.client
import telnetlib
import re
import socket
from impacketEngine.smbconnection import SMBConnection
from impacketEngine.examples.smbclient import MiniImpacketShell as _MiniImpacketShell
from impacketEngine import smb, smb3
import ssl
from ldap3 import Connection, Server, ALL
from random import choice
from string import ascii_letters
from collections import Counter

def ftpservice(host, port=21):
    """FTP Enumerator"""
    ftp = ftplib.FTP()
    ftp.connect(host=host, port=port)
    banner = ftp.welcome
    try:
        ftp.login()
        try:
            ftplist = []
            ftp.retrlines('LIST',ftplist.append)
            return (banner,'\n'.join(ftplist))
        except ftplib.all_errors:
            return banner
    except ftplib.all_errors:
        return banner

def httpservice(host, port=80):
    """HTTP Banner Grabber"""
    client = http.client.HTTPConnection(host, port)
    client.request('head','/')
    resp = client.getresponse()
    banner = None
    for header in resp.getheaders():
        if 'Server' in header:
            banner = header[-1]
    return banner

def httpsservice(host, port=443):
    """HTTPS Banner Grabber"""
    client = http.client.HTTPSConnection(host, port)
    try:
        client.request('head','/')
    except ssl.SSLCertVerificationError:
        client.close()
        context = ssl._create_unverified_context()
        client = http.client.HTTPSConnection(host, port, context=context)
        client.request('head','/')
    resp = client.getresponse()
    banner = None
    for header in resp.getheaders():
        if 'Server' in header:
            banner = header[-1]
    client.close()
    return banner

def telnetservice(host, port=23):
    """Telnet Banner Grabber"""
    regex = re.compile(br'.*(login)( )?:.*',re.IGNORECASE)
    reglist = [regex]
    client = telnetlib.Telnet(host=host)
    match = client.expect(reglist)
    banner = match[-1].decode().splitlines()
    banner.remove(banner[-1])
    banner = '\n'.join([line for line in banner if len(line) != 0])
    client.close()
    return banner

def sshservice(host, port=22):
    """SSH Banner Grabber"""
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.connect((host,port))
    result = client.recv(1024).decode()
    client.close()
    banner = '\n'.join(result.splitlines())
    return banner

def fingerservice(host, port=79, file=None):
    """Finger Service User Enumerator"""
    file = open(file,'r')
    text = [line.strip() for line in file.readlines()]
    file.close()
    result = [fingerenum(host,port,user) for user in text]
    result = 'Users:\n'+ '\n'.join([ans for ans in result if ans != None])
    return result

'''I need to set up the user file'''

def fingerenum(host, port, user):
    """Finger Enumerator"""
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.setsockopt(socket.SO_REUSEADDR, 1)
    client.connect((host, port))
    client.send(bytes(user,'utf-8'))
    client.send(b'\r\n')
    resp = client.recv(1024).decode()
    client.close()
    if '?' not in resp:
        return user
    else:
        return None

class MiniImpacketShell(_MiniImpacketShell):
    """A Copy of impackets MiniImpacketShell Class
        with an altered do_shares function."""
    def do_shares(self):
        result = []
        if self.loggedIn is False:
            return
        resp = self.smb.listShares()
        for i in range(len(resp)):
            result.append(resp[i]['shi1_netname'][:-1])
        result = '\n'.join(result)
        return result

def smbservice(host, port=445, user='', passwd=''):
    """SMB Service Enumerator"""
    try:
        conn = SMBConnection(host,host)
        banner = conn.getServerDNSHostName()
        conn.login(user,passwd)
        client = MiniImpacketShell(conn)
        shares = client.do_shares()
        return banner,shares
    except Exception:
        if banner == None:
            banner = 'Unknown'
        return banner

def ldapservice(host, port=389, user='', passwd=''):
    """LDAP Domain Dump"""
    server = Server(host, get_info=ALL)
    try:
        client = Connection(server)
        client.bind()
    except:
        client.unbind()
        return None
    dn = 'a' * 100000
    info = [server.info.vendor_name, server.info.vendor_version]
    for base in server.info.naming_contexts:
        if len(base) < len(dn):
            dn = base
    info = list(map(ldap_info, info))
    client.search(dn,'(objectclass=*)',attributes='*')
    results = client.entries
    client.unbind()
    info = '\n'.join([vendor for vendor in info if vendor != None])
    if info == '':
        return results
    return info,results

def ldap_info(info):
    if len(info) != 0:
        return '\n'.join(info)
    return None

def randemail():
    """Creates a fake email address."""
    userlen = list(range(3,13))
    servlen = list(range(9,20))
    user = server = ''
    userlen = choice(userlen)
    servlen = choice(servlen)
    for _ in range(userlen):
        user += choice(ascii_letters)
    for _ in range(servlen):
        server += choice(ascii_letters)
    server = list(server)
    if len(server) < 11:
        server[-4] = '.'
    else:
        server[-6] = '.'
        server[-10] = '.'
    server = ''.join(server)
    email = user + '@' + server
    return bytes(email, 'utf-8')

def smtpservice(host, port=25):
    client = socket.socket()
    client.connect((host, port))
    reg = re.compile(rb'220 (.*) ready')
    banner = client.recv(1024)
    banner = reg.searchbanner.group(1).decode()
    name = randemail()
    client.send(b'HELO '+name+b'\r\n')
    client.send(b'QUIT\r\n')
    client.close()
    return banner

def pop3service(host, port=110):
    """POP3 Banner Grabber"""
    client = socket.socket()
    client.connect((host, port))
    banner = client.recv(1024).decode().split()
    client.send(b'QUIT\r\n')
    client.close()
    banner.pop(0)
    banner.pop(-1)
    return ' '.join(banner)

def imapservice(host, port=143):
    """IMAP4 Banner Grabber"""
    client = socket.socket()
    client.connect((host, port))
    banner = client.recv(1024).decode().split('] ')[-1].split()
    banner.pop(-1)
    client.close()
    return ' '.join(banner)

enumerators = Counter({21 : ftpservice, 80 : httpservice, 443 : httpsservice, 445 : smbservice,
                       143 : imapservice, 389 : ldapservice, 110 : pop3service, 25 : smtpservice,
                       22 : sshservice, 23 :telnetservice})