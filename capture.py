#!/usr/bin/python3

import signal
import sys
from optparse import OptionParser
from scapy.all import *
from datetime import datetime, timedelta
from netaddr import EUI, NotRegisteredError
from mongoengine import connect, DoesNotExist
from mongoengine.queryset.visitor import Q
from py2neo import Graph, Node, Relationship, NodeSelector

from models import Probe, Beacon, Data, Device


connect('wispy_data')

graph = Graph('http://neo4j:neo4j@127.0.0.1:7474/db/data')
selector = NodeSelector(graph)

class Term:
    RED   = "\033[1;31m"  
    BLUE  = "\033[1;34m"
    CYAN  = "\033[1;36m"
    GREEN = "\033[0;32m"
    RESET = "\033[0;0m"
    BOLD  = "\033[;1m"

def is_beacon(pkt):
    return (pkt.type == 0 and pkt.subtype == 8)

def is_probe(pkt):
    return (pkt.type == 0 and pkt.subtype == 4)

def is_response(pkt):
    return (pkt.type == 0 and pkt.subtype == 5)

def is_data(pkt):
    return (pkt.type == 2)

def get_device(addr):
    try:
        device = Device.objects.get(mac=addr)
    except DoesNotExist: # Create the entry
        device = Device(mac=addr)
        try:
            vendor = EUI(addr).oui.registration().org
        except NotRegisteredError:
            vendor = "Unknown"
        device.vendor = vendor

    return device

# Keep track of wireless access points
def parse_beacon(dtg, addr, ssid):
    device = get_device(addr)
    
    recent = Device.objects(Q(events__timestamp__gte=datetime.utcnow() - timedelta(minutes=10)) | Q(events__ssid__ne=ssid), mac=addr)
    if len(recent) == 0:
        event = Beacon()
        event.ssid = ssid
        event.timestamp = datetime.utcnow()
        device.events.append(event)
        device.save()

        dev = selector.select('Device', mac=addr).first()
        if dev == None:
            dev = Node('Device', mac=addr, last_seen=str(datetime.utcnow()), vendor=device.vendor)
            graph.create(dev)
        
        ss = selector.select('SSID', ssid=ssid).first()
        if ss == None:
            ss = Node('SSID', ssid=ssid, timestamp=str(datetime.utcnow()))
            graph.create(ss)

        if len(list(graph.match(start_node=dev, rel_type='beacon', end_node=ss))) == 0:
            rel = Relationship(dev, 'beacon', ss)
            graph.create(rel)
        
        print("%s[+] (%s) AP beacon: %s (%s) -> '%s'" % (Term.GREEN, dtg, addr, device.vendor, ssid))

# Keep track of probing clients
def parse_probe(dtg, addr, ssid):
    device = get_device(addr)
    
    recent = Device.objects(Q(events__timestamp__gte=datetime.utcnow() - timedelta(minutes=10)) | Q(events__ssid__ne=ssid), mac=addr)
    if len(recent) == 0:
        event = Probe()
        event.ssid = ssid
        event.timestamp = datetime.utcnow()
        device.events.append(event)
        device.save()
        
        dev = selector.select('Device', mac=addr).first()
        if dev == None:
            dev = Node('Device', mac=addr, last_seen=str(datetime.utcnow()), vendor=device.vendor)
            graph.create(dev)

        ss = selector.select('SSID', ssid=ssid).first()
        if ss == None:
            ss = Node('SSID', ssid=ssid, timestamp=str(datetime.utcnow()))
            graph.create(ss)

        if len(list(graph.match(start_node=dev, rel_type='probe', end_node=ss))) == 0:
            rel = Relationship(dev, 'probe', ss)
            graph.create(rel)
        
        print("%s[+] (%s) Probe: %s (%s) -> '%s'" % (Term.CYAN, dtg, addr, device.vendor, ssid))
    
def parse_data(dtg, addr, bssid):
    device = get_device(addr)

    recent = Device.objects(Q(events__timestamp__gte=datetime.utcnow() - timedelta(minutes=10)) | Q(events__dest__ne=bssid), mac=addr)
    if len(recent) == 0:
        event = Data()
        event.timestamp = datetime.utcnow()
        event.dest = bssid
        device.events.append(event)
        device.save()

        dev = selector.select('Device', mac=addr).first()
        if dev == None:
            dev = Node('Device', mac=addr, last_seen=str(datetime.utcnow()), vendor=device.vendor)
            graph.create(dev)
        
        bs = selector.select('Device', mac=bssid).first()
        if bs == None:
            bs = Node('Device', mac=bssid, vendor=device.vendor, last_seen=str(datetime.utcnow()))
            graph.create(bs)

        if len(list(graph.match(start_node=dev, rel_type='data', end_node=bs))) == 0:
            rel = Relationship(dev, 'data', bs)
            graph.create(rel)

        print("%s[+] (%s) Data: %s (%s) -> %s" % (Term.BLUE, dtg, addr, device.vendor, bssid))

def parse_response(dtg, addr, dest, ssid):
    device = get_device(addr)

    recent = Device.objects(Q(events__timestamp__gte=datetime.utcnow() - timedelta(minutes=10)) | Q(events__dest__ne=ssid), mac=addr)
    if len(recent) == 0:
        event = Beacon()
        event.timestamp = datetime.utcnow()
        event.ssid = ssid
        device.events.append(event)
        device.save()

        dev = selector.select('Device', mac=dest).first()
        if dev == None:
            dev = Node('Device', mac=dest, last_seen=str(datetime.utcnow()), vendor=device.vendor)
            graph.create(dev)

        ss = selector.select('SSID', ssid=ssid).first()
        if ss == None:
            ss = Node('SSID', ssid=ssid, timestamp=str(datetime.utcnow()))
            graph.create(ss)

        if len(list(graph.match(start_node=dev, rel_type='probe', end_node=ss))) == 0:
            rel = Relationship(dev, 'response', ss)
            graph.create(rel)
            print('Hidden SSID Discovered %s -> %s' % (dest, ssid))    

# Parse out beacons and probes
def parse_pkt(pkt):
    dtg = datetime.utcnow()
    if pkt.haslayer(Dot11):
        #print("%d%d" % (pkt.type, pkt.subtype))
        if is_beacon(pkt):
            parse_beacon(dtg, str(pkt.addr2), pkt.info.decode('utf-8', 'backslashreplace'))
        elif is_probe(pkt):
            parse_probe(dtg, str(pkt.addr2), pkt[Dot11Elt].info.decode('utf-8', 'backslashreplace'))
        elif is_data(pkt):
            parse_data(dtg, str(pkt.addr2), str(pkt.addr3))
        elif is_response(pkt):
            parse_response(dtg, str(pkt.addr2), str(pkt.addr3), pkt.info.decode('utf-8', 'backslashreplace'))

# Parse args and start sniffing!
def main(argv):
    parser = OptionParser("usage: %prog [options]")
    parser.add_option("-i", "--iface", dest="iface",
        help="Interface (in monitor mode) to use for packet capture")
    (opts, args) = parser.parse_args()
    
    if not opts.iface:
        print("[+] Defaulting to mon0")
        opts.iface = "mon0"
    
    try:
        sniff(filter="", iface=opts.iface, prn=parse_pkt, store=False)
    except Exception as e:
        raise(e)
 
# Catch KeyboardInterrupt
def sig_handler(signal, frame):
    print("%s[!] Exiting!" % Term.RESET)
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sig_handler)
    main(sys.argv[1:])
