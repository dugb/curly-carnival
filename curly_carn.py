#!/usr/bin/env python

import scapy.all as scapy
import argparse


def parse_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('-i', '--interface', dest='interface', help='The interface to sniff packets from.')
  options = parser.parse_args()
  if not options.interface:
    parser.error('[-] Please specify an interface, see --help for more info.')
  return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    print(packet)


options = parse_args()
sniff(options.interface)