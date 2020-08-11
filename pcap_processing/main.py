import argparse
import os
import sys
import packet_processing
import re


def main(argv):

    # Checking if the directory exists
    if not os.path.isdir(args.folder):
        print('"{}" does not exist'.format(args.folder), file=sys.stderr)
        sys.exit(-1)
    
    # Obtaining the mac_address from the folder
    # It must be considered that the mac address of the folder could not be in the correct format e.g. 0:26:29:0:77:ce but it is always valid
    # This problem is related to our folder
    myre = re.compile(r'(?:[0-9a-fA-F]:?){6,12}')
    mac_address = re.findall(myre, args.folder)
   
    # Verify path validity
    if not mac_address:
        print("Path {} not valid!".format(args.folder), file=sys.stderr)
        sys.exit(-1)
    
    mac_address = packet_processing.mac_address_fixer(mac_address[0])

    if args.packet_rate_final:
        packet_processing.packet_rate_final(args.folder, mac_address, args.window)

    if args.destinations_contacted:
        if args.src_address is None:
            print('you must specify the source ip address', file=sys.stderr)
            sys.exit(-1)
        
        packet_processing.destinations_contacted(args.folder, args.src_address)

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PCAP processer: It requires that all pcaps file are in a path which contains the mac address of the device to analyse (e.g. mac_address/subfolder/file.pcap or mac_address/file.pcap")

    # TODO change pcap with folder name
    parser.add_argument('-f', '--folder', metavar='<folder>',
                        help='folder containing pcap file to parse', type=str, required=True)
    parser.add_argument('--packet_rate_final', action='store_true',
                        help='packet rate considering all packets divided by protocol')
    parser.add_argument('--window','-w', type=int,
                        help='window size in secs')
    parser.add_argument('--destinations_contacted', action='store_true',
                        help='destinations contacted by a src address')
    parser.add_argument('--src_address', type=str,
                        help='src ip address')
    args = parser.parse_args()
    
    
    main(args)