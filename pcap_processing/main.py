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
    mac_address = packet_processing.mac_address_fixer(mac_address[0])
    
    if args.packet_rate:
        if args.window is None:
            packet_processing.packet_rate(args.folder, mac_address, False)
        else:
            packet_processing.packet_rate(args.folder, mac_address, False, window=args.window, plotting=True)
    if args.packet_rate_protocol:
        packet_processing.packet_rate_filtering_by_protocol(args.folder, mac_address, args.window)

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PCAP processer: It requires that all pcaps file are in a path which contains the mac address of the devices to consider (e.g. mac_address/subfolder/file.pcap or mac_address/file.pcap")

    # TODO change pcap with folder name
    parser.add_argument('-f', '--folder', metavar='<folder>',
                        help='folder containing pcap file to parse', type=str, required=True)
    parser.add_argument('--packet_rate', action='store_true',
                        help='packet rate considering all packets')
    parser.add_argument('--packet_rate_protocol', action='store_true',
                        help='packet rate considering all packets divided by protocol')
    parser.add_argument('--window','-w', type=int,
                        help='window size in secs')
    
    
    args = parser.parse_args()
    
    
    main(args)