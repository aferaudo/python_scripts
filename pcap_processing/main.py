import argparse
import os
import sys
import packet_processing


def main(argv):
    if args.packet_rate:
        if args.window is None:
            packet_processing.packet_rate(args.pcap, "00:26:29:00:77:ce", False, plotting=True)
        else:
            packet_processing.packet_rate(args.pcap, "00:26:29:00:77:ce", False, window=args.window, plotting=True)
    if args.packet_rate_protocol:
        packet_processing.packet_rate_filtering_by_protocol(args.pcap, "00:26:29:00:77:ce", args.window)

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PCAP reader")

    # TODO change pcap with folder name
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', type=str, required=True)
    parser.add_argument('--packet_rate', action='store_true',
                        help='packet rate considering all packets')
    parser.add_argument('--packet_rate_protocol', action='store_true',
                        help='packet rate considering all packets divided by protocol')
    parser.add_argument('--window','-w', type=int,
                        help='window size in secs')
    
    
    args = parser.parse_args()
    
    
    main(args)