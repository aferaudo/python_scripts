import datetime
import os
from enum import Enum
from collections import Counter
from scapy.utils import RawPcapReader
from scapy.layers.all import *

# TODO Future upgrades: the links provided give csv file with this matching, so it could be cool to create these dictionaries starting from there


class PktDirection(Enum):
    not_defined = 0
    outgoing = 1
    incoming = 2


# To add other protocol layer 2, look at this link: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
protocol_mapping_l2 = {
    'ARP': 0x0806,
    'IPv4': 0x0800,
    'IEEE 802.1X': 0x0888E,
    'IPv6': 0x086DD
}

# To add other protocol numbers (layer 3), look at this link: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
protocol_mapping_l3 = {
    'ICMP': 1,
    'IGMP': 2,
    'TCP': 6,
    'UDP': 17,
    'IPv6': 41,
    'IPv6-ICMP': 58,
    'TTP': 84, # Transaction Transfer Protocol
    'MTP': 92, # Multicast Transport Protocol
    'SMP': 121, # Simple Message Protocol
}


# Utility method
def direction_view(direction):
    if direction == PktDirection.incoming:
        return "<--"
    elif direction == PktDirection.outgoing:
        return "-->"
    else:
        return "---"


# Utility method
def logs_data_writing(file_1, window=-1):
    if window != -1:
        file_1.write("-------------------:Window::{}:-------------------\n".format(window))
    else:
        file_1.write("-------------------:NEW-PcapFile:-------------------\n")

# Utility method
def file_log_counter_writing(opened_file, counter_dict, window=-1):
    total = 0
    for key in counter_dict.keys():
        if key == PktDirection.incoming:
            opened_file.write('Incoming:{}\n'.format(counter_dict[key]))
        else:
            opened_file.write('Outgoing:{}\n'.format(counter_dict[key]))
        
        total += counter_dict[key]
    
    opened_file.write("Total:{}\n\n".format(total))


# Utility method
def file_log_counter_writing_protocol(opened_file, counter_dict, separator="", window=-1):
    for (proto, direction) in counter_dict.keys():
        pkts = counter_dict.get((proto,direction))
        opened_file.write("{}{}:Protocol:::{}...{}\n".format(separator, direction_view(direction), proto, pkts))


# Utility method
def mac_address_fixer(mac_address):
    """The folders provided use to have only a single zero when multiple zero are present in the same part of the address
    e.g. 00:af:... 0:af
    Args:
        mac_address: mac address to be fixed
    """
    new_mac = ''
    for value in mac_address.split(':'):
        new_mac += ('0' + value) if len(value) == 1 else value
        new_mac += ':'
    
    return new_mac[:-1]


# Utility method
def print_timestamp_first_last(file_name):
    """
    This method prints the first and the last timestamp of the packets composing the pcap file in the format Day, Month, Year HH:MM:SS
    Args:
        filename: pcap file
    """
    
    counter = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        counter += 1

        if counter == 1:
            # first_timestamp = datetime.datetime.fromtimestamp(pkt_metadata.sec).strftime("%A, %B %d, %Y %I:%M:%S")
            first_timestamp = datetime.datetime.fromtimestamp(pkt_metadata.sec)
            first_timestamp = first_timestamp + datetime.timedelta(microseconds=pkt_metadata.usec)
            # Debugging
            # print("{} {}".format(pkt_metadata.sec, pkt_metadata.usec))
            # print(first_timestamp.timestamp())
        
        last_timestamp = datetime.datetime.fromtimestamp(pkt_metadata.sec)
        last_timestamp = last_timestamp + datetime.timedelta(microseconds=pkt_metadata.usec)
    
    print("{}: First packet captured at {}, last packet captured {}".format(file_name, first_timestamp, last_timestamp))



# Utility method
def computing_timestamp(pkt_metadata):
    timestamp = datetime.datetime.fromtimestamp(pkt_metadata.sec)
    return (timestamp + datetime.timedelta(microseconds=pkt_metadata.usec)).timestamp()



def destinations_contacted(folder, src_address):
    """
    This method provides an overview about the destinations contacted by a devices with a specific ip address. 
    Particularly, the methods return the number of packets send to all the destions
    Args:
        folder: folder containing pcap files
        src_address: ip address to analalyse
        plotting: plot the result obtained
    """
    counter = Counter()
    output_file_name = "destination_contacted" + src_address + ".log"

    out_file = open(output_file_name,'w')

    # Ordering Files in the directory (useful for window purposes)
    files = sorted(os.listdir(folder))

    for filename in files:
        
        if not filename.endswith(".pcap"):
            print("Not processed {} ...".format(filename))
            continue
            
        file_name = folder + filename
        print("Processing {} ...".format(file_name))
        for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
            
            # Obtaining ether packet 
            ether_pkt = Ether(pkt_data)
            
            if 'type' not in ether_pkt.fields:
                # LLC frames will have 'len' instead of 'type'.
                # We disregard those
                continue
            
            if ether_pkt.type != protocol_mapping_l2.get('IPv4'):
                continue
            
            ip_pkt = ether_pkt[IP]
            
            if ip_pkt.src != src_address:
                continue

            counter[ip_pkt.dst] += 1
    
    out_file.write("Destinations contacted by {}: \n".format(src_address))
    for key in counter.keys():
        out_file.write("{}::{}\n".format(key, counter[key]))
    
    out_file.close()
    

# Avoid to process the same pcap file multiple times
def packet_rate_final(folder, mac_address, window=None):
    """
    The method produces an output file containing the packet rates organised in layers (e.g. IPv4...1000)
    Args:
        folder: folder containing pcap files
        mac_address: device to be analysed
        window: sliding window allows to select count the packets send or received in a certain time window(default None) (time is in secs)
    """
    # TODO Add diurnal and nocturnal window
    # TODO Add new interesting protocols

    last_folder = folder.split("/")[-2]

    # Loggging organization
    path = "./processing_results/"
    if not os.path.isdir(path):
        os.mkdir(path)
    path += mac_address + "/"
    if not os.path.isdir(path):
        # It is possible that the directory was created in other calls of the method
        os.mkdir(path)
    #################################

    output_file_name = path + mac_address + "_rate_by_protocol_" +  last_folder + "_" + str(window) + ".log"
    # output_file_name_general = mac_address + "_rate_" + last_folder+ "_" + str(window) + ".log"

    # Layers refer to TCP/IP stack (layer1: Host-to-network, layer2: Internet(Network), layer3: Transport, layer4: Application)
    protocols_packet_counter_layer_1 = Counter()
    protocols_packet_counter_layer_2 = Counter()
    protocols_packet_counter_layer_3 = Counter()
    general_packet_counter = Counter()

    general_counter = 0 # Timestamp guideline
    window_counter = 0 # Useful for logging purposes

    protocols_code_l3 = list(protocol_mapping_l3.values())
    protocols_code_l2 = list(protocol_mapping_l2.values())

    # useful for debug = checking that all the packets were counted
    # debug = 0

    # In case of window enabled, the relative_timestamp must be set to zero before looping on the files
    relative_timestamp = 0 

    # Open log file
    log_file = open(output_file_name,'w')
    # log_file_general = open(output_file_name_general,'w')

    # Ordering Files in the directory (useful for window purposes)
    files = sorted(os.listdir(folder))
    total_files = len(files)

    # terminal log
    file_log = 0

    # Loop in the directory
    for filename in files:
        
        file_log += 1
        
        if not filename.endswith(".pcap"):
            print("Not processed {} ...".format(filename))
            continue
            
        file_name = folder + filename
        print("Processing {} ...".format(file_name))

        for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
            
            general_counter += 1
            
            # If window is enabled we should get the timestamp and reset all counters
            if not window is None:

                # Computing timestamp
                if general_counter == 1: # This is useful only for the first packet (Is there a clever way?)
                    # Computing first_timestamp
                    first_timestamp = computing_timestamp(pkt_metadata)
                
                last_timestamp = computing_timestamp(pkt_metadata)
                
                relative_timestamp = last_timestamp - first_timestamp
                

                if relative_timestamp >= window:
                    # Useful logs writing
                    logs_data_writing(log_file, window=window_counter)

                    # Counters writing
                    file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_1, window=window_counter)
                    file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_2, window=window_counter)
                    file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_3, separator="\t", window=window_counter)
                    file_log_counter_writing(log_file, general_packet_counter, window=window_counter)

                    window_counter += 1
                    
                    # Reset counters
                    protocols_packet_counter_layer_1.clear() # Deletes all the elements keys + values
                    protocols_packet_counter_layer_2.clear()
                    protocols_packet_counter_layer_3.clear()
                    general_packet_counter.clear()

                    general_counter = 1

                    # Computing another time the first_timestamp
                    first_timestamp = computing_timestamp(pkt_metadata)

                    # Reset relative_timestamp
                    relative_timestamp = 0
            
            # Obtaining ether packet
            ether_pkt = Ether(pkt_data)
            
            direction = PktDirection.not_defined
            
            if 'type' not in ether_pkt.fields:
                # LLC frames will have 'len' instead of 'type'.
                # We do not consider them in this analysis
                protocols_packet_counter_layer_1[('UNDEFINED-L1', direction)] += 1
                continue
            
            
            # Considering only outbound packets
            if ether_pkt.src != mac_address and ether_pkt.dst != mac_address:
                continue

            # Defining direction
            if ether_pkt.src == mac_address:
                direction = PktDirection.outgoing
            else:
                direction = PktDirection.incoming
            
            # Counting all the input and output packets 
            general_packet_counter[direction] += 1
            
            # In this method only IP packets are considered (interesting for our purposes)
            if ether_pkt.type != protocol_mapping_l2.get('IPv4'):
                # It is possible that the type value is not our mapping
                if ether_pkt.type in protocols_code_l2:
                    protocols_packet_counter_layer_2[(list(protocol_mapping_l2.keys())[protocols_code_l2.index(ether_pkt.type)], direction)] += 1
                else:
                    print("Unrecognized type l2: {}".format(ether_pkt.type))
                    protocols_packet_counter_layer_2[('UNDEFINED-L2', direction)] += 1
                continue
            
            protocols_packet_counter_layer_2[('IPv4',direction)] += 1
            
            ip_pkt = ether_pkt[IP]

            if ip_pkt.proto == protocol_mapping_l3.get('TCP'):
                
                if not ip_pkt.haslayer(TCP):
                    # Some pcap files are not complete, so some packet could be halved
                    continue
                protocols_packet_counter_layer_3 [('TCP',direction)] += 1
                
                tcp_pkt = ip_pkt[TCP]
                
                if 'S' in str(tcp_pkt.flags) and not 'A' in str(tcp_pkt.flags):
                    # Useful to understand the normal SYN traffic (avoiding SYN flood attacks)
                    protocols_packet_counter_layer_3[("TCP-SYN-REQ-TO-" + ip_pkt.dst,direction)] +=1

            elif ip_pkt.proto in protocols_code_l3:
                protocols_packet_counter_layer_3 [(list(protocol_mapping_l3.keys())[protocols_code_l3.index(ip_pkt.proto)], direction)] += 1
            
            else:
                print("Unrecognized L-3: {}".format(ip_pkt.proto))
                protocols_packet_counter_layer_3 [('UNDEFINED-L3', direction)] += 1

        
        if window is None:

            # Useful logs writing
            logs_data_writing(log_file)

            # Counters writing
            file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_1)
            file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_2)
            file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_3, separator="\t")
            file_log_counter_writing(log_file, general_packet_counter)

            # Reset Counter
            protocols_packet_counter_layer_1.clear() # Deletes all the elements keys + values
            protocols_packet_counter_layer_2.clear()
            protocols_packet_counter_layer_3.clear()
            general_packet_counter.clear()
        

        print("{}: {}/{} files analysed...".format(mac_address, file_log, total_files))
        
    if not window is None:
        # In this case we have to write the packets counted but still not written

        # Useful logs writing
        logs_data_writing(log_file, window=window_counter)

        # Counters writing
        file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_1, window=window_counter)
        file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_2, window=window_counter)
        file_log_counter_writing_protocol(log_file, protocols_packet_counter_layer_3, separator="\t", window=window_counter)
        file_log_counter_writing(log_file, general_packet_counter, window=window_counter)


    log_file.close()
    print("done.")
