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
def counters_logger(opened_file, counter_dict, window=-1, is_byte=False):
    total = 0
    for key in counter_dict.keys():
        if key == PktDirection.incoming:
            to_write = 'Incoming:{}\n'.format(counter_dict[key]) if not is_byte else 'Incoming bytes:{}\n'.format(counter_dict[key])
            opened_file.write(to_write)
        elif key == PktDirection.outgoing:
            to_write = 'Outgoing:{}\n'.format(counter_dict[key]) if not is_byte else 'Outgoing bytes:{}\n'.format(counter_dict[key])
            opened_file.write(to_write)
        else:
            to_write = 'Undefined direction:{}\n'.format(counter_dict[key]) if not is_byte else 'Undefined direction bytes:{}\n'.format(counter_dict[key])
            opened_file.write(to_write)
        total += counter_dict[key]
    
    to_write = "Total:{}\n\n".format(total) if not is_byte else "Total bytes:{}\n\n".format(total)
    opened_file.write(to_write)


# Utility method
def counters_logger_protocol(opened_file, counter_dict, separator=""):
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
def reset_counters(*counters):
    for counter in counters:
        counter.clear()

# Utility method
# def computing_timestamp(pkt_metadata):
#     print("metadata sec: {}".format(pkt_metadata.sec))
#     print("metadata usec: {}".format(pkt_metadata.usec))
#     timestamp = datetime.datetime.fromtimestamp(pkt_metadata.sec)
#     return (timestamp + datetime.timedelta(microseconds=pkt_metadata.usec)).timestamp()

def computing_timestamp(pkt_metadata):
    # New timestamp computation
    microseconds = (pkt_metadata.sec * 1000000) + pkt_metadata.usec
    return microseconds

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

    last_folder = folder.split("/")[-2]

    # Loggging organization #############
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
                # print(relative_timestamp)
                
                if relative_timestamp >= (window*1000000):
                    # Useful logs writing
                    logs_data_writing(log_file, window=window_counter)

                    # Counters writing
                    counters_logger_protocol(log_file, protocols_packet_counter_layer_1)
                    counters_logger_protocol(log_file, protocols_packet_counter_layer_2)
                    counters_logger_protocol(log_file, protocols_packet_counter_layer_3, separator="\t")
                    counters_logger(log_file, general_packet_counter, window=window_counter)
                    
                    # Debugging
                    # print("Start window {}: {}\nEnd window {}: {}".format(window_counter, first_timestamp, window_counter, last_timestamp))
                    
                    window_counter += 1
                    
                    # Reset counters
                    protocols_packet_counter_layer_1.clear() # Deletes all the elements keys + values
                    protocols_packet_counter_layer_2.clear()
                    protocols_packet_counter_layer_3.clear()
                    general_packet_counter.clear()

                    general_counter = 1

                    # Computing another time the first_timestamp
                    first_timestamp = computing_timestamp(pkt_metadata)
                    
                    # Debugging
                    # print("Window after upgrade {}".format(first_timestamp))

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
                    protocols_packet_counter_layer_2[(str(ether_pkt.type), direction)] += 1
                continue
            
            # Even if is an IPv4 packet it can be a halved packet
            if not ether_pkt.haslayer(IP):
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
                protocols_packet_counter_layer_3 [(str(ip_pkt.proto), direction)] += 1

        
        if window is None:

            # Useful logs writing
            logs_data_writing(log_file)

            # Counters writing
            counters_logger_protocol(log_file, protocols_packet_counter_layer_1)
            counters_logger_protocol(log_file, protocols_packet_counter_layer_2)
            counters_logger_protocol(log_file, protocols_packet_counter_layer_3, separator="\t")
            counters_logger(log_file, general_packet_counter)

            # Reset Counter
            protocols_packet_counter_layer_1.clear() # Deletes all the elements keys + values
            protocols_packet_counter_layer_2.clear()
            protocols_packet_counter_layer_3.clear()
            general_packet_counter.clear()
        

        print("{}: {}/{} files analysed...".format(mac_address, file_log, total_files))
        
    if not window is None:
        # In this case we have to write the packets counted but still not written
        print("Start window {}: {}\nEnd window {}: {}".format(window_counter, first_timestamp, window_counter, last_timestamp))
        # Useful logs writing
        logs_data_writing(log_file, window=window_counter)

        # Counters writing
        counters_logger_protocol(log_file, protocols_packet_counter_layer_1)
        counters_logger_protocol(log_file, protocols_packet_counter_layer_2)
        counters_logger_protocol(log_file, protocols_packet_counter_layer_3, separator="\t")
        counters_logger(log_file, general_packet_counter)


    log_file.close()
    print("done.")

def packet_rate_final_fixed_window(folder, mac_address, window=None):
    """
    The method produces an output file containing the packet rates organised in protocol layers (e.g. IPv4...1000)
    Args:
        folder: folder containing pcap files
        mac_address: device to be analysed
        window: sliding window allows to select count the packets send or received in a certain time window(default None) (time is in secs)
    """

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

    # Layers refer to TCP/IP stack (layer1: Host-to-network, layer2: Internet(Network), layer3: Transport, layer4: Application)
    protocols_packet_counter_layer_1 = Counter()
    protocols_packet_counter_layer_2 = Counter()
    protocols_packet_counter_layer_3 = Counter()
    general_packet_counter = Counter()
    bytes_counter = Counter()

    general_counter = 0 # Timestamp guideline
    window_counter = 0 # Useful for logging purposes

    protocols_code_l3 = list(protocol_mapping_l3.values())
    protocols_code_l2 = list(protocol_mapping_l2.values())

    # useful for debug = checking that all the packets were counted
    # debug = 0

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
        
        if os.stat(file_name).st_size == 0:
            print("{} is empty. Skipping...".format(file_name))
            continue

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
                
                while last_timestamp > first_timestamp + (window * 1000000):
                    # I need to move the window until I find the one able to host the packet

                    # Useful logs writing
                    logs_data_writing(log_file, window=window_counter)

                    # Counters writing
                    counters_logger_protocol(log_file, protocols_packet_counter_layer_1)
                    counters_logger_protocol(log_file, protocols_packet_counter_layer_2)
                    counters_logger_protocol(log_file, protocols_packet_counter_layer_3, separator="\t")
                    counters_logger(log_file, general_packet_counter)
                    counters_logger(log_file, bytes_counter, is_byte=True)
                    
                    # Debugging
                    # print("Start window {}: {}\nEnd window {}: {}".format(window_counter, first_timestamp, window_counter, last_timestamp))
                    
                    window_counter += 1
                    
                    # Reset counters
                    reset_counters(protocols_packet_counter_layer_1, 
                            protocols_packet_counter_layer_2, 
                            protocols_packet_counter_layer_3, 
                            general_packet_counter, 
                            bytes_counter)
                    
                    general_counter = 1

                    # Computing another time the first_timestamp
                    first_timestamp = first_timestamp + (window*1000000)
                    
                    # Debugging
                    # print("Window after upgrade {}".format(first_timestamp))
                    

            # Obtaining ether packet
            try:
                # There are some cases where the pcap file cut the packet at the Ethernet layer
                # This packets generate an error runtime (struct.error: unpack requires a buffer of 6 bytes), so they must be discarded
                ether_pkt = Ether(pkt_data)
            except BaseException:
                continue
            
            direction = PktDirection.not_defined
            
            
            if 'type' not in ether_pkt.fields:
                # LLC frames will have 'len' instead of 'type'.
                # We do not consider them in this analysis
                protocols_packet_counter_layer_1[('UNDEFINED-L1', direction)] += 1
                bytes_counter[direction] += len(pkt_data)
                continue
            
            # Considering only outbound packets
            if ether_pkt.src != mac_address and ether_pkt.dst != mac_address:
                continue

            # Defining direction
            if ether_pkt.src == mac_address:
                direction = PktDirection.outgoing
            else:
                direction = PktDirection.incoming
            
            # Tracking packet lenght
            bytes_counter[direction] += len(pkt_data)

            # Counting all the input and output packets 
            general_packet_counter[direction] += 1
            
            # In this method only IP packets are considered (interesting for our purposes)
            if ether_pkt.type != protocol_mapping_l2.get('IPv4'):

                # It is possible that the type value is not our mapping
                if ether_pkt.type in protocols_code_l2:
                    protocols_packet_counter_layer_2[(list(protocol_mapping_l2.keys())[protocols_code_l2.index(ether_pkt.type)], direction)] += 1
                else:
                    print("Unrecognized type l2: {}".format(ether_pkt.type))
                    protocols_packet_counter_layer_2[(str(ether_pkt.type), direction)] += 1
                continue
            
            # Even if is an IPv4 packet it can be a halved packet
            if not ether_pkt.haslayer(IP):
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
                protocols_packet_counter_layer_3 [(str(ip_pkt.proto), direction)] += 1

        
        if window is None:

            # Useful logs writing
            logs_data_writing(log_file)

            # Counters writing
            counters_logger_protocol(log_file, protocols_packet_counter_layer_1)
            counters_logger_protocol(log_file, protocols_packet_counter_layer_2)
            counters_logger_protocol(log_file, protocols_packet_counter_layer_3, separator="\t")
            counters_logger(log_file, general_packet_counter)
            counters_logger(log_file, bytes_counter, is_byte=True)

            # Reset Counter
            reset_counters(protocols_packet_counter_layer_1, 
                            protocols_packet_counter_layer_2, 
                            protocols_packet_counter_layer_3, 
                            general_packet_counter, 
                            bytes_counter)
        

        print("{}: {}/{} files analysed...".format(mac_address, file_log, total_files))
        
    if not window is None:
        # In this case we have to write the packets counted but still not written
    
        # Useful logs writing
        logs_data_writing(log_file, window=window_counter)

        # Counters writing
        counters_logger_protocol(log_file, protocols_packet_counter_layer_1)
        counters_logger_protocol(log_file, protocols_packet_counter_layer_2)
        counters_logger_protocol(log_file, protocols_packet_counter_layer_3, separator="\t")
        counters_logger(log_file, general_packet_counter)
        counters_logger(log_file, bytes_counter, is_byte=True)


    log_file.close()
    print("done.")

def bytes_rate_final_fixed_window(folder, mac_address, window=None):
    """
    The method produces an output file containing the bytes rates organised in protocol layers (e.g. IPv4...1000)
    Args:
        folder: folder containing pcap files
        mac_address: device to be analysed
        window: sliding window allows to select count the packets send or received in a certain time window(default None) (time is in secs)
    """

    last_folder = folder.split("/")[-2]

    # Loggging organization
    path = "./bytes_processing_results/"
    if not os.path.isdir(path):
        os.mkdir(path)
    path += mac_address + "/"
    if not os.path.isdir(path):
        # It is possible that the directory was created in other calls of the method
        os.mkdir(path)
    #################################

    output_file_name = path + mac_address + "_bytes_rate_by_protocol_" +  last_folder + "_" + str(window) + ".log"

    # Counters
    # Layers refer to TCP/IP stack (layer1: Host-to-network, layer2: Internet(Network), layer3: Transport, layer4: Application)
    protocols_bytes_counter_layer_1 = Counter()
    protocols_bytes_counter_layer_2 = Counter()
    protocols_bytes_counter_layer_3 = Counter()
    general_bytes_counter = Counter()

    general_counter = 0 # Timestamp guideline
    window_counter = 0 # Useful for logging purposes

    protocols_code_l3 = list(protocol_mapping_l3.values())
    protocols_code_l2 = list(protocol_mapping_l2.values())

    # Open log file
    log_file = open(output_file_name,'w')

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
        
        if os.stat(file_name).st_size == 0:
            print("{} is empty. Skipping...".format(file_name))
            continue

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
                
                # Window scrolling
                while last_timestamp > first_timestamp + (window * 1000000):
                    # I need to move the window until I find the one able to host the packet

                    # Useful logs writing
                    logs_data_writing(log_file, window=window_counter)

                    # Counters writing
                    counters_logger_protocol(log_file, protocols_bytes_counter_layer_1)
                    counters_logger_protocol(log_file, protocols_bytes_counter_layer_2)
                    counters_logger_protocol(log_file, protocols_bytes_counter_layer_3, separator="\t")
                    counters_logger(log_file, general_bytes_counter)
                    
                    window_counter += 1
                    
                    # Reset counters
                    reset_counters(protocols_bytes_counter_layer_1, 
                            protocols_bytes_counter_layer_2, 
                            protocols_bytes_counter_layer_3, 
                            general_bytes_counter)
                    
                    general_counter = 1

                    # Computing another time the first_timestamp
                    first_timestamp = first_timestamp + (window*1000000)
            
             # Obtaining ether packet
            try:
                # There are some cases where the pcap file cut the packet at the Ethernet layer
                # This packets generate an error runtime (struct.error: unpack requires a buffer of 6 bytes), so they must be discarded
                ether_pkt = Ether(pkt_data)
            except BaseException:
                continue
            
            direction = PktDirection.not_defined
            
            
            if 'type' not in ether_pkt.fields:
                # LLC frames will have 'len' instead of 'type'.
                # We do not consider them in this analysis
                protocols_bytes_counter_layer_1[('UNDEFINED-L1', direction)] += len(pkt_data)
                general_bytes_counter[direction] += len(pkt_data)
                continue
            
            # Considering only outbound packets
            if ether_pkt.src != mac_address and ether_pkt.dst != mac_address:
                continue

            # Defining direction
            if ether_pkt.src == mac_address:
                direction = PktDirection.outgoing
            else:
                direction = PktDirection.incoming
            
            # Tracking packet lenght
            general_bytes_counter[direction] += len(pkt_data)
            
            # In this method only IP packets are considered (interesting for our purposes)
            if ether_pkt.type != protocol_mapping_l2.get('IPv4'):

                # It is possible that the type value is not our mapping
                if ether_pkt.type in protocols_code_l2:
                    protocols_bytes_counter_layer_2[(list(protocol_mapping_l2.keys())[protocols_code_l2.index(ether_pkt.type)], direction)] += len(pkt_data)
                else:
                    print("Unrecognized type l2: {}".format(ether_pkt.type))
                    protocols_bytes_counter_layer_2[(str(ether_pkt.type), direction)] += len(pkt_data)
                continue
            
            # Even if is an IPv4 packet it can be a halved packet
            if not ether_pkt.haslayer(IP):
                continue
            
            ip_pkt = ether_pkt[IP]
            protocols_bytes_counter_layer_2[('IPv4',direction)] += len(pkt_data)

            if ip_pkt.proto == protocol_mapping_l3.get('TCP'):
                
                if not ip_pkt.haslayer(TCP):
                    # Some pcap files are not complete, so some packet could be halved
                    continue
                
                tcp_pkt = ip_pkt[TCP]
                protocols_bytes_counter_layer_3 [('TCP',direction)] += len(pkt_data)
                
                if 'S' in str(tcp_pkt.flags) and not 'A' in str(tcp_pkt.flags):
                    # Useful to understand the normal SYN traffic (avoiding SYN flood attacks)
                    protocols_bytes_counter_layer_3[("TCP-SYN-REQ-TO-" + ip_pkt.dst,direction)] += len(pkt_data)

            elif ip_pkt.proto in protocols_code_l3:
                protocols_bytes_counter_layer_3 [(list(protocol_mapping_l3.keys())[protocols_code_l3.index(ip_pkt.proto)], direction)] += len(pkt_data)
            
            else:
                print("Unrecognized L-3: {}".format(ip_pkt.proto))
                protocols_bytes_counter_layer_3 [(str(ip_pkt.proto), direction)] += len(pkt_data)

        if window is None:

            # Useful logs writing
            logs_data_writing(log_file)

            # Counters writing
            counters_logger_protocol(log_file, protocols_bytes_counter_layer_1)
            counters_logger_protocol(log_file, protocols_bytes_counter_layer_2)
            counters_logger_protocol(log_file, protocols_bytes_counter_layer_3, separator="\t")
            counters_logger(log_file, general_bytes_counter)

            # Reset Counter
            reset_counters(protocols_bytes_counter_layer_1, 
                            protocols_bytes_counter_layer_2, 
                            protocols_bytes_counter_layer_3, 
                            general_bytes_counter)
        
        print("{}: {}/{} files analysed...".format(mac_address, file_log, total_files))
    
    if not window is None:
        # In this case we have to write the packets counted but still not written
    
        # Useful logs writing
        logs_data_writing(log_file, window=window_counter)

        # Counters writing
        counters_logger_protocol(log_file, protocols_bytes_counter_layer_1)
        counters_logger_protocol(log_file, protocols_bytes_counter_layer_2)
        counters_logger_protocol(log_file, protocols_bytes_counter_layer_3, separator="\t")
        counters_logger(log_file, general_bytes_counter)


    log_file.close()
    print("done.")