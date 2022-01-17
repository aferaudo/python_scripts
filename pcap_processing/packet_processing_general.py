import packet_processing
from collections import Counter
from scapy.utils import RawPcapReader
from scapy.layers.all import *
import string
import random
import os

i = 0

class GeneralPcapParser():
    def __init__(self):
        self.protocols_packet_counter_layer_1 = Counter()
        self.protocols_packet_counter_layer_2 = Counter()
        self.protocols_packet_counter_layer_3 = Counter()
        self.general_packet_counter = Counter()

        self.protocols_bytes_counter_layer_1 = Counter()
        self.protocols_bytes_counter_layer_2 = Counter()
        self.protocols_bytes_counter_layer_3 = Counter()
        self.general_bytes_counter = Counter()

        self.file_counter = 0

        self.protocols_code_l3 = list(packet_processing.protocol_mapping_l3.values())
        self.protocols_code_l2 = list(packet_processing.protocol_mapping_l2.values())
        


    def reset_counters(self):
        print("Resetted")
        # Clear packet counters
        self.protocols_packet_counter_layer_1.clear()
        self.protocols_packet_counter_layer_2.clear()
        self.protocols_packet_counter_layer_3.clear()
        self.general_packet_counter.clear()

        # Clear byte counters
        self.protocols_bytes_counter_layer_1.clear()
        self.protocols_bytes_counter_layer_2.clear()
        self.protocols_bytes_counter_layer_3.clear()
        self.general_bytes_counter.clear()
    

    def scrolling_window(self, log_file_packet, log_file_byte, last_timestamp, first_timestamp, window, window_counter):
        """
        The method finds the window where the packet will fall. In order to do this windows are scrolled until the 
        timestamp of the packet is in the window.
        """
        scrolled = False
        
        while last_timestamp > first_timestamp + (window * 1000000):
            # I need to move the window until I find the one able to host the packet
            packet_processing.logs_data_writing(log_file_packet, window=window_counter)

            # Useful logs writing
            packet_processing.logs_data_writing(log_file_byte, window=window_counter)

            # Counters writing
            # packet_processing.counters_logger_protocol(log_file, self.protocols_bytes_counter_layer_1)
            # packet_processing.counters_logger_protocol(log_file, self.protocols_bytes_counter_layer_2)
            # packet_processing.counters_logger_protocol(log_file, self.protocols_bytes_counter_layer_3, separator="\t")
            # packet_processing.counters_logger(log_file, self.general_bytes_counter)
            self.__logging_data(log_file_packet=log_file_packet, log_file_byte=log_file_byte)

            window_counter += 1
            
            # Reset counters
            self.reset_counters()
            
            # This is used to reset the general_counter (resetting first timestamp)
            scrolled = True

            # Computing another time the first_timestamp
            first_timestamp = first_timestamp + (window*1000000)
        
        return scrolled, window_counter, first_timestamp


    def __logging_data(self, log_file_packet, log_file_byte):
        
        # Writing packets data
        packet_processing.counters_logger_protocol(log_file_packet, self.protocols_packet_counter_layer_1)
        packet_processing.counters_logger_protocol(log_file_packet, self.protocols_packet_counter_layer_2)
        packet_processing.counters_logger_protocol(log_file_packet, self.protocols_packet_counter_layer_3, separator="\t")
        packet_processing.counters_logger(log_file_packet, self.general_packet_counter)

        # Writing bytes data
        packet_processing.counters_logger_protocol(log_file_byte, self.protocols_bytes_counter_layer_1)
        packet_processing.counters_logger_protocol(log_file_byte, self.protocols_bytes_counter_layer_2)
        packet_processing.counters_logger_protocol(log_file_byte, self.protocols_bytes_counter_layer_3, separator="\t")
        packet_processing.counters_logger(log_file_byte, self.general_bytes_counter)

    
    def increment_counters(self, pkt_data, layer, direction, flag=None):
        if layer == 0:
            self.general_bytes_counter[direction] += len(pkt_data)
            self.general_packet_counter[direction] += 1
        elif layer == 1:
            self.protocols_packet_counter_layer_1[(flag, direction)] += 1
            self.protocols_bytes_counter_layer_1[(flag, direction)] += len(pkt_data)
        elif layer == 2:
            self.protocols_packet_counter_layer_2[(flag, direction)] += 1
            self.protocols_bytes_counter_layer_2[(flag, direction)] += len(pkt_data)
        elif layer == 3:
            self.protocols_packet_counter_layer_3[(flag, direction)] += 1
            self.protocols_bytes_counter_layer_3[(flag, direction)] += len(pkt_data)


    def packet_byte_rate_window(self, folder, ip, window=None):
        """
        Differently from packet_processing.py here the direction is defined through source and destination ip address
        """


        # Loggging organization
        
        path = "./processing_results_general/" 
        if not os.path.isdir(path):
            os.mkdir(path)
        
        #################################
        other_counter = 0

        # output_file_name = path + str(self.file_counter) + random.choice(string.ascii_letters[0:24]) + ".log"
        output_file_name_packet = "{}{}_packet_{}.log".format(path, ip, window)
        print("Output File name packet: {}".format(output_file_name_packet))
        log_file_packet = open(output_file_name_packet,'w')
        
        output_file_name_byte = "{}{}_byte_{}.log".format(path, ip, window)
        print("Output File name byte: {}".format(output_file_name_byte))
        log_file_byte = open(output_file_name_byte,'w')

        self.file_counter += 1

        general_counter = 0 # Timestamp guideline
        window_counter = 0 # Useful for logging purposes

        # Ordering Files in the directory (useful for window purposes)
        files = sorted(os.listdir(folder))

        for pcap_file in files:
            
            if not pcap_file.endswith(".pcap"):
                print("Not processed {} ...".format(pcap_file))
                continue
                
            file_name = folder + pcap_file
            
            if os.stat(file_name).st_size == 0:
                print("{} is empty. Skipping...".format(file_name))
                continue

            print("Processing {} ...".format(file_name))

            for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
                general_counter += 1
                # print(self.protocols_packet_counter_layer_3)
                
                # If window is enabled we should get the timestamp and reset all counters
                if not window is None:
                     # Computing timestamp
                    if general_counter == 1: # This is useful only for the first packet (Is there a clever way?)
                        # Computing first_timestamp
                        first_timestamp = packet_processing.computing_timestamp(pkt_metadata)
                    
                    last_timestamp = packet_processing.computing_timestamp(pkt_metadata)

                    # Scrolling window until finding the right one
                    scrolled, window_counter, first_timestamp = self.scrolling_window(log_file_packet=log_file_packet, log_file_byte=log_file_byte, last_timestamp=last_timestamp, first_timestamp=first_timestamp, window=window, window_counter=window_counter)
                    
                    if scrolled:
                        general_counter = 1
                        
                    # print(general_counter)

                
                # Obtaining ether packet
                try:
                    # There are some cases where the pcap file cut the packet at the Ethernet layer
                    # This packets generate an error runtime (struct.error: unpack requires a buffer of 6 bytes), so they must be discarded
                    ether_pkt = Ether(pkt_data)
                except BaseException:
                    continue
                
                # print(ether_pkt.fields)
                # print(ether_pkt.show())
                # print(pkt_metadata)

                if 'type' not in ether_pkt.fields:
                    # LLC frames will have 'len' instead of 'type'.
                    # We do not consider them in this analysis
                    self.increment_counters(pkt_data=pkt_data, layer=1, flag='UNDEFINED-L1', direction=packet_processing.PktDirection.not_defined)
                    other_counter +=1
                    continue
                
                # In this method only IP packets are considered (interesting for our purposes)
                if ether_pkt.type != packet_processing.protocol_mapping_l2.get('IPv4') and ether_pkt.type != packet_processing.protocol_mapping_l2.get('IPv6'):
                    # It is possible that the type value is not our mapping
                    if ether_pkt.type in self.protocols_code_l2:
                        flag = list(packet_processing.protocol_mapping_l2.keys())[self.protocols_code_l2.index(ether_pkt.type)]
                        self.increment_counters(pkt_data=pkt_data, layer=2, flag=flag, direction=packet_processing.PktDirection.not_defined)
                        # self.protocols_packet_counter_layer_2[(list(packet_processing.protocol_mapping_l2.keys())[self.protocols_code_l2.index(ether_pkt.type)], packet_processing.PktDirection.not_defined)] += 1
                    else:
                        print("Unrecognized type l2: {}".format(ether_pkt.type))
                        flag = str(ether_pkt.type)
                        self.increment_counters(pkt_data=pkt_data, layer=2, flag=flag, direction=packet_processing.PktDirection.not_defined)
                        # self.protocols_packet_counter_layer_2[(str(ether_pkt.type), packet_processing.PktDirection.not_defined)] += 1
                    continue
                
                if not ether_pkt.haslayer(IP):
                    continue

                ip_pkt = ether_pkt[IP]

                # Computing direction
                if ip_pkt.src==ip:
                    direction = packet_processing.PktDirection.outgoing
                else:
                    direction = packet_processing.PktDirection.incoming

                self.increment_counters(pkt_data=pkt_data, layer=0, direction=direction)

                # counter ipv4/ipv6
                # print(ip_pkt.version)
                # print(type(ip_pkt.version))
                flag = 'IPv{}'.format(ip_pkt.version)
                if ip_pkt.version == 0:
                    print(ether_pkt.show())
                
                self.increment_counters(pkt_data=pkt_data, layer=2, direction=direction, flag=flag)
                # self.protocols_bytes_counter_layer_2[(flag, direction)] += 1
                
                if ip_pkt.proto == packet_processing.protocol_mapping_l3.get('TCP'):
                
                    if not ip_pkt.haslayer(TCP):
                        # Some pcap files are not complete, so some packet could be halved
                        continue
                    
                    flag = "TCP"
                    
                    # self.protocols_packet_counter_layer_3 [('TCP',direction)] += 1
                    self.increment_counters(pkt_data=pkt_data, layer=3, direction=direction, flag=flag)
                    
                    tcp_pkt = ip_pkt[TCP]
                    
                    if 'S' in str(tcp_pkt.flags) and not 'A' in str(tcp_pkt.flags):
                        # Useful to understand the normal SYN traffic (avoiding SYN flood attacks)
                        flag = "TCP-SYN-REQ-TO-" + ip_pkt.dst
                        self.increment_counters(pkt_data=pkt_data, layer=3, direction=direction, flag=flag)
                
                elif ip_pkt.proto in self.protocols_code_l3:
                    flag = list(packet_processing.protocol_mapping_l3.keys())[self.protocols_code_l3.index(ip_pkt.proto)]
                    self.increment_counters(pkt_data=pkt_data, layer=3, direction=direction, flag=flag)
                else:
                    print("Unrecognized L-3: {}".format(ip_pkt.proto))
                    flag = str(ip_pkt.proto)
                    self.increment_counters(pkt_data=pkt_data, layer=3, direction=direction, flag=flag)
                
                
                
            
            if window is None:
                packet_processing.logs_data_writing(log_file_byte)
                packet_processing.logs_data_writing(log_file_packet)

                self.__logging_data(log_file_packet=log_file_packet, log_file_byte=log_file_byte)

                # Reset counter
                self.reset_counters()
        
        if not window is None:
        # In this case we have to write the packets counted but still not written
    
            # Useful logs writing
            packet_processing.logs_data_writing(log_file_byte, window=window_counter)
            packet_processing.logs_data_writing(log_file_packet, window=window_counter)

            # Counters writing
            self.__logging_data(log_file_packet=log_file_packet, log_file_byte=log_file_byte)


        log_file_packet.close()
        log_file_byte.close()
        print(other_counter)
        print("done.")




