import sys
import os
import matplotlib.pyplot as plt
import matplotlib
import argparse
import numpy as np
import re
import packet_processing

protocols_filter = [
    'IPv4',
    'IPv6',
    'TCP',
    'UDP'
]

def from_string_to_direction(direction):
    if '<--' == direction:
        return packet_processing.PktDirection.incoming
    elif '-->' == direction:
        return packet_processing.PktDirection.outgoing
    else:
        return packet_processing.PktDirection.not_defined

def from_direction_to_string(direction):
    if direction == packet_processing.PktDirection.incoming:
        return "incoming"
    elif direction == packet_processing.PktDirection.outgoing:
        return "outgoing"
    else:
        return "undefined"

def plot_results_by_directory(folder, device_name):
    
    # Ordering Files in the directory (useful for window purposes)
    files = os.listdir(folder)

    for filename in files:
        file_path = folder + filename
        plot_results_by_file(file_path, device_name)


def plot_results_by_file(file_name, device_name):
    fig, ax = plt.subplots(figsize = (7, 4)) 
    print("Processing {} ...".format(file_name))
    if not file_name.endswith('.log'):
        return
    
    window_size = file_name.replace('.log','').split('_')[-1]
    if window_size == 'None':
        return
    window_size = int(window_size)
    
    packet_per_protocol = {}

    # Reading the file
    with open(file_name) as opened_file:
        lines = opened_file.readlines()
        for line in lines:
            if 'Window' in line:
                window_counter = int(line.split('::')[1].split(':')[0])
                # Maybe we should have a limit on the amount of window to consider
                # For instance:
                # if window_counter >= 100000:
                #     break
                continue
            
            if "Outgoing" in line or "Incoming" in line or "Total" in line:
                # TODO: what should we do in these cases
                continue
            
            if line == '\n':
                continue
            
            direction = from_string_to_direction(line.split(':')[0].replace('\t',''))
            protocol_pkt = line.split(':::')[1].split('...')
            protocol = protocol_pkt[0]
            packet_number = int(protocol_pkt[1].replace('\n',''))

            # Dictionary key: (protocol, direction, window). So we have packets send for that window
            packet_per_protocol[(protocol, direction, window_counter)] = packet_number
        
        
        # print(packet_per_protocol)
        
        # Fill the empty parts (It is possible that a device didn't send a packet for a particular protocol, in such a case we should insert 0)
        dict_values_complete = {}
        
        for (protocol, direction, _) in packet_per_protocol.keys():
            
            if (protocol,direction) in  dict_values_complete.keys():
                continue
            
            dict_values_complete[(protocol,direction)] = []
            
            for counter in range(0, window_counter + 1):
                if (protocol, direction, counter) in packet_per_protocol.keys():
                    value = packet_per_protocol.get((protocol, direction, counter))
                else:
                    value = 0 # For that window no packets have been sent
                
                dict_values_complete[(protocol,direction)].append(value)

        # print(dict_values_complete)

        for (protocol, direction) in dict_values_complete.keys():
            # Representing only outgoing packets
            if direction == packet_processing.PktDirection.outgoing and protocol in protocols_filter:
                time_values = np.array(list(range(1, window_counter+2))) * window_size
                ax.plot(time_values, dict_values_complete.get((protocol,direction)), label=(protocol))
                ax.set_title("{} packet rate from {} in a window of {} secs".format(from_direction_to_string(direction), device_name, window_size))
        
        ax.set_xlabel('Time (secs)')
        ax.set_ylabel('# Packets')
        ax.legend()
        plt.savefig("packet_rate_300.pdf")
    
    

def main(argv):
    # Checking if the directory exists
    myre = re.compile(r'(?:[0-9a-fA-F]:?){6,12}')
    mac_address = re.findall(myre, args.path)
    if not mac_address:
        print('{} not valid path!'.format(args.path))
        sys.exit(-1)

    device_name = mac_address[0]

    if os.path.isfile(args.path):
        print("File found!")
        plot_results_by_file(args.path, device_name)
        sys.exit(0)

    if not os.path.isdir(args.path):
        print('"{}" does not exist'.format(args.path), file=sys.stderr)
        sys.exit(-1)

    plot_results_by_directory(args.path, device_name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Plotting pcap processer's result")

    # TODO implement plotting by file feature

    parser.add_argument("--path", "-p", type=str, required=True, help="folder of data")

    args = parser.parse_args()
    
    
    main(args)