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

categories = {}
devices_cat_match = {}
    

OUTGOING = "Outgoing"
INCOMING = "Incoming"
UNDEFINED_DIRECTION = "Undefined direction"
TOTAL = "Total"
OUTGOING_BYTES = OUTGOING + " bytes"
INCOMING_BYTES = INCOMING + " bytes"
UNDEFINED_BYTES= "Undefined direction bytes"
TOTAL_BYTES = TOTAL + " bytes"

bbox_props = dict(boxstyle="square,pad=0.1", alpha=0.5, fc="lightgrey")
font=matplotlib.font_manager.FontProperties()
font.set_weight('bold')


def from_string_to_direction(direction):
    if '<--' == direction or INCOMING in direction:
        return packet_processing.PktDirection.incoming
    elif '-->' == direction or OUTGOING in direction:
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

def initialise_dict(dictionary, is_bytes=False):

    if not is_bytes:
        dictionary[INCOMING] = []
        dictionary[OUTGOING] = []
        dictionary[UNDEFINED_DIRECTION] = []
        dictionary[TOTAL] = []
    else:
        dictionary[INCOMING_BYTES.replace(' ', '_')] = []
        dictionary[OUTGOING_BYTES.replace(' ', '_')] = []
        dictionary[UNDEFINED_BYTES.replace(' ', '_')] = []
        dictionary[TOTAL_BYTES.replace(' ', '_')] = []

def highlight_max_value_y_axis(ax, max_value, text, color, showText=False):
    ax.axhline(y=max_value, color=color, ls='--', lw=1)
    if showText:
        ax.text(1000, (max_value), ('{} max= {}'.format(text, max_value)), size=8, fontproperties=font)

def lists_plotting(x_values, *lists_to_plot, labels, showText):
    """
    Prints different list of values on Y axis. 
    The method requires the labels for each of the line to plot
    Args:
        x_values: values on x axis (this is just one list)
        *lists_to_plot: lists of values to plot on y axis
        labels: list of labels of the line to plot
    """
    if len(lists_to_plot) != len(labels):
        return None
    
    fig, ax = plt.subplots(figsize = (10, 5))
    
    plt.grid(linestyle="dashed", color='lightgrey') 
    base_lines = []
    for i, to_plot in enumerate(lists_to_plot):
        max_value = max(to_plot)
        base_line,  = ax.plot(x_values, to_plot, label=labels[i])
        highlight_max_value_y_axis(ax=ax, max_value=max_value, text=labels[i], color=base_line.get_color(), showText=showText)
        base_lines.append(base_line)
        
    # Standard for all packets
    ax.set_xlabel('Time in secs')
    ax.axhline(y=0, color='k')
    ax.axvline(x=0, color='k')
    ax.legend(handles=base_lines, bbox_to_anchor=(1, 1), loc='upper left', fontsize='xx-small')
    return fig, ax

def plot_by_protocol(data_dict, time_values, showText, path, window_size, mac_address,packets=True):
    # Plotting packets/bytes grouped by protocol
    fig, ax = plt.subplots(figsize = (10, 5))
    fig2, ax2 = plt.subplots(figsize = (10, 5))
    ax.grid(linestyle="dashed", color='lightgrey') 
    ax2.grid(linestyle="dashed", color='lightgrey') 
    base_lines = []
    base_lines2 = []
    labeling = "packets" if packets else "bytes"

    for protocol, direction in data_dict.keys():
        if protocol in protocols_filter and direction == packet_processing.PktDirection.outgoing:
            max_value = max(data_dict.get((protocol, direction)))
            base_line, = ax.plot(time_values, data_dict.get((protocol, direction)), label=("{} {}".format(protocol, from_direction_to_string(direction))))
            highlight_max_value_y_axis(ax=ax, max_value=max_value, text="{} {} ".format(protocol, labeling), color=base_line.get_color(), showText=showText)
            base_lines.append(base_line)
        elif protocol in protocols_filter and direction == packet_processing.PktDirection.incoming:
            max_value = max(data_dict.get((protocol, direction)))
            base_line2, = ax2.plot(time_values, data_dict.get((protocol, direction)), label=("{} {}".format(protocol, from_direction_to_string(direction))))
            highlight_max_value_y_axis(ax=ax2, max_value=max_value, text="{} {} ".format(protocol, labeling), color=base_line2.get_color(), showText=showText)
            base_lines2.append(base_line2)
    
    # Plotting outgoing
    ax.legend(handles=base_lines, bbox_to_anchor=(1, 1), loc='upper left', fontsize='xx-small')
    ax.set_title("{} {} rate from {} in a window of {} secs".format(from_direction_to_string(packet_processing.PktDirection.outgoing), labeling.replace('s', ''), mac_address, window_size))
    ax.set_ylabel('# Packets' if packets else 'Bytes')
    ax.set_xlabel('Time in secs')
    ax.axhline(y=0, color='k')
    ax.axvline(x=0, color='k')
    fig.savefig("{}outgoing_{}_protocols_{}.pdf".format(path, labeling, window_size))
    plt.close(fig=fig)

    # Plotting incoming
    ax2.legend(handles=base_lines2, bbox_to_anchor=(1, 1), loc='upper left', fontsize='xx-small')
    ax2.set_title("{} {} rate to {} in a window of {} secs".format(from_direction_to_string(packet_processing.PktDirection.incoming), labeling.replace('s', ''), mac_address, window_size))
    ax2.set_ylabel('# Packets' if packets else 'Bytes')
    ax2.set_xlabel('Time in secs')
    ax2.axhline(y=0, color='k')
    ax2.axvline(x=0, color='k')
    fig2.savefig("{}incoming_{}_protocols_{}.pdf".format(path, labeling, window_size))
    plt.close(fig=fig2)

def processing_results_by_directory(folder, showText, total, packets_protocol, bytes_protocol, filter_by_window):
    
    # Ordering Files in the directory (useful for window purposes)
    files = os.listdir(folder)

    for filename in files:
        file_path = folder + filename
        if filter_by_window != None and not filter_by_window in filename.replace(".log","").split("_"):
            continue
        processing_results_by_file(file_path, showText, total, packets_protocol, bytes_protocol)

def processing_results_by_file(file_name, showText, total, packets_protocol, bytes_protocol):
    
    print("Processing {} ...".format(file_name))
    if not file_name.endswith('.log'):
        return
    splitted_file_name = file_name.split('/')[-1].split('_')

    window_size = splitted_file_name[-1].replace('.log','')
    if window_size == 'None':
        return
    window_size = int(window_size)
    mac_address = splitted_file_name[0]

    packets_traffic = {}
    packets_lenght = {}
    traffic_by_protocol = {}
    
    initialise_dict(packets_traffic)
    initialise_dict(packets_lenght, True)
   
    counter = 0

    # Create dir which will contain device's graphs
    # Creating graphs dir
    path = "./graphs/"
    if not os.path.isdir(path):
        os.mkdir(path)
    
    cat = categories.get(0)
    # Creating graphs/category dir
    if devices_cat_match.get(mac_address):
        cat = categories.get(devices_cat_match.get(mac_address))
    path += cat + "/"
    if not os.path.isdir(path):
        os.mkdir(path)
    
    # Creating graphs/category/device dir
    path += mac_address + "/"
    if not os.path.isdir(path):
        os.mkdir(path)

    # Reading the file (obtaining data)
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
            
            if OUTGOING_BYTES in line or INCOMING_BYTES in line or TOTAL_BYTES in line or UNDEFINED_BYTES in line:
                value = int(line.split(':')[1])
                key = line.split(':')[0].replace(' ','_')

                packets_lenght[key].append(value)

                # When there are no packets for a particular direction in a specific window they are not represented in the file. So we need to rebuild them.
                # Filling gaps
                if TOTAL_BYTES in line:
                    for key in packets_lenght.keys():
                        if not key in TOTAL_BYTES.replace(' ', '_') and len(packets_lenght[key]) < len(packets_lenght[TOTAL_BYTES.replace(' ', '_')]):
                            packets_lenght[key].append(0)
                continue

            if OUTGOING in line or INCOMING in line or TOTAL in line or UNDEFINED_DIRECTION in line:
                value = int(line.split(':')[1])
                key = line.split(':')[0]
                packets_traffic[key].append(value)

                if TOTAL in line:
                    for key in packets_traffic.keys():
                        if not key in TOTAL and len(packets_traffic[key]) < len(packets_traffic[TOTAL]):
                            packets_traffic[key].append(0)
                continue
                
            if line == '\n':
                continue
            
            direction = from_string_to_direction(line.split(':')[0].replace('\t',''))
            protocol_pkt = line.split(':::')[1].split('...')
            protocol = protocol_pkt[0]
            packet_number = int(protocol_pkt[1].replace('\n',''))

            # print("{} {} {}".format(direction, protocol, packet_number))
            traffic_by_protocol[(protocol, direction, window_counter)] = packet_number
    
    # Time values (x axis)
    time_values = np.array(list(range(1, window_counter+2))) * window_size
    
    # Fill empty values (this allow to have the same dimension)
    temp_dict = {}
        
    for (protocol, direction, _) in traffic_by_protocol.keys():
        
        if (protocol,direction) in  temp_dict.keys():
            continue
        
        temp_dict[(protocol,direction)] = []
        
        for counter in range(0, window_counter + 1):
            if (protocol, direction, counter) in traffic_by_protocol.keys():
                value = traffic_by_protocol.get((protocol, direction, counter))
            else:
                value = 0 # For that window no packets have been sent
            
            temp_dict[(protocol,direction)].append(value)

    if total:    
        #  Plotting incoming and outgoing bytes
        fig, ax = lists_plotting(time_values, packets_lenght.get(INCOMING_BYTES.replace(' ','_')), 
                            packets_lenght.get(OUTGOING_BYTES.replace(' ','_')), 
                            labels=[INCOMING_BYTES, OUTGOING_BYTES], 
                            showText=showText)
        
        if ax is None:
            print('Somthing went wrong')
            sys.exit(-1)
        
        ax.set_ylabel('Bytes')
        ax.set_title("{} and {} bytes ({}) in a window of {} secs".format(INCOMING, OUTGOING, mac_address, window_size))
        plt.savefig("{}incoming_outgoing_bytes_{}.pdf".format(path, window_size))
        plt.close(fig)

        # Plotting undefined direction bytes and total bytes
        fig, ax = lists_plotting(time_values, 
                            packets_lenght.get(UNDEFINED_BYTES.replace(' ','_')), 
                            packets_lenght.get(TOTAL_BYTES.replace(' ','_')), 
                            labels=[UNDEFINED_BYTES, TOTAL_BYTES],
                            showText=showText)
        
        if ax is None:
            print('Somthing went wrong')
            sys.exit(-1)
        
        ax.set_ylabel('Bytes')
        ax.set_title("{} and {} bytes ({}) in a window of {} secs".format(UNDEFINED_DIRECTION, TOTAL, mac_address, window_size))

        plt.savefig("{}undefined_total_bytes_{}.pdf".format(path, window_size))
        plt.close(fig)

        # Plotting incoming and outgoing packets
        fig, ax = lists_plotting(time_values, 
                            packets_traffic.get(INCOMING), 
                            packets_traffic.get(OUTGOING), 
                            labels=[INCOMING, OUTGOING],
                            showText=showText)
        
        if ax is None:
            print('Somthing went wrong')
            sys.exit(-1)
        
        ax.set_ylabel('# Packets')
        ax.set_title("{} and {} packets ({}) in a window of {} secs".format(INCOMING, OUTGOING, mac_address, window_size))

        plt.savefig("{}incoming_outgoing_packets_{}.pdf".format(path, window_size))
        plt.close(fig)

        # Plotting undefined direction packet and total packet
        fig, ax = lists_plotting(time_values, 
                            packets_traffic.get(UNDEFINED_DIRECTION), 
                            packets_traffic.get(TOTAL), 
                            labels=[UNDEFINED_DIRECTION, TOTAL],
                            showText=showText)
        
        if ax is None:
            print('Somthing went wrong')
            sys.exit(-1)
        
        ax.set_ylabel('# Packets')
        ax.set_title("{} and {} packets ({}) in a window of {} secs".format(UNDEFINED_DIRECTION, TOTAL, mac_address, window_size))
        
        plt.savefig("{}undefined_total_packets_{}.pdf".format(path, window_size))
        plt.close(fig)
        
    if packets_protocol:
        plot_by_protocol(data_dict=temp_dict, time_values=time_values, 
                        path=path, window_size=window_size, mac_address=mac_address, 
                        showText=showText)
    
    if bytes_protocol:
        plot_by_protocol(data_dict=temp_dict, time_values=time_values, 
                        path=path, window_size=window_size, mac_address=mac_address, 
                        showText=showText, packets=False)

    # plt.show()

def main(argv):
    # Checking if the directory exists
    myre = re.compile(r'(?:[0-9a-fA-F]:?){6,12}')

    # Category and device matching
    if args.category != None:
        category_path = args.category + "categories.txt"
        device_path = args.category + "devices.txt"
        
        categories[0] = 'not-defined'
        with open(category_path, 'r') as file_categories:
            lines = file_categories.readlines()
            for line in lines:
                categories[int(line.split()[1])] = line.split()[0]
        with open(device_path, 'r') as file_devices:
            lines = file_devices.readlines()
            for line in lines:
                splitted_line = line.split()
                cat = 0
                if len(splitted_line) == 4:
                    cat = int(splitted_line[-1])
                
                devices_cat_match[packet_processing.mac_address_fixer(splitted_line[0].replace("#",""))] = cat
    
    if os.path.isfile(args.folder):
        print("File found!")
        processing_results_by_file(args.folder, args.text, args.total, args.packets_protocol, args.bytes_protocol)
        sys.exit(0)

    if not os.path.isdir(args.folder):
        print('"{}" does not exist'.format(args.folder), file=sys.stderr)
        sys.exit(-1)

    

    for directory in os.listdir(args.folder):
        if not re.findall(myre, directory):
            continue
        path = "{}/{}/".format(args.folder, directory)
        if os.path.isdir(path):
            processing_results_by_directory(path, args.text, args.total, args.packets_protocol, args.bytes_protocol, args.filter_by_window)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Plotting pcap processer's result")

    parser.add_argument("--folder", "-f", type=str, required=True, 
                        help="folder containing the data's directories")

    parser.add_argument("--category", "-c", type=str, required=True,
                        help='generate folder divided by category (specify path that contains categories.txt and devices.txt)')

    parser.add_argument("--filter_by_window", "-w", type=str,
                        help='filter files by window size')
    
    parser.add_argument("--total", "-t", action='store_true',
                        help='Plot total packets and bytes')
    
    parser.add_argument("--packets_protocol", "-p", action='store_true',
                        help='Plot packets grouped by protocol')
    
    parser.add_argument("--bytes_protocol", "-b", action='store_true',
                        help='Plot bytes grouped by protocol')

    parser.add_argument("--text", "-x", action='store_true',
                        help='show major details')

    args = parser.parse_args()
    
    
    main(args)