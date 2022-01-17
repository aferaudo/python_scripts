from io import BufferedWriter
import sys
import os
import matplotlib.pyplot as plt
import matplotlib
import argparse
import numpy as np
import re
import packet_processing

# I use this script to take some piecies of code (not usable anymore)

protocols_filter = {
    'IPv4':'blue',
    'IPv6':'red',
    'TCP':'green',
    'UDP':'orange'
}

protocols_iptables_filter_color = {
    'TCP iptables': 'blue',
    'TCP noiptables': 'red'
    # ...
}

protocols_ip_tables_markers = {
    'TCP iptables': 'o',
    'TCP noiptables': 's'
    # ...
}

protocols_markers = {
    'IPv4':'8',
    'IPv6':'*',
    'TCP':'o',
    'UDP':'s',
    'ICMP': '*'
}

protocols_layer = {
    4: ["UDP", "TCP", "ICMP"],
    3: ["IPv4", "IPv6"]
    # ... 
}

# This dictionary contains useful values for analysis
resulting_values = {}


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

def plot_bars(ax, x_values, y_values):
    ax.bar(x_values, y_values, width=0.35, secondary_y=True)


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

def plot_by_protocol(data_dict, time_values, showText, path, window_size, mac_address, packets=True):
    # TODO This function contains too much boiler plate code, which is due to the usage of two graphs!

    # Plotting packets/bytes grouped by protocol
    fig, ax = plt.subplots(figsize = (10, 5))
    fig2, ax2 = plt.subplots(figsize = (10, 5))
    ax.grid(linestyle="dashed", color='lightgrey') 
    ax2.grid(linestyle="dashed", color='lightgrey') 
    base_lines = []
    base_lines2 = []
    labeling = "packets" if packets else "bytes"

    for protocol, direction in data_dict.keys():
        if protocol in protocols_filter.keys() and direction == packet_processing.PktDirection.outgoing:
            max_value = max(data_dict.get((protocol, direction)))
            # base_line, = ax.plot(time_values, data_dict.get((protocol, direction)), label=("{} {}".format(protocol, from_direction_to_string(direction))), color=protocols_filter.get(protocol), 
            #                    marker=protocols_markers.get(protocol), linestyle='dashdot', linewidth=1.2)
            
            base_line, = ax.plot(time_values, data_dict.get((protocol, direction)), label=("{}".format(protocol)), color=protocols_filter.get(protocol), 
                               marker=protocols_markers.get(protocol), linestyle='dashdot', linewidth=1.2, markersize=2)
            # other_line, = ax.plot(time_values, np.random.randint(1,3000,len(time_values)), label="TCP iptables", marker=protocols_markers.get(protocol), linestyle='dashdot', linewidth=1.2, markersize=3)
            # Analysis values
            resulting_values[mac_address].append('avg_{}_{}: {}'.format(protocol, from_direction_to_string(direction), round(np.mean(data_dict.get((protocol, direction))), 3)))
            resulting_values[mac_address].append('max_{}_{}: {}'.format(protocol, from_direction_to_string(direction), max_value))
            
            highlight_max_value_y_axis(ax=ax, max_value=max_value, text="{} {} ".format(protocol, labeling), color=base_line.get_color(), showText=showText)
            # plot_bars(ax=ax, x_values=data_dict.get((protocol, direction)), y_values=time_values)
            base_lines.append(base_line)
            # base_lines.append(other_line)
        elif protocol in protocols_filter and direction == packet_processing.PktDirection.incoming:
            max_value = max(data_dict.get((protocol, direction)))
            # base_line2, = ax2.plot(time_values, data_dict.get((protocol, direction)), label=("{} {}".format(protocol, from_direction_to_string(direction))), color=protocols_filter.get(protocol),
            #                         marker=protocols_markers.get(protocol), linestyle='dashdot', linewidth=1.2)
            
            base_line2, = ax2.plot(time_values, data_dict.get((protocol, direction)), label=("{}".format(protocol)), color=protocols_filter.get(protocol),
                                    marker=protocols_markers.get(protocol), linestyle='dashdot', linewidth=1.2, markersize=2)
            
            # Analysis values
            resulting_values[mac_address].append('avg_{}_{}: {}'.format(protocol, from_direction_to_string(direction), round(np.mean(data_dict.get((protocol, direction))), 3)))
            resulting_values[mac_address].append('max_{}_{}: {}'.format(protocol, from_direction_to_string(direction), max_value))
            
            highlight_max_value_y_axis(ax=ax2, max_value=max_value, text="{} {} ".format(protocol, labeling), color=base_line2.get_color(), showText=showText)
            base_lines2.append(base_line2)
    
    # Plotting outgoing
    # ax.legend(handles=base_lines, bbox_to_anchor=(1, 1), loc='upper left', fontsize='xx-small')
    ax.legend(handles=base_lines, loc='upper right', fontsize='x-small')
    # ax.set_title("{} {} rate from {} in a window of {} secs".format(from_direction_to_string(packet_processing.PktDirection.outgoing), labeling.replace('s', ''), mac_address, window_size))
    ax.set_ylabel('# Packets' if packets else 'Bytes')
    # ax.set_xlabel('Time in secs')
    ax.set_xlabel('# Windows')
    ax.axhline(y=0, color='k')
    ax.axvline(x=0, color='k')
    ax.set_xlim(xmin=0)
    ax.set_ylim(ymin=0)
    fig.savefig("{}outgoing_{}_protocols_{}.pdf".format(path, labeling, window_size))
    plt.close(fig=fig)

    # Plotting incoming
    # ax2.legend(handles=base_lines2, bbox_to_anchor=(1, 1), loc='upper left', fontsize='xx-small')
    ax2.legend(handles=base_lines, loc='upper right', fontsize='x-small')
    # ax2.set_title("{} {} rate to {} in a window of {} secs".format(from_direction_to_string(packet_processing.PktDirection.incoming), labeling.replace('s', ''), mac_address, window_size))
    ax2.set_ylabel('# Packets' if packets else 'Bytes')
    # ax2.set_xlabel('Time in secs')
    ax2.set_xlabel('# Windows')
    ax2.axhline(y=0, color='k')
    ax2.axvline(x=0, color='k')
    ax2.set_xlim(xmin=0)
    ax2.set_ylim(ymin=0)
    fig2.savefig("{}incoming_{}_protocols_{}.pdf".format(path, labeling, window_size))
    plt.close(fig=fig2)

def comparison_iptables_plotter(list_data, list_window_values, list_window_size, list_labels, path, bytes_plot=False):
    # Plotting packets/bytes grouped by protocol
    fig, ax = plt.subplots(figsize = (10, 5))
    ax.grid(linestyle="dashed", color='lightgrey') 
    labeling = "bytes" if bytes_plot else "packets"
    base_lines = []
    for index, data_dict in enumerate(list_data):
        for protocol, direction in data_dict.keys():
            if protocol in protocols_filter.keys() and direction == packet_processing.PktDirection.outgoing:
                max_value = max(data_dict.get((protocol, direction)))
                label = "{} {}".format(protocol, list_labels[index])
                base_line, = ax.plot(list_window_values[index], data_dict.get((protocol, direction)), label=label, color=protocols_iptables_filter_color.get(label), 
                               marker=protocols_ip_tables_markers.get(label), linestyle='dashdot', linewidth=1.2, markersize=3)
                # highlight_max_value_y_axis(ax=ax, max_value=max_value, text="{} {} ".format(protocol, labeling), color=base_line.get_color())
                base_lines.append(base_line)
    
    ax.legend(handles=base_lines, loc='upper right', fontsize='x-small')
    # ax.set_title("{} {} rate from {} in a window of {} secs".format(from_direction_to_string(packet_processing.PktDirection.outgoing), labeling.replace('s', ''), mac_address, window_size))
    ax.set_ylabel('Bytes' if bytes_plot else '# Packets')
    # ax.set_xlabel('Time in secs')
    ax.set_xlabel('# Windows')
    ax.axhline(y=0, color='k')
    ax.axvline(x=0, color='k')
    ax.set_xlim(xmin=0)
    ax.set_ylim(ymin=0)
    print(path)
    fig.savefig("{}/outgoing_{}_protocols_{}.pdf".format(path, labeling, list_window_size[0]))
    plt.close(fig=fig)

def processing_results_by_directory(folder, showText, total, packets_protocol, bytes_protocol, filter_by_window, layer, min_win, iptables):
    
    # Ordering Files in the directory (useful for window purposes)
    files = os.listdir(folder)
    
    iptables_plotter_list_data = []
    iptables_plotter_list_window_values = [] 
    iptables_plotter_list_window_size = []
    iptables_plotter_list_labels = []

    for filename in files:
        file_path = folder + filename
        if filter_by_window != None and not filter_by_window in filename.replace(".log","").split("_"):
            continue
        
        data_dict, window_values, path, window_size, label = processing_results_by_file(file_path, showText, total, packets_protocol, bytes_protocol,layer=layer, min_win=min_win, iptables=iptables)
        if data_dict:
            iptables_plotter_list_data.append(data_dict)
            iptables_plotter_list_window_values.append(window_values)
            iptables_plotter_list_window_size.append(window_size)
            iptables_plotter_list_labels.append(label)
    
    if iptables_plotter_list_data:
        if "byte" in files[0]:
            bytes_protocol = True
        else:
            bytes_protocol = False
        comparison_iptables_plotter(iptables_plotter_list_data, iptables_plotter_list_window_values, iptables_plotter_list_window_size, iptables_plotter_list_labels, path, bytes_plot=bytes_protocol)
            
def obtain_path(file_name, iptables=False):
    
    splitted_file_name = file_name.split('/')[-1].split('_')

    if iptables:
        rate_name = file_name.split('/')[-2]
        minutes = file_name.split('/')[-3]
        

        dir_name = splitted_file_name[0] + "_" + rate_name + "_" + minutes

        path = "./graphs_iptables/"
        if not os.path.isdir(path):
            os.mkdir(path)

        path += dir_name
        if not os.path.isdir(path):
            os.mkdir(path)
    else:
        mac_address = splitted_file_name[0]

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
    return path

def processing_results_by_file(file_name, showText, total, packets_protocol, bytes_protocol, layer, min_win, iptables=False):
    print("Processing {} ...".format(file_name))
    
    if not file_name.endswith('.log'):
        return
    
    packets_traffic = {}
    packets_lenght = {}
    traffic_by_protocol = {}
    
    initialise_dict(packets_traffic)
    initialise_dict(packets_lenght, True)
   
    counter = 0
    splitted_file_name = file_name.split('/')[-1].split('_')
    window_size = splitted_file_name[-1].replace('.log','')
    if window_size == 'None':
            return
    
    window_size = int(window_size)

    if iptables:
        iptables_enabled = splitted_file_name[-2].replace('.log','')

    else:
        mac_address = splitted_file_name[0]
        resulting_values[mac_address] = []

    path = obtain_path(file_name=file_name, iptables=iptables)
    # print(path)
    
    # Reading the file (obtaining data)
    with open(file_name) as opened_file:
        lines = opened_file.readlines()
        
        real_window_counter = 0
        for line in lines:
            if 'Window' in line:
                window_counter = int(line.split('::')[1].split(':')[0])
                if min_win and window_counter >= min_win:
                    real_window_counter = window_counter - min_win
                elif not min_win:
                    real_window_counter = window_counter
                # Maybe we should have a limit on the amount of window to consider
                # For instance:
                # if window_counter >= 100000:
                #     break
                continue
            if not min_win or window_counter >= min_win:
                
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
                traffic_by_protocol[(protocol, direction, real_window_counter)] = packet_number
    
    
    
    # Time values (x axis) (window*window_size)
    time_values = np.array(list(range(1, real_window_counter+2))) * window_size

    # Window_values
    window_values = np.array(list(range(0, real_window_counter+1)))
    
    # Fill empty values (this allow to have the same dimension)
    temp_dict = {}
    protocols = []
    if not layer is None:
        protocols = protocols_layer.get(layer)

    for (protocol, direction, _) in traffic_by_protocol.keys():
        # Filtering by protocols    
        if protocols and not protocol in protocols:
            continue

        if (protocol,direction) in  temp_dict.keys():
            continue
        
        temp_dict[(protocol,direction)] = []
        
        for counter in range(0, real_window_counter + 1):
            if (protocol, direction, counter) in traffic_by_protocol.keys():
                value = traffic_by_protocol.get((protocol, direction, counter))
            else:
                value = 0 # For that window no packets have been sent
            
            temp_dict[(protocol,direction)].append(value)
    # Analysis values
    if not iptables:
        resulting_values[mac_address].append('Type: {}'.format(categories.get(devices_cat_match.get(mac_address))))
        resulting_values[mac_address].append('avg_tot: {}'.format(round(np.mean(packets_traffic.get(TOTAL)), 3)))
        resulting_values[mac_address].append('avg_incoming: {}'.format(round(np.mean(packets_traffic.get(INCOMING)), 3)))
        resulting_values[mac_address].append('avg_outgoing: {}'.format(round(np.mean(packets_traffic.get(OUTGOING)), 3)))
    ################################

    

    if total and not iptables:    
        #  Plotting incoming and outgoing bytes
        fig, ax = lists_plotting(time_values, packets_lenght.get(INCOMING_BYTES.replace(' ','_')), 
                            packets_lenght.get(OUTGOING_BYTES.replace(' ','_')), 
                            labels=[INCOMING_BYTES, OUTGOING_BYTES], 
                            showText=showText)
        
        if ax is None:
            print('Something went wrong')
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
            print('Something went wrong')
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

    # Plotting packets    
    if iptables:
        return temp_dict, window_values, path, window_size, iptables_enabled
    else:
        if packets_protocol:
            plot_by_protocol(data_dict=temp_dict, time_values=window_values, 
                            path=path, window_size=window_size, mac_address=mac_address, 
                            showText=showText)
        # Plotting bytes
        if bytes_protocol:
            plot_by_protocol(data_dict=temp_dict, time_values=window_values, 
                            path=path, window_size=window_size, mac_address=mac_address, 
                            showText=showText, packets=False)

    plt.show()

    return None, None, None, None, None

def main(argv):
    ####COMMAND TO BE LAUNCHED FOR GENERAL CASE####
    # BYTES: python3 plot_generator.py -f processing_results_general/192.168.3.11_byte_60.log --bytes_protocol -c to_ignore/
    # PACKETS: python3 plot_generator.py -f processing_results_general/192.168.3.11_packet_60.log --packets_protocol -c to_ignore/
    # iptables: python3 plot_generator.py -f processing_results_general/5Min -i -l 4

    # Checking if the directory exists
    myre = re.compile(r'(?:[0-9a-fA-F]:?){6,12}')

    # Category and device matching
    if args.category != None:
        category_path = args.category + "categories.txt"
        device_path = args.category + "devices.txt"
        
        categories[0] = 'not-defined'
        # Initializing categories
        with open(category_path, 'r') as file_categories:
            lines = file_categories.readlines()
            for line in lines:
                categories[int(line.split()[1])] = line.split()[0]
        
        # Initializing devices
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
        processing_results_by_file(args.folder, args.text, args.total, args.packets_protocol, args.bytes_protocol, layer=args.layer, min_win=args.min)
        sys.exit(0)

    if not os.path.isdir(args.folder):
        print('"{}" does not exist'.format(args.folder), file=sys.stderr)
        sys.exit(-1)

    

    for directory in os.listdir(args.folder):
        if not re.findall(myre, directory) and not args.iptables:
            continue
        path = "{}/{}/".format(args.folder, directory)
        if os.path.isdir(path):
            processing_results_by_directory(path, args.text, args.total, args.packets_protocol, args.bytes_protocol, args.filter_by_window, layer=args.layer, min_win=args.min, iptables=args.iptables)

    if args.analysis:
        print("here")
        paper_table_avg_out = {}
        paper_table_UDP_out = {}
        paper_table_TCP_out = {}
        paper_table_TCP_peaks_out = {}
        paper_table_UDP_peaks_out = {}
        with open(args.analysis, "w+") as analysis_file:
            for key in resulting_values.keys():
                analysis_file.write("{}: {}\n\n".format(key, resulting_values.get(key)))
                # paper table
                category = resulting_values.get(key)[0].split(':')[1].replace(" ", "")
                if category not in paper_table_avg_out.keys():
                    paper_table_avg_out[category] = []
                    paper_table_TCP_out[category] = []
                    paper_table_TCP_peaks_out[category] = []
                    paper_table_UDP_out[category] = []
                    paper_table_UDP_peaks_out[category]= []
                for value in resulting_values[key]:
                    to_write =  value.split(":")[1].replace(" ","")
                    if value.split(":")[0] == "avg_outgoing":
                        paper_table_avg_out[category].append(float(to_write))
                    elif value.split(":")[0] == "max_TCP_outgoing":
                        paper_table_TCP_peaks_out[category].append(float(to_write))
                    elif value.split(":")[0] == "avg_TCP_outgoing":
                        paper_table_TCP_out[category].append(float(to_write))
                    elif value.split(":")[0] == "avg_UDP_outgoing":
                        paper_table_UDP_out[category].append(float(to_write))
                    elif value.split(":")[0] == "max_UDP_outgoing":
                        paper_table_UDP_peaks_out[category].append(float(to_write))
                    else:
                        continue
        print("AVG_OUT: {}".format(paper_table_avg_out)) 
        print("TCP_AVG_OUT: {}".format(paper_table_TCP_out))
        print("TCP_PEAKS_AVG_OUT: {}".format(paper_table_TCP_peaks_out))
        print("UDP_AVG_OUT: {}".format(paper_table_UDP_out))
        print("UDP_PEAKS_AVG_OUT: {}".format(paper_table_UDP_peaks_out))      
           

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Plotting pcap processer's result")

    parser.add_argument("--folder", "-f", type=str, required=True, 
                        help="folder containing the data's directories")

    parser.add_argument("--category", "-c", type=str, required=False,
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
    
    parser.add_argument("--layer", "-l", type=int, required=False,
                        help="Plot only protocols of a specified layer (e.g. UDP/TCP layer 4)")

    parser.add_argument("--analysis", "-a", type=str,
                        help='give an output file, named with a specified string, containing useful data (very interesting for analysis purposes)')

    parser.add_argument("--min", "-m", type=int,
                        help="Specify the first window to be shown. If None all windows are plotted")

    parser.add_argument("--iptables", "-i", action='store_true',
                        help="Plotting two lines: iptables, noiptables")

    args = parser.parse_args()
    
    
    main(args)