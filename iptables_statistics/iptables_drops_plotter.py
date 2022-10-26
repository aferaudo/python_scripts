import matplotlib.pyplot as plt
import os
import argparse
import numpy as np
import math

def round_up(n, decimals=0):
    multiplier = 10 ** decimals
    return math.ceil(n * multiplier) / multiplier

def packets_bytes_parser(packet_string, bytes_string):
    total_packets = 0
    total_bytes = 0
    
    # PACKETS
    if "K" in packet_string:
        total_packets = int(packet_string.replace("K","")) * 1024
    else:
        total_packets = int(packet_string.replace(" ", ""))

    # BYTES
    if "K" in bytes_string:
        total_bytes = int(bytes_string.replace("K","")) * 1024
    else:
        total_bytes = int(bytes_string.replace(" ", ""))

    return total_packets, total_bytes


def main(argv):
    # python3 iptables_drops_plotter.py --folder ./data -C "MUD_CHAIN"
    # If you want to process more than one file just add *_label.txt, this will gnerate another bar with
    # that label
    
    # processing all .txt data in the specified folder
    data_to_plot_packets = {}
    data_to_plot_bytes = {}
    for file_name in os.listdir(argv.folder):
        if ".md" in file_name or "_ex" in file_name:
            continue

        received_packets = 0
        received_bytes = 0
        dropped_packets = 0
        dropped_bytes = 0
        with open("{}/{}".format(argv.folder,file_name), "r") as fd:
            actual_chain = ""
            for line in fd:
                if "Chain" in line:
                    actual_chain = line.split(" ")[1]
                index_1 = -1
                index_2 = 0
                # We need to do this due to iptables output
                for index, v in enumerate(line.split(" ")):
                    if v != "" and index_1 == -1:
                        index_1 = index
                        continue
                    if v != "":
                        index_2 = index 
                        break
                ###############
                if actual_chain == argv.chain and argv.custom_chain in line:
                    # elaborating content of standard iptables chain
                    received_packets, received_bytes = packets_bytes_parser(line.split(" ")[index_1], line.split(" ")[index_2])
                    # print("total packets received: {}, total bytes received: {}".format(received_packets, received_bytes))

                if actual_chain == argv.custom_chain and "DROP" in line:
                    # print(line.split(" "))
                    dropped_packets, dropped_bytes = packets_bytes_parser(line.split(" ")[index_1],line.split(" ")[index_2])
                    print("{}".format(file_name.split("_")[2].replace(".txt","")))
                    data_to_plot_packets[file_name.split("_")[2].replace(".txt","")] = round_up((dropped_packets/received_packets) * 100, 2)
                    data_to_plot_bytes[file_name.split("_")[2].replace(".txt","")] = round_up((dropped_bytes/received_bytes) * 100, 2)
                    print("ratio packets: {}/{}, ratio bytes: {}/{}".format(dropped_packets, received_packets, dropped_bytes, received_bytes))
                
                #print(actual_chain)

    print("Percentage: ")
    print(data_to_plot_packets)     
    print(data_to_plot_bytes)

    avg_packets = []
    avg_bytes = []
    peaks_packets = []
    peaks_bytes = []
    
    for key in sorted(data_to_plot_packets.keys()):
        if "Avg" in key:
            avg_packets.append(data_to_plot_packets[key])
        else:
            peaks_packets.append(data_to_plot_packets[key])
    
    for key in sorted(data_to_plot_bytes.keys()):
        if "Avg" in key:
            avg_bytes.append(data_to_plot_bytes[key])
        else:
            peaks_bytes.append(data_to_plot_bytes[key])
    

    plt.rcParams.update({'font.size': 14, 'font.family': 'Times New Roman'})
    fig, ax = plt.subplots(figsize = (6, 3))
    fig2, ax2 = plt.subplots(figsize = (6, 3))
    x = np.arange(2)
    width=0.3
    
    rects1 = ax.bar(x - (width+0.01)/2, avg_packets, width, label = 'Packets drop', hatch = "////", edgecolor="black", alpha=0.85,align='center')
    rects2 = ax.bar(x + (width+0.01)/2, avg_bytes, width, label = 'Bytes drop', hatch = "xxx", edgecolor="black", alpha=0.85, align='center')

    rects3 = ax2.bar(x - (width+0.01)/2, peaks_packets, width, label = 'Packets drop', hatch = "////", edgecolor="black", alpha=0.85,align='center')
    rects4 = ax2.bar(x + (width+0.01)/2, peaks_bytes, width, label = 'Bytes drop', hatch = "xxx", edgecolor="black", alpha=0.85, align='center')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Dropped (%)')
    y_ticks = [0, 10, 20, 40, 60, 80, 100]
    ax.set_yticks(y_ticks)
    y_ticks_2 = [0, 0.5, 1, 1.5]
    ax2.set_yticks(y_ticks_2)
    #ax.set_title('Scores by group and gender')
    ax.set_xticks(x, ["Appliances", "Smart-Hubs"])
    ax2.set_xticks(x, ["Appliances", "Smart-Hubs"])
    ax.legend()
    ax2.legend()

    # ax.bar_label(rects1)
    # ax.bar_label(rects2)
    ax.bar_label(rects1, padding=3)
    ax.bar_label(rects2, padding=3)
    ax2.bar_label(rects3, padding=3)
    ax2.bar_label(rects4, padding=3)  
    plt.show()

    




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Plot percentage of packet dropped of a particular chain (iptables should contain a custom chain with a drop rule)")

    parser.add_argument("--folder", "-f", type=str, required=True, 
                        help="folder containing iptables file")
    parser.add_argument("--chain", "-c", type=str, required=False, default="FORWARD",
                        help="iptables chain containing target with custom chain")
    parser.add_argument("--custom-chain", "-C", type=str, required=True,
                        help="custom iptables chain to process")

    args = parser.parse_args()
    
    
    main(args)