import argparse
import os
import sys
import matplotlib.pyplot as plt
import matplotlib
import numpy as np


BYTES_FILE="bytes.txt"
PACKETS_FILE="packets.txt"

bytes_dict = {}
packets_dict = {}

def plotter():
    fig, ax = plt.subplots()
    
    plt.grid(linestyle="dashed", color='lightgrey')
    
    n_groups = 2
    index = np.arange(n_groups)
    bar_width = 0.10
    opacity = 1


    # for i, target in enumerate(packets_dict.keys()):
    #     if not bytes_dict.get(target):
    #         continue
    #     if i > 0:
    #         value = index+bar_width
    #     else:
    #         value = index
    #     rects = ax.bar(value, [packets_dict.get(target), bytes_dict.get(target)], bar_width,
    #     alpha=opacity,
    #     label=target)
    
    rects = ax.bar(index, [packets_dict.get("ACCEPT"), bytes_dict.get("ACCEPT")], 
            bar_width, label="ACCEPT")
    
    rects2 = ax.bar(index+bar_width, [packets_dict.get("DROP"), bytes_dict.get("DROP")], bar_width, label="DROP")

    
    plt.xticks(index + bar_width/2, ("PACKET_NO", "PACKET_SIZE"))
    plt.tight_layout()
    plt.show()


def main(argv):
    if not os.path.isfile(BYTES_FILE):
        print("Bytes file not found: please run iptables_statics first")
        sys.exit(-1)
    
    if not os.path.isfile(PACKETS_FILE):
        print("Packets file not found: please run iptables_statics first")
        sys.exit(-1)

    with open(BYTES_FILE, 'r') as f:
        for line in f:
            bytes_dict[line.split(" ")[0]] = int(line.split(" ")[1].replace("\n",""))
    
    with open(PACKETS_FILE, 'r') as f:
        for line in f:
            packets_dict[line.split(" ")[0]] = int(line.split(" ")[1].replace("\n",""))
    
    plotter()
    
    print(bytes_dict)
    print(packets_dict)
            





if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Plotting iptables data, by reading  \"bytes.txt\" and \"packets.txt\" files")
    
    args = parser.parse_args()
    
    main(args)
