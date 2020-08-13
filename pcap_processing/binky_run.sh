#!/bin/bash

# This implementation run thep packet processer in the binky machine

# <path>/mac_address/unctrl/*.pcap

# Path in binky
# "/local/scratch/rmm1002/imperial-data/sigcomm/pcaps"

INITIAL_PATH=$1

# Test
# source /Users/angeloferaudo/Desktop/Research\ activities/Internship\ July-September/IoT\ Data/data_analysis_script/venv/bin/activate

for FOLDER_L1 in "$INITIAL_PATH"/*;do
    # First layer mac address folders
    for FOLDER_L2 in "$FOLDER_L1"/*;do
        # Second layer unctrl, ctrl#
        python main.py --folder "$FOLDER_L2"/ --packet_rate_final
    done
done

# Test
# deactivate
