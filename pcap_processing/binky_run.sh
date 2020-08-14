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
        for i in 1 60 300;do
            # timestamp=`date "+%Y%m%d-%H%M%S"`
            start_time=`date +%s`
            python main.py --folder "$FOLDER_L2"/ --packet_rate_final -w $i >> test.log
            end_time=`date +%s`
            echo "execution time `expr $end_time - $start_time` s." >> test.log
        done
    done
done

# Test
# deactivate
