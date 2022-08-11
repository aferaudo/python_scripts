import os
import ast
import numpy as np


def main():

    #Opening file
    with open("packets.txt", "r") as fd:
        print("----------Packets Analysis----------")
        #print(fd.read().split("AVG_OUT:")[0].replace(" ", ""))
        for line  in fd:
            
            read_line = line.split("AVG_OUT:")[1].replace(" ", "")
            # print(read_line)
            my_dict = ast.literal_eval(read_line)

            np_array = np.array(my_dict['smart-hubs'])

            print("{} of category smart-hubs: {}".format(line.split(":")[0], np_array.mean()))

    with open("bytes.txt", "r") as fd:
        print("----------Bytes Analysis----------")
        #print(fd.read().split("AVG_OUT:")[0].replace(" ", ""))
        for line  in fd:
            
            read_line = line.split("AVG_OUT:")[1].replace(" ", "")
            # print(read_line)
            my_dict = ast.literal_eval(read_line)

            np_array = np.array(my_dict['smart-hubs'])

            print("{} of category smart-hubs: {}".format(line.split(":")[0], np_array.mean()))
            
            

if __name__ == '__main__':
    main()