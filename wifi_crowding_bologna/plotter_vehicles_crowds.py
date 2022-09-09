from turtle import width
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

def main():

    df_vehicles = pd.read_csv("data_to_plot/entering_cars_average.csv", sep=";")

    df_crowd_bologna = pd.read_csv("data_to_plot/data_iperbole_entering.csv", sep=";")

    fig, ax = plt.subplots()
    width = 0.4
    p1 = ax.bar(df_crowd_bologna["ora"].array - width/2, df_crowd_bologna["affluenza_media"].array, width=width, label="UEs", align="center")
    p2 =  ax.bar(df_vehicles["date"].array + width/2, df_vehicles["cars"].array, width=width, label="Cars parking", align="center", color="goldenrod")
    
    ax.set_ylabel("Average")
    ax.set_xlabel("Day Hours")
    ax.set_xticks(np.arange(24), lables=df_crowd_bologna["ora"].array)
    ax.legend()
    # ax.set_title("") # No title!


    plt.show()






if __name__ == "__main__":

    main()