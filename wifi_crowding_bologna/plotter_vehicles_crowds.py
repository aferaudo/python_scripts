from turtle import width
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt


def main():

    # df_vehicles = pd.read_csv("data_to_plot/entering_cars_average.csv", sep=";")

    df_vehicles_half_enter = pd.read_csv("data_to_plot/entering_cars_each_30_minutes.csv", sep=";")
    df_vehicles_half_leave = pd.read_csv("data_to_plot/leaving_cars_each_30_minutes.csv", sep=";")
    print(df_vehicles_half_enter)
    # df_crowd_bologna = pd.read_csv("data_to_plot/data_iperbole_entering.csv", sep=";")

    times_ticks = ["10:00", "10:30", "11:00", "11:30", "12:00", "12:30", "13:00", "13:30", "14:00", "14:30", "15:00", "",
                   "16:00", "", "17:00", "", "18:00", "", "19:00", "", "20:00", "", "21:00", "",
                   ]
    plt.rcParams.update({'font.size': 22, 'font.family': 'Times New Roman'})
    fig, ax = plt.subplots(figsize=(10, 5.8))
    width = 0.4
    #p1 = ax.bar(df_crowd_bologna["ora"].array - width/2, df_crowd_bologna["affluenza_media"].array, width=width, label="UEs", align="center")
    #p2 =  ax.bar(df_vehicles["date"].array + width/2, df_vehicles["cars"].array, width=width, label="Cars parking", align="center", color="goldenrod")
    
    X_axis = np.arange(len(times_ticks)-10)
    p3 = ax.bar(X_axis-width/2, df_vehicles_half_enter["average_entering_each_30_minutes"].array[30:44], width=width, label="Cars parking", align="center", color="#1f77b4", edgecolor="#000000", linewidth=2)
    p4 = ax.bar(X_axis+width/2, df_vehicles_half_leave["average_leaving_each_30_minutes"].array[30:44], width=width, label="Cars leaving", align="center", color="#ff7f0e",  edgecolor="#000000", linewidth=2)

    ax.set_ylabel("Average Number of Cars")
    ax.set_xlabel("Time")
    # Ticks first graph
    ax.set_xticks(X_axis, labels=times_ticks[10:])
    
    # Ticks second graphs

    ax.legend()
    ax.grid(linestyle="--", linewidth=0.2)
    # ax.set_title("") # No title!
    # print(df_crowd_bologna)
    # print(np.ceil(df_crowd_bologna["affluenza_media"].array))

    plt.tight_layout(pad=0.4, w_pad=0.5, h_pad=1.0)

    plt.savefig("enteringVehicles.pdf", bbox_inches='tight', pad_inches=0, transparent=True)
    plt.show()






if __name__ == "__main__":

    main()