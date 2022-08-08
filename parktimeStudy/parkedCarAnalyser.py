import os
from turtle import width
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt


weekend = ["Saturday", "Sunday"]
general_counter = 0

def compute_total_parked_cars(x):
    global general_counter
    general_counter = general_counter + x["carsEntered"] - x["carsLeaving"]

    return general_counter

def main():

    print("Average Parked Cars during the day")
    dir_name = 'dataset'
    files = sorted(os.listdir(dir_name))
    total = len(files)

    df = pd.DataFrame()
    for i, file in enumerate(files):
        if  i == 0:
            continue
        df = pd.concat([df, pd.read_csv('{}/{}'.format(dir_name, file), sep=';', parse_dates=['start_parking_dt', 'pay_parking_dt', 'end_parking_dt'])])
        df = df.loc[df["garage_nm"] == "Centraal"]
        print("analysing {} {} of {}".format(file, (i+1), total))

    
    # new Dataframes
    enteringCars = pd.DataFrame()
    outgoingCars = pd.DataFrame()

    enteringCars["start_parking_dt"] = df["start_parking_dt"]
    outgoingCars["end_parking_dt"] = df["end_parking_dt"]
    # print("{} {} {}".format(enteringCars["start_parking_dt"].dt.day, enteringCars["start_parking_dt"].dt.month, enteringCars["start_parking_dt"].dt.hour))
    
    # Group by hour for each day
    enteringCars = enteringCars.groupby([enteringCars["start_parking_dt"].dt.day, enteringCars["start_parking_dt"].dt.month, enteringCars["start_parking_dt"].dt.hour]).count()
    outgoingCars = outgoingCars.groupby([outgoingCars["end_parking_dt"].dt.day, outgoingCars["end_parking_dt"].dt.month, outgoingCars["end_parking_dt"].dt.hour]).count()

    enteringCars["year"] = 2022
    
    enteringCars = enteringCars.rename(columns={"start_parking_dt": "carsEntered"})
    enteringCars = enteringCars.reset_index(level=0).rename(columns={"start_parking_dt": "day"})
    enteringCars = enteringCars.reset_index(level=0).rename(columns={"start_parking_dt": "month"})
    enteringCars = enteringCars.reset_index(level=0).rename(columns={"start_parking_dt": "hour"})

    enteringCars["date"] = pd.to_datetime(enteringCars[["year", "month", "day", "hour"]])

    outgoingCars["year"] = 2022
    outgoingCars = outgoingCars.rename(columns={"end_parking_dt": "carsLeaving"})
    outgoingCars = outgoingCars.reset_index(level=0).rename(columns={"end_parking_dt": "day"})
    outgoingCars = outgoingCars.reset_index(level=0).rename(columns={"end_parking_dt": "month"})
    outgoingCars = outgoingCars.reset_index(level=0).rename(columns={"end_parking_dt": "hour"})

    outgoingCars["date"] = pd.to_datetime(outgoingCars[["year", "month", "day", "hour"]])
    #dropping useless columns
    
    enteringCars = enteringCars.drop(["year", "month", "day", "hour"], axis=1)
    outgoingCars = outgoingCars.drop(["year", "month", "day", "hour"], axis=1)

    # print(enteringCars)
    # print(outgoingCars)

    finalDataFrame = pd.merge(enteringCars, outgoingCars, on="date", how="outer", sort=True)
    finalDataFrame[["carsEntered", "carsLeaving"]] = finalDataFrame.select_dtypes('float64').fillna(0)

    
    finalDataFrame["total_parked"] = finalDataFrame.apply(lambda row : compute_total_parked_cars(row), axis=1)
    # finalDataFrame.to_csv("join.csv", sep=";")
    
    # We should delete some rows because the first ones don't represent the real scenario: counter is set to zero initially
    finalDataFrame.drop(index=df.index[:100], axis=0, inplace=True)
    finalDataFrame = finalDataFrame.reset_index(drop=True)
    # work days
    # Remove weekend
    # In this park usually during the weekend there is a greater number of vehicles compared with ferial days
    # Thus, we should separate the aggregation
    # work_days_df = pd.DataFrame()
    # work_days_df = finalDataFrame.loc[(finalDataFrame["date"].dt.day_name()!="Saturday") & (finalDataFrame["date"].dt.day_name()!="Sunday")]
    
    # # weekend
    # # remove work days
    # weekend_df = pd.DataFrame()
    # weekend_df = finalDataFrame.loc[(finalDataFrame["date"].dt.day_name()=="Saturday") | (finalDataFrame["date"].dt.day_name()=="Sunday")]


    collapsed_in_hours = pd.DataFrame()
    collapsed_in_hours = finalDataFrame.groupby(finalDataFrame["date"].dt.hour)["total_parked"].mean().reset_index(name="parkedAverage")
    print(collapsed_in_hours)

    fig, ax = plt.subplots()
    p1 = ax.bar(collapsed_in_hours['date'].array, collapsed_in_hours['parkedAverage'].array, width=0.35, label='Total', align='center', color='goldenrod')

    ax.set_ylabel("Average Parked Cars")
    ax.set_xlabel("Day Hours")
    ax.set_xticks(np.arange(24), lables=collapsed_in_hours["date"].array)

    plt.show()


if __name__ == '__main__':
    main()