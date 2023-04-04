import os
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import analyser as an
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures

global file_index
file_index = 0

def fromTimeToSec(row):
    return row.hour *3600+ row.minute*60 + row.second

def plottingOccupancyTimes(df, occupancy_col='average', time_col='seconds'):
    global file_index
    occupancies = df[occupancy_col].to_numpy()
    times = df[time_col].to_numpy()
    plt.plot(times, occupancies,'o', label='study on occupancy time average')
    # plt.show()
    # plt.savefig('line_plot_{}.pdf'.format(file_index))  
    file_index = file_index + 1

def aggregatorFuncEnterLeav(df, interval=30):
    # interval in minutes
    print("do something")
    temp_df_entering = df.resample('{}T'.format(interval), on='start_parking_dt')['start_parking_dt'].count().reset_index(name='entering_cars_{}_minutes'.format(interval))
    temp_df_leaving = df.resample('{}T'.format(interval), on='end_parking_dt')['end_parking_dt'].count().reset_index(name='leaving_cars_{}_minutes'.format(interval))

    
    temp_df_entering["start_parking_dt"] = temp_df_entering["start_parking_dt"].dt.time
    temp_df_leaving["end_parking_dt"] = temp_df_leaving["end_parking_dt"].dt.time

    temp_df_entering = temp_df_entering.groupby('start_parking_dt')['entering_cars_{}_minutes'.format(interval)].mean().reset_index(name='average_entering_each_{}_minutes'.format(interval))
    temp_df_leaving = temp_df_leaving.groupby('end_parking_dt')['leaving_cars_{}_minutes'.format(interval)].mean().reset_index(name='average_leaving_each_{}_minutes'.format(interval))

    temp_df_entering = temp_df_entering.rename(columns={"start_parking_dt": "date"})
    temp_df_leaving = temp_df_leaving.rename(columns={"end_parking_dt": "date"})
    
    temp_df_entering.to_csv("entering_cars_each_{}_minutes.csv".format(interval),sep=';')
    temp_df_leaving.to_csv("leaving_cars_each_{}_minutes.csv".format(interval),sep=';')
   

def aggregatorFunc(df, interval=10):
    # interval in minutes

    temp_df = df.resample('{}T'.format(interval), on='start_parking_dt')['occupancyTime'].mean().reset_index(name='average_occupancy_time')
    temp_df['time'] = temp_df['start_parking_dt'].dt.time
    temp_df = temp_df.dropna()
    temp_df = temp_df.groupby(['time']).agg({'average_occupancy_time':['mean','std']}).reset_index()
    temp_df = temp_df.droplevel(0, axis=1)
    temp_df['time'] = temp_df['']
    temp_df = temp_df[['time', 'mean', 'std']]
    # temp_df = temp_df.agg(['mean', 'std']).reset_index()
    # print(temp_df)
    # temp_df.to_csv("test_4.csv", sep=";")

    # Operations to compute time in seconds
    # temp_df['seconds'] = temp_df['start_parking_dt'].dt.time
    # temp_df['seconds'] = temp_df['seconds'].apply(lambda row : fromTimeToSec(row))
    # temp_df = temp_df.dropna()
    # temp_df_2 = df.resample('{}T'.format(interval), on='start_parking_dt')['start_parking_dt'].count().reset_index(name='number of cars')
    # occupancies = temp_df['average'].to_numpy()
    # times = temp_df['seconds'].to_numpy()
    # return occupancies, times
    return temp_df



def main():

    dir_name = 'dataset' # To change
    files = sorted(os.listdir(dir_name))
    total = len(files)
    main_df = pd.DataFrame()
    main_df_2 = pd.DataFrame()
    main_complete_df = pd.DataFrame()

    for i, file in enumerate(files):
        df = pd.DataFrame()
        print("Analysing {} {} of {}".format(file, i+1, total))
        # if i < 4:
        #     print("Skipping..")
        #     continue
        complete_df = pd.read_csv('{}/{}'.format(dir_name, file), sep=';', parse_dates=['start_parking_dt', 'pay_parking_dt', 'end_parking_dt'])

        
        complete_df = complete_df.loc[complete_df['garage_nm'] == "Centraal"]
        complete_df = complete_df.dropna(subset = ['start_parking_dt', 'end_parking_dt']).reset_index(drop=True)
        
        df = complete_df

        # Computing occupancytime and putting it in a new column
        df['occupancyTime'] = df.apply(lambda row : an.difference_dates(row), axis = 1)
        
        # Selecting a subset of columns
        df = df[["start_parking_dt", "occupancyTime"]]

        # we do not consider car parked for > 10 hours and < 1 minute.
        df = df.loc[(df['occupancyTime'] <= 600) & (df['occupancyTime'] >= 1)]

        # converting time in seconds
        #df['time in seconds'] = (df["start_parking_dt"].dt.hour * 3600) + (df["start_parking_dt"].dt.minute * 60)  + df["start_parking_dt"].dt.second
        df['hour'] = df['start_parking_dt'].dt.hour
        
        test = aggregatorFunc(df)
        test['seconds'] = test['time'].apply(lambda row : fromTimeToSec(row))
        plottingOccupancyTimes(test,occupancy_col='mean',time_col='seconds')

        # Creating dataframe to manage cars entering in a certain hour
        df2 = pd.DataFrame()
        df2['day'] = df["start_parking_dt"].dt.day
        df2['hour'] = df["start_parking_dt"].dt.hour
        df2['month'] = df["start_parking_dt"].dt.month
        df2 = df2.groupby(['day','hour', 'month'])['hour'].count().reset_index(name='count')
        df2.to_csv("test.csv", index=False)
        main_df = pd.concat([main_df, df], ignore_index=True)
        main_df_2 = pd.concat([main_df_2, df2], ignore_index=True)
        main_complete_df = pd.concat([main_complete_df, complete_df], ignore_index=True)
    
    print(main_df)
    print(main_complete_df)
    aggregatorFuncEnterLeav(main_complete_df)
    # main_df.to_csv("test.csv")
    
    
    # Plotting occupancy times
    # occupancies, times = plottingCarsInInterval(df=main_df)
    # main_df = aggregatorFunc(df=main_df)
    # main_df['seconds'] = main_df['time'].apply(lambda row : fromTimeToSec(row))
    # plottingOccupancyTimes(main_df,occupancy_col='mean',time_col='seconds')
    # main_df.to_csv("OccTimeGaussianDistr10Minutes.csv", sep=";")
    
    # Computing averages
    # main_df = main_df.groupby(['hour']).mean().reset_index()
    # main_df_2 = main_df_2.groupby(['hour'])['count'].mean().reset_index(name='cars average')
    
    # print(main_df)
    # print(main_df_2)
    # hours = main_df['hour'].to_numpy() # x
    # occupancies = main_df['occupancyTime'].to_numpy() # y
    # cars = main_df_2['cars average'].to_numpy() # z

    # fig = plt.figure()
    # ax = fig.add_subplot(111, projection='3d')
    # dx = np.full(24, 0.5)   # Width of each bar
    # dy = np.full(24, 20)   # Depth of each bar
    # z = np.zeros(24)       # Height of each bar

    # ax.bar3d(hours, occupancies, z, dx, dy, cars)

    # plt.plot(times, occupancies,'o', label='study on occupancy time average')
    # ax.set_xticks(hours)
    
    # ax.set_xlabel("Hours of the day")
    # ax.set_ylabel("Occupancy time (minutes)")
    # ax.set_zlabel("Number of Cars")

    # plt.show()


if __name__ == '__main__':
    main()