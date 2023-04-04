import os
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import scipy.stats as stats
from scipy.optimize import curve_fit


def occupancy_percentage(row):
    percentage = row['Occupancy']/row['Capacity'] * 100
    return round(percentage, 2)

def difference_dates(row):
    # returns the values in minute
    return round((row['end_parking_dt'] - row['start_parking_dt']).total_seconds() / 60)

def Gauss(x, A, B):
    y = A*np.exp(-1*B*x**2)
    return y

def quadraticFunction(x, a, b, c):
    return a * x + b * x**2 + c

def objective1(x, a, b, c, d, e, f):
	return (a * x) + (b * x**2) + (c * x**3) + (d * x**4) + (e * x**5) + f

def objective(x, a, b, c, d, e, f, g):
	return (a * x) + (b * x**2) + (c * x**3) + (d * x**4) + (e * x**5) + (f * x**6) + g

def main(argv):

    dir_name = 'dataset'
    files = sorted(os.listdir(dir_name))
    total = len(files)
    main_df = pd.DataFrame()
    occupancies = np.empty(1)
    cars = np.empty(1)

    print("Aggregation started...")
    
    for i, file in enumerate(files):
        # if  i == 0:
        #     continue
        df = pd.DataFrame()
        df = pd.read_csv('{}/{}'.format(dir_name, file), sep=';', parse_dates=['start_parking_dt', 'pay_parking_dt', 'end_parking_dt'])
        # Data aggregation
        print("analysing {} {} of {}".format(file, (i+1), total))
        df = df.loc[df['garage_nm'] == argv.parking]
    
        df = df.dropna(subset = ['start_parking_dt', 'end_parking_dt']).reset_index(drop=True)

        # Computing occupancytime and putting it in a new column
        df['occupancyTime'] = df.apply(lambda row : difference_dates(row), axis = 1)
        print(df)
        df = df.groupby(['occupancyTime', 'garage_nm']).size().reset_index()

        
        df.columns = ['occupancyTime', 'garage_nm', 'count']
        # we do not consider car parked for > 10 hours and < 1 minute. Additionallyk, parking times where cars are less than 10
        df = df.loc[(df['count'] > 10) & (df['occupancyTime'] <= 600) & (df['occupancyTime'] >= 1)] 
        main_df = pd.concat([main_df, df], ignore_index=True)
        # occupancies = np.concatenate(occupancies, df['occupancyTime'].to_numpy())
        # cars = np.concatenate(cars, df['count'].to_numpy())
    
    print("End aggregation")
    
    main_df = main_df.sort_values(by=['occupancyTime'])
    
    main_df = main_df.groupby(['occupancyTime']).mean().reset_index()

    print(main_df)
    
    sum = pd.Series(main_df['count']).sum()
    
 
    # print(sum)
    occupancies = main_df['occupancyTime'].to_numpy()
    cars = main_df['count'].to_numpy() / sum
    parameters, covariance = curve_fit(objective, occupancies, cars)
    fit_A = parameters[0]
    fit_B = parameters[1]
    fit_C = parameters[2]
    fit_D = parameters[3]
    fit_E = parameters[4]
    fit_F = parameters[5]
    fit_G = parameters[6]

    print("{} * x**6 + {} * x**5 + {} * x**4 + {} * x**3 + {} * x**2 + {} * x + {}".format(fit_F, fit_E, fit_D, fit_C, fit_B, fit_A, fit_G))

    sum_total = 0
    sum_weights = 0
    M = 0
    for index, row in main_df.iterrows():
        if row['count'] > 0:
            M = M + 1
        sum_total = sum_total + (row['occupancyTime'] * row['count'])
        sum_weights = sum_weights + row['count']

    weighted_mean = sum_total/sum_weights # because the mean should be oriented towards times where there are more parked cars

    num_sum = 0

    for index, row in main_df.iterrows():
        num_sum = num_sum + (row['count'] * np.square((row['occupancyTime'] - weighted_mean)))
    
    weighted_std = np.sqrt(num_sum/(((M-1)/M) * sum_weights))
    print("Media pesata: {}, std pesata: {} ".format(weighted_mean, weighted_std))
    print("Media normale: {}, std normale: {} ".format(np.mean(occupancies), np.std(occupancies)))
    # fit_y = Gauss(occupancies, fit_A, fit_B)
    # fit_y = quadraticFunction(occupancies, fit_A, fit_B, fit_C)
    fit_y = objective(occupancies, fit_A, fit_B, fit_C, fit_D, fit_E, fit_F, fit_G)

    # pdf = stats.norm.pdf(occupancies, np.mean(occupancies), np.std(occupancies))
    pdf = stats.norm.pdf(occupancies, weighted_mean, weighted_std)
    plt.plot(occupancies, cars,'o', label='normalised data')
    plt.plot(occupancies, fit_y, '-', label='fit')
    plt.plot(occupancies, pdf,'-', label='normal', color="red", linewidth=2)

    plt.xlabel('occupancy time (minutes)')
    plt.ylabel('density')

    # df['occupancyTime', 'count'].reset_index(drop=True).plot()
    # df.plot.kde()
    plt.show()




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Arnhem dataset analyser: This program plots the function that describes parked cars along time')

    parser.add_argument('-p', '--parking', metavar='<parking_lot_name>',
                        help='parking lot to filter out from the dataset (by default is Centraal)', type=str, default='Centraal')
    args = parser.parse_args()
   
    main(args)