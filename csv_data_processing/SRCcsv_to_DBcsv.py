import pandas as pd
import os

# TODO implement multiple files (maybe this should be the most external loop)

def dict_initialization(portata_length=1):
    db_dict = dict()
    db_dict["COD_POZZO"] = list()
    db_dict["DATA_ORA"] = list()
    db_dict["LIVELLO"] = list()

    if portata_length == 1:
        db_dict["PORTATA"] = list()
    else:
        for i in range(0, portata_length):
            db_dict["PORTATA_{}".format(i)] = list()
        
    return db_dict

# Loop on each file in the directory
data_source_dir = "data_source/"
file_list = os.listdir(data_source_dir)
total_files = len(file_list)
for k, file_name in enumerate(file_list):
    
    if not file_name.endswith(".csv"):
        print("{}: Bad file format".format(file_name))
        continue
    
    print("Analysing {}/{} file: {}...".format(k+1, total_files, file_name))
    pozzi = pd.read_csv("{}{}".format(data_source_dir, file_name), sep=";", decimal=",")
    tags = pd.read_excel('pozzi_tags/Tag Pozzi con Sonde_per TLC.xlsx')
    initial_path = "db_data/"


    level_data = pd.DataFrame()
    # Loop on file containing sensor tags (short loop)
    for index_tags, row_tags in tags.iterrows():
        # Variable initialization
        cod_pozzo = row_tags["DENOMINAZIONE"]
        print("Pozzo: {}".format(cod_pozzo))
        rel_path = "{}{}.csv".format(initial_path, row_tags["TERRITORIO"])
        # print("File: {}".format(rel_path))
        
        # Take level data (only if new one)
        # if previous data was related to the same level sensor, we should skip
        if not level_data.empty and not level_data[level_data.TAG.eq(row_tags["TAG_LIV"])][["TAG"]].empty:
            continue
        level_data = pozzi[pozzi.TAG.eq(row_tags["TAG_LIV"])][["TAG", "MEDIA", "DATA_ORA"]]

        # We can have multiple portata sensors but one level sensor. So, we should base our data search on the latter
        portata_sensors = tags[tags.TAG_LIV.eq(row_tags["TAG_LIV"])][["TAG_PORTATA"]]
        
        # Debugging
        # print("LEVEL DATA")
        # print(level_data)
        # print("PORTATA SENSORS")
        # print(portata_sensors)

        # It is possible that a file does not contain data regarding that sensor, in such a case skip...
        if level_data.empty:
            print("{} not found in {} skip...".format(row_tags["TAG_LIV"], file_name))
            continue

        
        port_data = pd.DataFrame(columns=["TAG", "MEDIA", "DATA_ORA"])

        # Here we manage the multiple portata sensors.
        for _, portata_sensor in portata_sensors.iterrows():
            temp_df = pozzi[pozzi.TAG.eq(portata_sensor["TAG_PORTATA"])][["TAG", "MEDIA", "DATA_ORA"]]
            if not temp_df.empty:
                port_data = port_data.append(temp_df, ignore_index=True)
        
        # It is possible that a file does not contain data regarding that sensor, in such a case skip...
        if port_data.empty:
            print("{} not found in {}skip...".format(row_tags["TAG_PORTATA"], file_name))
            continue

        # New dict initialization
        print(portata_sensors)
        db_dict = dict_initialization(portata_length=len(portata_sensors))
        print(db_dict)

        # Check if the file already exists, if yes we have to initialize the DataFrame
        main_df = pd.DataFrame
        if os.path.isfile(rel_path):
            main_df=pd.read_csv(rel_path, sep=";")
        

        # Populating dictionary (long loop)
        for index, row in level_data.iterrows():
            # Take only MEDIA and DATA_ORA data
            # There is the possibility that the same sensors record two times in the same our (see in B1). In such a case we group by
            portata = port_data.loc[port_data.DATA_ORA.eq(row.DATA_ORA)][["TAG","MEDIA", "DATA_ORA"]]
            port_data.astype({"MEDIA":"float64"}) # TODO problem: 8,79 != 8.79
            # We need to force media as float
            portata = portata.groupby(["TAG","DATA_ORA"]).mean()
            if not portata.empty:
                db_dict["COD_POZZO"].append(cod_pozzo)
                db_dict["DATA_ORA"].append(row["DATA_ORA"])
                db_dict["LIVELLO"].append(row["MEDIA"])
                if len(portata) > 1:
                    i = 0
                    # j does not start from zero
                    for _, row_portata in portata.iterrows():
                        db_dict["PORTATA_{}".format(i)].append(row_portata["MEDIA"])
                        i = i + 1
                else:
                    db_dict["PORTATA"].append(portata["MEDIA"].iloc[0])

        # Creating csv files
        secondary_df = pd.DataFrame(db_dict, columns=list(db_dict.keys()))
        if not main_df.empty:
            print("Writing csv {} MAIN".format(rel_path))
            main_df = main_df.append(secondary_df)
            # Writing csv file
            main_df.to_csv(rel_path, index=False, sep=";")
        else:
            print("Writing csv {} Secondary".format(rel_path))
            secondary_df.to_csv(rel_path, index=False, sep=";")
            
        
    
    