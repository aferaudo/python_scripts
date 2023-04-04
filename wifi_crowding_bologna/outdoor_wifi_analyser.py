from asyncio.base_subprocess import ReadSubprocessPipeProto
from dataclasses import field
import requests
import argparse
from datetime import datetime, timedelta
import urllib.parse as urlParser
import geopandas
from shapely.geometry import Polygon
import pandas
import matplotlib.pyplot as plt
import numpy as np

# field_to_monitor = "affollamento_medio"
field_to_monitor = "affluenza_media"

gdf = geopandas.read_file("geometry.json") # change geometry.json to change polygon

output_data = {
    "nome_zona" : [],
    "data" : [],
    "ora" : [],
    field_to_monitor : []
}

def elaborate_results(records):
    for record in records:
        values = record["record"]["fields"]
        polygon_geom = Polygon(values["geo_shape"]["geometry"]["coordinates"][0])
        gdf1 = geopandas.GeoDataFrame({'geometry':[polygon_geom]}).set_crs(4326)
        # df1 = df1.to_crs()
        # print(df["geometry"])
        if gdf["geometry"].intersects(gdf1["geometry"])[0]:
            print("Analysing {}".format(values["nome_zona"]))
            output_data["nome_zona"].append(values["nome_zona"])
            output_data["data"].append(values["data"])
            output_data["ora"].append(values["ora"])
            output_data[field_to_monitor].append(values[field_to_monitor])
    



def main(argv):

    # basic_url = "https://opendata.comune.bologna.it/api/v2/catalog/datasets/iperbole-wifi-affollamento/records?select=geo_shape%2C%20nome_zona%2C%20data%2C%20ora%2C%20{}&&timezone=Europe%2FBerlin&where=".format(field_to_monitor)
    basic_url = "https://opendata.comune.bologna.it/api/v2/catalog/datasets/iperbole-wifi-affluenza/records?select=geo_shape%2C%20nome_zona%2C%20data%2C%20ora%2C%20{}&&timezone=Europe%2FBerlin&where=".format(field_to_monitor)
    
    datetime_str = '2023-01-01 00:00:00'
    datetime_s_object = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
    
    datetime_str = '2023-04-01 00:00:00'
    datetime_e_object = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
    
    while datetime_s_object < datetime_e_object:
        start_date = datetime_s_object.isoformat()
        datetime_s_object += timedelta(days=1)
        end_date = (datetime_s_object - timedelta(seconds=1)).isoformat()
        
        # First query
        query = urlParser.quote("data>=date'" + start_date + "' and data<=date'" +end_date + "'")+ "&sort=data&limit=50" # We need to specify other facet
        final_url = basic_url + query
        response = requests.get(final_url)
        # print(final_url)
        # print(response.json())
        elaborate_results(response.json()["records"])
        link_next_page = "init" # simulating do while
        # Finding link for the next page (do it until the last page)
        while link_next_page:
            link_next_page = ""
            links = response.json()["links"] # it is a list of element
            for link in links:
                # Each link is a dict with the following keys:
                # rel: 'last', 'previous', 'next', 'self', 'first'
                # href: link
                if link['rel'] == 'next':
                    link_next_page = link['href']
                    break
            if not link_next_page:
                print("No next page")
                break
            # print(link_next_page)
            response = requests.get(link_next_page)
            elaborate_results(response.json()["records"])



    df = pandas.DataFrame(data=output_data)

    df = df.groupby(df["ora"]).mean().reset_index()

    df.to_csv("data_iperbole_entering_new.csv", sep=";")

    fig, ax = plt.subplots()

    p1 = ax.bar(df["ora"].array, df[field_to_monitor].array, width=0.4, label='UEs', align='center', color='goldenrod')

    ax.set_ylabel("Average UEs")
    ax.set_xlabel("Day Hours")
    ax.set_xticks(np.arange(24), lables=df["ora"].array)
    ax.set_title("UEs Average")

    plt.show()




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Iperbole crowding in Bologna')

    # TODO to be defined
    parser.add_argument('-s', '--startDate', metavar='<data_filter_start_time>',
                        help='startDate', type=str)
    
    parser.add_argument('-e', '--endDate', metavar='<data_filter_end_time>',
                        help='endDate', type=str)

    args = parser.parse_args()
   
    main(args)