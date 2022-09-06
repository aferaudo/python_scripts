from asyncio.base_subprocess import ReadSubprocessPipeProto
from dataclasses import field
import requests
import argparse
from datetime import datetime, timedelta
import urllib.parse as urlParser
import geopandas
from shapely.geometry import Polygon
import pandas

gdf = geopandas.read_file("geometry.json") # change geometry.json to change polygon

output_data = {
    "nome_zona" : [],
    "data" : [],
    "ora" : [],
    "affollamento_medio" : []
}

def elaborate_results(records):
    for record in records:
        values = record["record"]["fields"]
        print("Analysing {}".format(values["nome_zona"]))
        polygon_geom = Polygon(values["geo_shape"]["geometry"]["coordinates"][0])
        gdf1 = geopandas.GeoDataFrame({'geometry':[polygon_geom]}).set_crs(4326)
        # df1 = df1.to_crs()
        # print(df["geometry"])
        if gdf["geometry"].intersects(gdf1["geometry"])[0]:
            output_data["nome_zona"].append(values["nome_zona"])
            output_data["data"].append(values["data"])
            output_data["ora"].append(values["ora"])
            output_data["affollamento_medio"].append(values["affollamento_medio"])
    



def main(argv):

    basic_url = "https://opendata.comune.bologna.it/api/v2/catalog/datasets/iperbole-wifi-affollamento/records?select=geo_shape%2C%20nome_zona%2C%20data%2C%20ora%2C%20affollamento_medio&&timezone=Europe%2FBerlin&where="
    
    datetime_str = '2022-07-01 00:00:00'
    datetime_s_object = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
    
    datetime_str = '2022-07-04 00:00:00'
    datetime_e_object = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
    
    while datetime_s_object < datetime_e_object:
        start_date = datetime_s_object.isoformat()
        datetime_s_object += timedelta(days=1)
        end_date = (datetime_s_object - timedelta(seconds=1)).isoformat()
        
        # First query
        query = urlParser.quote("data>=date'" + start_date + "' and data<=date'" +end_date + "'")+ "&sort=data" # We need to specify other facet
        final_url = basic_url + query
        response = requests.get(final_url)

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
            response = requests.get(link_next_page)
            elaborate_results(response.json()["records"])



    df = pandas.DataFrame(data=output_data)

    df.to_csv("data_iperbole_test.csv", sep=";")
            

    
    


    # end_date = datetime_s_object + 1
    

    # api_url = "https://opendata.comune.bologna.it/api/v2/catalog/datasets/iperbole-wifi-affollamento/records?q=data%3A%5B2022-06-30T22%3A00%3A00Z&sort=data"
    # response = requests.get(api_url)
    # print(response.json())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Iperbole crowding in Bologna')

    # TODO to be defined
    parser.add_argument('-s', '--startDate', metavar='<data_filter_start_time>',
                        help='startDate', type=str)
    
    parser.add_argument('-e', '--endDate', metavar='<data_filter_end_time>',
                        help='endDate', type=str)

    args = parser.parse_args()
   
    main(args)