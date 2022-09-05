from asyncio.base_subprocess import ReadSubprocessPipeProto
import requests
import argparse
from datetime import datetime, timedelta
import urllib.parse as urlParser



def main(argv):

    basic_url = "https://opendata.comune.bologna.it/api/v2/catalog/datasets/iperbole-wifi-affollamento/records?where="
    
    datetime_str = '2022-07-01 00:00:00'
    datetime_s_object = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
    
    datetime_str = '2022-07-04 00:00:00'
    datetime_e_object = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
    
    while datetime_s_object < datetime_e_object:
        start_date = datetime_s_object.isoformat()
        datetime_s_object += timedelta(days=1)
        end_date = (datetime_s_object - timedelta(seconds=1)).isoformat()
        print(end_date)
        query = urlParser.quote("data>=date'" + start_date + "' and data<=date'" +end_date + "'")+ "&sort=data" # We need to specify other facet
        final_url = basic_url + query
        print(final_url)

    
    


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