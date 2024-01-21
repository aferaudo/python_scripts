import pandas as pd
import plotly.express as px

def main():
    
    df = pd.read_csv("config/dataset.csv", sep=";")
    df = df.dropna()
    px.set_mapbox_access_token(open("config/.mapbox_token").read())

    df = df.groupby(["ID_univoco_stazione_spira", "geopoint"]).size().reset_index(name="count")
    df[['lat', 'longi']] = df['geopoint'].str.split(', ', expand=True)
    df['lat'] = pd.to_numeric(df['lat'], errors='coerce')
    df['longi'] = pd.to_numeric(df['longi'], errors='coerce')

    print(df)
    # fig = px.scatter_mapbox(df,
    #                 lat=df.lat,
    #                 lon=df.longi,
    #                 hover_name="ID_univoco_stazione_spira")
    # fig.show()

if __name__ == '__main__':
    main()