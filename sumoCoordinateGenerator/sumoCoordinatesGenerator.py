import geojson
import sumolib

from lxml import etree

# This script converts the coordinates from geojson to sumo coordinates
# Furthermore it generates a RSU.xml file with the coordinates of the RSUs in geojson format

def main():
    
    with open('geojsonCoordinates/coordinates.geojson') as fp:
        gj = geojson.load(fp)

    root = etree.Element("RSUs")

    for index, feature in enumerate(gj['features']):
        longitude = feature['geometry']['coordinates'][0]
        latitude = feature['geometry']['coordinates'][1]
        net = sumolib.net.readNet("sumoNetwork/sumoNetwork.net.xml")
        x, y = net.convertLonLat2XY(longitude, latitude)
        print("x: " + str(x) + " y: " + str(y))
        doc = etree.SubElement(
            root, "rsu",
            id=str(index),
            positionX=str(x), positionY=str(y))

        # static direction of the antenna
        etree.SubElement(doc, "antenna", direction="-0.0881487013012407")
        etree.SubElement(doc, "antenna", direction="-3.0129436717947353")
        etree.SubElement(doc, "antenna", direction="-1.515835552273525")

    tree = etree.ElementTree(root)
    tree.write("RSU.xml", pretty_print=True)

if __name__ == '__main__':
    main()