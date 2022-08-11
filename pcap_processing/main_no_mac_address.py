from packet_processing_general import GeneralPcapParser

def main():

    parser = GeneralPcapParser()
    parser.packet_byte_rate_window("/Users/angeloferaudo/Desktop/Personal Data/Coding/python_scripts/pcap_processing/test/smart_hubs/noiptables/",ip="192.168.3.11", window=60)

if __name__ == '__main__':
    main()
    