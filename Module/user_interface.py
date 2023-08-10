import sys
from tkinter import StringVar
import pcap_reader
import plot_lan_network
import communication_details_fetch
import device_details_fetch
import report_generator
import tor_traffic_handle
import time
import threading
import memory
from PIL import Image,ImageTk
import os, sys

class pcapXrayCLI():
    def __init__(self):
        import datetime
        current_date = datetime.date.today()
        date_string = current_date.strftime("%Y-%m-%d")
        self.pcap_file = f'<Set the Directory>/AdvancePcapXray/zeek/packets_{date_string}/capture.pcap'
        self.destination_report = '<Set the Directory>/AdvancePcapXray/Module/Report'
        
        self.engine = str()
        self.engine = 'scapy'
        
        self.option = str()
        self.options = {'All', 'HTTP', 'HTTPS', 'Tor', 'Malicious', 'ICMP', 'DNS'}
        self.from_ip = str()
        self.from_hosts = {"All"}
        self.to_ip = str()
        self.to_hosts = {"All"}
        self.from_menu = self.from_hosts
        self.to_menu = self.to_hosts

        self.from_menu={"All"}
        self.to_menu={"All"}
        self.option={"All"}

        self.analyse()

        self.pcap_file= ''
    
    def analyse(self):
        self.pcap_analyse()

    def pcap_analyse(self):
        if not os.access(self.destination_report, os.W_OK):
            print("Error","Permission denied to create report! Run with higher privilege.")
            return

        if os.path.exists(self.pcap_file):
            #PcapRead - First of All!
            packet_read = threading.Thread(target=pcap_reader.PcapEngine,args=(self.pcap_file, self.engine))
            packet_read.start()
            print("Reading the packets")
            while packet_read.is_alive():
                continue
            packet_read.join()

            self.browse_directory("pcap")
            self.browse_directory("report")


            #Report Generation of the PcapData
            reportThreadpcap = threading.Thread(target=report_generator.reportGen(self.destination_report,self.filename).packetDetails,args=())
            reportThreadpcap.start()

            #Reset
            self.details_fetch = 0
            self.to_hosts = {"All"}
            self.from_hosts = {"All"}

            self.to_menu.update(self.to_hosts)
            self.from_menu.update(self.from_hosts)
            self.from_menu={"All"}
            self.to_menu={"All"}
            self.option={"All"}

            self.to_hosts.update(memory.destination_hosts.keys())

            for mac in list(memory.lan_hosts.keys()):
                self.from_hosts.add(memory.lan_hosts[mac]["ip"])
            self.to_hosts = list(self.to_hosts.union(self.from_hosts))
            self.to_menu.update(self.to_hosts)
            self.from_menu.update(self.from_hosts)

            self.map_select()
            self.gimmick()

        else:
            print("File Not Found !")

    def generate_graph(self):
        if self.details_fetch == 0:
            t = threading.Thread(target=communication_details_fetch.trafficDetailsFetch,args=("sock",))
            t1 = threading.Thread(target=device_details_fetch.fetchDeviceDetails("ieee").fetch_info, args=())
            t.start()
            t1.start()
            print("Generating Graph")
            while t.is_alive():
                continue
            t.join()
            t1.join()
            
            self.details_fetch = 1

            reportThread = threading.Thread(target=report_generator.reportGen(self.destination_report, self.filename).communicationDetailsReport,args=())
            reportThread.start()
            reportThread = threading.Thread(target=report_generator.reportGen(self.destination_report, self.filename).deviceDetailsReport,args=())
            reportThread.start()

        
        # Loding the generated map
        options = str(self.option) + "_" + self.to_ip.replace(".", "-") + "_" + self.from_ip.replace(".", "-")
        self.image_file = os.path.join(self.destination_report,"index.png")
        if not os.path.exists(self.image_file):
            t1 = threading.Thread(target=plot_lan_network.main, args=(self.filename, self.destination_report, self.option, self.to_ip, self.from_ip))
            t1.start()
            print("Ladign the generated graph")
            while t1.is_alive():
                continue
            t1.join()
            self.load_image()
        else:
            self.load_image()
    
    def gimmick(self):
        import interactive_gui
        interactive_gui.gimmick_initialize(self, "file://"+self.image_file.replace(".png",".html"))

    def load_image(self):
        import webbrowser
        webbrowser.open(self.image_file)
    
    def map_select(self, *args):
        print(self.option)
        print(self.to_ip, self.from_ip)
        self.generate_graph()

    def browse_directory(self, option):
        if option == 'pcap':
            self.filename = self.pcap_file.replace(".pcap","")
            if "/" in self.filename:
                self.filename = self.filename.split("/")[-1]
            print(self.filename)
            print(self.pcap_file)
        else:
            if self.destination_report:
                if not os.access(self.destination_report, os.W_OK):
                   print("Error","Permission denied to create report! Run with higher privilege.")
            else:
                print("Error", "Enter a output directory!")


def main():
    pcapXrayCLI()
main()