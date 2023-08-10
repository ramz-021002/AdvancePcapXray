import logging
import sys
import memory
from netaddr import IPAddress
import threading
import base64
import malicious_traffic_identifier
import communication_details_fetch

tls_view_feature = False

class PcapEngine():
    def __init__(self, pcap_file_name, pcap_parser_engine="scapy"):
            memory.packet_db = {}
            memory.lan_hosts = {}
            memory.destination_hosts = {}
            memory.possible_mal_traffic = []
            memory.possible_tor_traffic = []

            self.engine = pcap_file_name


            if pcap_parser_engine == "scapy":
                try:
                    from scapy.all import rdpcap
                except:
                    logging.error("Cannot import selected pcap engine: Scapy!")
                    sys.exit()

                try:
                    from scapy.all import load_layer
                    global tls_view_feature
                    tls_view_feature = True
                    logging.info("tls view feature enabled")
                except:
                    logging.info("tls view feature not enabled")

                if tls_view_feature:
                    load_layer("tls")

                logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
                self.packets = rdpcap(pcap_file_name)
            
            elif pcap_parser_engine == "pyshark":
                try:
                    import pyshark
                except:
                    logging.error("Cannot import selected pcap engine: PyShark!")
                    sys.exit()
                
                self.packets = pyshark.FileCapture(pcap_file_name, include_raw=True, use_json=True)

            self.analyse_packet_data()

    def analyse_packet_data(self):
        for packet in self.packets:
            source_private_ip = None

            if "IPv6" in packet or "IPV6" in packet:
                if self.engine == "scapy":
                    IP = "IPv6"
                else:
                    IP = "IPv4"
            
                try:
                    private_source = IPAddress(packet[IP].src).is_private()
                except:
                    private_source = None
                
                try:
                    private_destination = IPAddress(packet[IP].dst).is_private()
                except:
                    private_destination = None

            elif "IP" in packet:
                IP = "IP"
                private_source = IPAddress(packet[IP].src).is_private()
                private_destination = IPAddress(packet[IP].dst).is_private()
            
            if "TCP" in packet or "UDP" in packet:
                if self.engine == "pyshark":
                    eth_layer = "ETH"
                    tcp_src = str(
                        packet["TCP"].srcport if "TCP" in packet else packet["UDP"].srcport)
                    tcp_dst = str(
                        packet["TCP"].dstport if "TCP" in packet else packet["UDP"].dstport)
                else:
                    eth_layer = "Ether"
                    tcp_src = str(
                        packet["TCP"].sport if "TCP" in packet else packet["UDP"].sport)
                    tcp_dst = str(
                        packet["TCP"].dport if "TCP" in packet else packet["UDP"].dport)
                
            
                if private_source and private_destination:
                    key1 = packet[IP].src + "/" + packet[IP].dst + "/" + tcp_dst
                    key2 = packet[IP].dst + "/" + packet[IP].src + "/" + tcp_src

                    if key2 in memory.packet_db:
                        source_private_ip = key2
                    else:
                        source_private_ip = key1
                    
                    if eth_layer in packet:
                        lan_key_src = packet[eth_layer].src
                        lan_key_dst = packet[eth_layer].dst
                        if lan_key_src not in memory.lan_hosts:
                            memory.lan_hosts[lan_key_src] = {"ip": packet[IP].src}
                        if lan_key_dst not in memory.lan_hosts:
                            memory.lan_hosts[lan_key_dst] = {"ip": packet[IP].dst}

                elif private_source:
                    key = packet[IP].src + "/" + packet[IP].dst + "/" + tcp_dst
                    source_private_ip = key

                    if eth_layer in packet:
                        lan_key_src = packet[eth_layer].src
                        if lan_key_src not in memory.lan_hosts:
                            memory.lan_hosts[lan_key_src] = {"ip": packet[IP].src}
                        if packet[IP].dst not in memory.destination_hosts:
                            memory.destination_hosts[packet[IP].dst] = {"mac": packet[IP].dst}
                        
                elif private_destination:
                    key = packet[IP].dst + "/" + packet[IP].src + "/" + tcp_src
                    source_private_ip = key
                
                    if eth_layer in packet:
                        lan_key_dst = packet[eth_layer].dst
                        if lan_key_dst not in memory.lan_hosts:
                            memory.lan_hosts[lan_key_dst] = {"ip": packet[IP].dst}
                        if packet[IP].src not in memory.destination_hosts:
                            memory.destination_hosts[packet[IP].src] = {"mac": packet[IP].src}
                    
                else:
                    if IP in packet:
                        key1 = packet[IP].src + "/" + packet[IP].dst + "/" + tcp_dst
                        key2 = packet[IP].dst + "/" + packet[IP].src + "/" + tcp_src

                    # if key2 in memory.packet_db:
                    #     source_private_ip = key2
                    # else:
                    #     source_private_ip = key1

                    if eth_layer in packet:
                        if IP in packet:
                            if packet[IP].src not in memory.destination_hosts:
                                memory.destination_hosts[packet[IP].src] = {"mac": packet[IP].src}
                            if packet[IP].dst not in memory.destination_hosts:
                                memory.destination_hosts[packet[IP].dst] = {"mac": packet[IP].dst}

            elif "ICMP" in packet:

                    # Key creation similar to both private interface condition
                    key1 = packet[IP].src + "/" + packet[IP].dst + "/" + "ICMP"
                    key2 = packet[IP].dst + "/" + packet[IP].src + "/" + "ICMP"

                    # First come first serve
                    if key2 in memory.packet_db:
                        source_private_ip = key2
                    else:
                        source_private_ip = key1
                    
            if source_private_ip:
                if source_private_ip not in memory.packet_db:
                    memory.packet_db[source_private_ip] = {}

                        # Ethernet Layer ( Mac address )
                if "Ethernet" not in memory.packet_db[source_private_ip]:
                    memory.packet_db[source_private_ip]["Ethernet"] = {"src":"", "dst":""}

                        # Record Payloads 
                if "Payload" not in memory.packet_db[source_private_ip]:
                            # Record unidirectional + bidirectional separate
                    memory.packet_db[source_private_ip]["Payload"] = {"forward":[],"reverse":[]}

                        # Covert Communication Identifier
                if "covert" not in memory.packet_db[source_private_ip]:
                    memory.packet_db[source_private_ip]["covert"] = False

                        # File Signature Identifier
                if "file_signatures" not in memory.packet_db[source_private_ip]:
                    memory.packet_db[source_private_ip]["file_signatures"] = []
            
            if source_private_ip is not None:
                src, dst, port = source_private_ip.split("/")
            else:
                continue

            if source_private_ip in memory.packet_db and memory.packet_db[source_private_ip]["covert"] == False:
                if not communication_details_fetch.trafficDetailsFetch.is_multicast(src) and not communication_details_fetch.trafficDetailsFetch.is_multicast(dst):
                    if malicious_traffic_identifier.maliciousTrafficIdentifier.covert_traffic_detection(packet) == 1:
                        memory.packet_db[source_private_ip]["covert"] = True

            payload_string = ""
            if self.engine == "pyshark":
                if private_source:
                    if "ETH" in packet:
                        memory.packet_db[source_private_ip]["Ethernet"]["src"] = packet["ETH"].src
                        memory.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["ETH"].dst
                    payload = "forward"
                else:
                    if "ETH" in packet:
                        memory.packet_db[source_private_ip]["Ethernet"]["src"] = packet["ETH"].dst
                        memory.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["ETH"].src
                    payload = "reverse"    
            
                    try:
                        memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet.get_raw_packet()))
                        payload_string = packet.get_raw_packet()
                    except:
                        memory.packet_db[source_private_ip]["Payload"][payload].append("")

            elif self.engine == "scapy":
                if private_source:
                    if "Ether" in packet:
                        memory.packet_db[source_private_ip]["Ethernet"]["src"] = packet["Ether"].src
                        memory.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["Ether"].dst
                    payload = "forward"
                else:
                    if "Ether" in packet:
                        memory.packet_db[source_private_ip]["Ethernet"]["src"] = packet["Ether"].dst
                        memory.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["Ether"].src
                payload = "reverse"
                try:
                    memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet.get_raw_packet()))
                    payload_string = packet.get_raw_packet()
                except:
                     memory.packet_db[source_private_ip]["Payload"][payload].append("")
                
            elif self.engine == "scapy":
                if private_source:
                    if "Ether" in packet:
                        memory.packet_db[source_private_ip]["Ethernet"]["src"] = packet["Ether"].src
                        memory.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["Ether"].dst
                    payload = "forward"
                else:
                    if "Ether" in packet:
                        memory.packet_db[source_private_ip]["Ethernet"]["src"] = packet["Ether"].dst
                        memory.packet_db[source_private_ip]["Ethernet"]["dst"] = packet["Ether"].src
                    payload = "reverse"

                global tls_view_feature
                if "TCP" in packet:
                    if tls_view_feature:
                        if "TLS" in packet:
                            memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet["TLS"].msg))
                        elif "SSLv2" in packet:
                            memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet["SSLv2"].msg))
                        elif "SSLv3" in packet:
                            memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet["SSLv3"].msg))
                        else:
                            if "_TLSEncryptedContent" in packet["TCP"]: # handle encrypted payload
                                memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet["TCP"].payload.show(True)))
                            else:
                                memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet["TCP"].payload))
                    else:   
                        memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet["TCP"].payload.show(True)))
                    payload_string = packet["TCP"].payload
                elif "UDP" in packet:
                    memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet["UDP"].payload))
                    payload_string = packet["UDP"].payload
                elif "ICMP" in packet:
                    memory.packet_db[source_private_ip]["Payload"][payload].append(str(packet["ICMP"].payload))
                    payload_string = packet["ICMP"].payload

                if payload_string and memory.packet_db[source_private_ip]["covert"] == True:
                    file_signs = malicious_traffic_identifier.maliciousTrafficIdentifier.covert_payload_prediction(payload_string)
                    if file_signs:
                        memory.packet_db[source_private_ip]["file_signatures"].extend(file_signs)
                        memory.packet_db[source_private_ip]["file_signatures"] = list(set(memory.packet_db[source_private_ip]["file_signatures"]))