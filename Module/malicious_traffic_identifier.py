import memory
import communication_details_fetch
import os, json, sys

class maliciousTrafficIdentifier:

    def __init__(self):
        for session in memory.packet_db:
            src, dst, port = session.split("/")
            if port.isdigit() and self.malicious_traffic_detection(src, dst, int(port)) == 1:
                memory.possible_mal_traffic.append(session)

    def malicious_traffic_detection(self, src, dst, port):
        very_well_known_ports = [443] # used to differentiate possible mal vs serious mal
        well_known_ports = [20, 21, 22, 23, 25, 53, 69, 80, 161, 179, 389, 443]
        if not communication_details_fetch.trafficDetailsFetch.is_multicast(src) and not communication_details_fetch.trafficDetailsFetch.is_multicast(dst):
            if (dst in memory.destination_hosts and memory.destination_hosts[dst]["domain_name"] == "NotResolvable") or port > 1024:
                return 1
        return 0

    @staticmethod
    def covert_traffic_detection(packet):
        tunnelled_protocols = ["DNS", "HTTP"]

        if "ICMP" in packet:
            if "TCP in ICMP" in packet or "UDP in ICMP" in packet or "DNS" in packet:
                return 1
            elif "padding" in packet:
                return 1
            elif filter(lambda x: x in str(packet["ICMP"].payload), tunnelled_protocols):
                return 1
        elif "DNS" in packet:
            try:
                if communication_details_fetch.trafficDetailsFetch.dns(packet["DNS"].qd.qname.strip()) == "NotResolvable":
                    return 1
                elif len(filter(str.isdigit, str(packet["DNS"].qd.qname).strip())) > 8:
                    return 1
            except:
                pass
        return 0
    
    @staticmethod
    def covert_payload_prediction(payload):
        try:
            if memory.signatures == {}:
                memory.signatures = json.load(open(sys.path[0]+"/magic_numbers.txt"))
            matches = []
            # Fetch payload from Packet in hex format
            string_payload = str(payload)
            try:
                payload = bytes(payload).hex()
            except:
                payload = str(payload)
            try:
                for file_type in memory.signatures.keys():
                    for sign in memory.signatures[file_type]["signs"]:
                        offset, magic = sign.split(",")
                        magic = magic.strip()
                        #print(magic, file_type)
                        #print(magic, string_payload, file_type)
                        if magic.lower() in payload or magic in string_payload:
                            matches.append(file_type)
            except:
                pass
            return matches
        except:
            print("File signature analysis failed!")
            return []

def main():
    import pcap_reader
    cap = pcap_reader.PcapEngine('examples/torExample.pcap', "scapy")
    maliciousTrafficIdentifier()
    print(memory.possible_mal_traffic)


