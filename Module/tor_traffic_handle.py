import memory
from stem.descriptor import remote
class torTrafficHandle():

    def __init__(self):
        if not memory.tor_nodes:
            self.get_consensus_data()

    def get_consensus_data(self):
        try:
            for desc in remote.get_consensus().run():
                memory.tor_nodes.append((desc.address, desc.or_port))
        except Exception as exc:
            print("Unable to retrieve the consensus: %s" % exc)

    def tor_traffic_detection(self):
        if memory.tor_nodes:
            for session in memory.packet_db:
                current_session = session.split("/")
                if current_session[2].isdigit() and (current_session[1], int(current_session[2])) in memory.tor_nodes:
                    memory.possible_tor_traffic.append(session)

def main():
     import pcap_reader
     pcap_reader.PcapEngine('examples/torExample.pcap', "scapy")
     tor = torTrafficHandle()
     print(memory.tor_nodes)
     tor.tor_traffic_detection()
     print(memory.possible_tor_traffic)






