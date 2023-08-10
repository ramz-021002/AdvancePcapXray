#File Import
import communication_details_fetch
import tor_traffic_handle
import malicious_traffic_identifier
import memory
import requests


from graphviz import Digraph
import os

from pyvis.network import Network

class plotLan:

    def __init__(self, filename, path, option="All", to_ip="All", from_ip="All"):
        import datetime
        current_date = datetime.date.today()
        
        self.directory = os.path.join(path, "Report")
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        options = str(option) + "_" + to_ip.replace(".", "-") + "_" + from_ip.replace(".", "-")
        self.filename = os.path.join(self.directory, f"Report_{current_date}/index")

        self.styles = {
            'graph': {
                'label': 'PcapGraph',
                'fontsize': '16',
                'fontcolor': 'black',
                'bgcolor': 'grey',
                'rankdir': 'LR', # BT
                'dpi':'300',
                'size': '50, 50',
                'overlap': 'scale'
            },
            'nodes': {
                'fontname': 'Helvetica',
                'shape': 'circle',
                'fontcolor': 'black',
                'color': ' black',
                'style': 'filled',
                'fillcolor': 'yellow',
                'fixedsize': 'true',
                'width': '3',
                'height': '3'
            }
        }

        self.sessions = memory.packet_db.keys()
        #device_details_fetch.fetchDeviceDetails("ieee").fetch_info()
        if str(option) == "Malicious" or str(option) == "All":
            self.mal_identify = malicious_traffic_identifier.maliciousTrafficIdentifier()
        if str(option) == "Tor" or str(option) == "All":
            self.tor_identify = tor_traffic_handle.torTrafficHandle().tor_traffic_detection()
        self.draw_graph(str(option), to_ip, from_ip)
    
    def apply_styles(self, graph, styles):
        graph.graph_attr.update(
            ('graph' in styles and styles['graph']) or {}
        )
        graph.node_attr.update(
            ('nodes' in styles and styles['nodes']) or {}
        )
        return graph

    def apply_custom_style(self, graph, color):
        style = {'edges': {
                'style': 'dashed',
                'color': color,
                'arrowhead': 'open',
                'fontname': 'Courier',
                'fontsize': '12',
                'fontcolor': color,
        }}
        graph.edge_attr.update(
            ('edges' in style and style['edges']) or {}
        )
        return graph
    

    def draw_graph(self, option="All", to_ip="All", from_ip="All"):
        f = Digraph('network_diagram - '+str(option), filename=self.filename, engine="dot", format="png")
        f.attr(rankdir='LR', size='8,5')
        if len(memory.lan_hosts) > 40:
            f = Digraph('network_diagram - '+str(option), filename=self.filename, engine="sfdp", format="png")
        elif len(memory.lan_hosts) > 20:
            f = Digraph('network_diagram - '+str(option), filename=self.filename, engine="circo", format="png")
        else:
            f = Digraph('network_diagram - '+str(option), filename=self.filename, engine="dot", format="png")
        
        interactive_graph = Network(directed=True, height="750px", width="100%", bgcolor="#222222", font_color="white")
        interactive_graph.barnes_hut()
        vis_nodes = []
        vis_edges = []

        f.attr('node', shape='doublecircle')
        #f.node('defaultGateway')

        f.attr('node', shape='circle')

        print("Starting Graph Plotting")
        edge_present = False

        mal, tor, http, https, icmp, dns, clear_text, unknown, covert = 0, 0, 0, 0, 0, 0, 0, 0, 0
        def get_isp_details(ip_address):
            try:
                import ipaddress
                public_ip = get_public_ip(ip_address)
                if public_ip == '':
                    return '\n'
                ip_obj = ipaddress.ip_address(public_ip)
                if ip_obj.is_multicast:
                    return 'Multicast via RFC 317'
                else:
                    from ipwhois import IPWhois
                    public_ip = public_ip.strip()
                    obj = IPWhois(public_ip)
                    res = obj.lookup_rdap()
                    return res['asn_description']
            except:
                return 'Multicast or not possible'
                    
        def get_public_ip(address):
            parts = address.split("\n")
            ip_address = parts[0]

            ip_parts = ip_address.split('.')

            if ((ip_parts[0] == '10') or \
            (ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31) or \
            ip_parts[0] == '192' and ip_parts[1] == '168'):
                response = requests.get('https://api.ipify.org')
                return response.text
            else:
                return ip_address
            

        
        def check_ip_malicious(address):
            parts = address.split("\n")
            ip_address = parts[0]
            ip = get_public_ip(ip_address)
            API_KEY = "<REPLACE WITH YOUR API KEY>" #API key of abuseipdp must be placed
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            headers = {
                "Key": API_KEY,
                "Accept": "application/json"
            }

            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if "data" in data and "abuseConfidenceScore" in data["data"]:
                    abuse_score = data["data"]["abuseConfidenceScore"]
                    if abuse_score > 0:
                        return 'Malicious'
                    else:
                        return 'Not Malicious'
                else:
                    return '1'
            else:
                return '2'
            
                    

        
        if str(option) == "All":
            # add nodes
            for session in self.sessions:
                src, dst, port = session.split("/")

                #print(from_ip, to_ip, src, dst)
                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst
                    
                    # Lan Host
                    if memory.packet_db[session]["Ethernet"]["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session]["Ethernet"]["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["src"]]["node"]
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if "mac" in memory.destination_hosts[dst] and memory.destination_hosts[dst]["mac"] in memory.lan_hosts and "node" in memory.lan_hosts[memory.destination_hosts[dst]["mac"]]:
                            destination = memory.lan_hosts[memory.destination_hosts[dst]["mac"]]["node"]
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                        else:
                            destination = memory.destination_hosts[dst]["mac"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                    else:
                        if memory.packet_db[session]["Ethernet"]["dst"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["dst"]]["node"]
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session]["Ethernet"]["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""
                    
                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        status = check_ip_malicious(destination)
                        if status == 'Malicious':
                            NodeColour = 'red'
                        else:
                            NodeColour = 'blue'
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)
                    except Exception as e:
                        print("Interactive graph error occurred: "+str(e))

                    # if vis_nodes(curr_node, curr_node, title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow") not in vis_nodes:
                    #     vis_nodes.append(curr_node, curr_node, title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                    # if vis_nodes(destination, destination, title=str(destination+"\n"+get_isp_details(curr_node)), color="yellow") not in vis_nodes:
                    #     vis_nodes.append(destination, destination, title=str(destination+"\n"+get_isp_details(curr_node)), color="yellow")

                    if curr_node != destination:
                        if session in memory.possible_tor_traffic:
                            f.edge(curr_node, destination, label='TOR: ' + str(map_dst) ,color="white")
                            tor += 1
                            if curr_node not in interactive_graph.get_nodes():
                                interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                            if destination not in interactive_graph.get_nodes():
                                status = check_ip_malicious(destination)
                                if status == 'Malicious':
                                    NodeColour = 'red'
                                else:
                                    NodeColour = 'blue'
                                interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)
                                
                            interactive_graph.add_edge(curr_node, destination, color="white", title='TOR: ' + str(map_dst), smooth={"type": "curvedCW", "roundness": tor/9})
                            #if edge not in vis_edges:toor
                            #    vis_edges.append(edge)
                            if edge_present == False:
                                edge_present = True
                        elif memory.packet_db[session]["covert"]:
                            if port == "53":
                                protocol = "DNS"
                            else:
                                protocol = port
                            f.edge(curr_node, destination, label='Covert/'+ protocol + ': ' + str(map_dst) +": "+str(dlabel), color = "cyan")
                            covert += 1

                            if curr_node not in interactive_graph.get_nodes():
                                interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                            if destination not in interactive_graph.get_nodes():
                                status = check_ip_malicious(destination)
                                if status == 'Malicious':
                                    NodeColour = 'red'
                                else:
                                    NodeColour = 'blue'
                                interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                            interactive_graph.add_edge(curr_node, destination, color="cyan", title='Covert: ' + str(map_dst) +": "+dlabel, smooth={"type": "curvedCCW", "roundness": covert/12})
                            if edge_present == False:
                                edge_present = True
                        else:
                            if port == "443":
                                f.edge(curr_node, destination, label='HTTPS: ' + str(map_dst) +": "+str(dlabel), color = "blue")
                                https += 1

                                if curr_node not in interactive_graph.get_nodes():
                                    interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                                if destination not in interactive_graph.get_nodes():
                                    status = check_ip_malicious(destination)
                                    if status == 'Malicious':
                                        NodeColour = 'red'
                                    else:
                                        NodeColour = 'blue'
                                    interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                                interactive_graph.add_edge(curr_node, destination, color="blue", title='HTTPS: ' + str(map_dst) +": "+ dlabel, smooth={"type": "curvedCCW", "roundness": https/10})
                                #if edge not in vis_edges:
                                #    vis_edges.append(edge)
                                if edge_present == False:
                                    edge_present = True
                            elif port == "80":
                                f.edge(curr_node, destination, label='HTTP: ' + str(map_dst) +": "+str(dlabel), color = "green")
                                http += 1
                                if curr_node not in interactive_graph.get_nodes():
                                    interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                                if destination not in interactive_graph.get_nodes():
                                    status = check_ip_malicious(destination)
                                    if status == 'Malicious':
                                        NodeColour = 'red'
                                    else:
                                        NodeColour = 'blue'
                                    interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                                interactive_graph.add_edge(curr_node, destination, color="green", title='HTTP: ' + str(map_dst) +": "+dlabel, smooth={"type": "curvedCW", "roundness": http/12})
                                #if edge not in vis_edges:
                                #    vis_edges.append(edge)
                                if edge_present == False:
                                    edge_present = True
                            elif port == "ICMP":
                                f.edge(curr_node, destination, label='ICMP: ' + str(map_dst) ,color="black")
                                icmp += 1
                                if curr_node not in interactive_graph.get_nodes():
                                    interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                                if destination not in interactive_graph.get_nodes():
                                    status = check_ip_malicious(destination)
                                    if status == 'Malicious':
                                        NodeColour = 'red'
                                    else:
                                        NodeColour = 'blue'
                                    interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                                interactive_graph.add_edge(curr_node, destination, color="purple", title='ICMP: ' + str(map_dst), smooth={"type": "curvedCCW", "roundness": icmp/6})
                                #if edge not in vis_edges:
                                #    vis_edges.append(edge)
                                if edge_present == False:
                                    edge_present = True
                            elif port == "53":
                                f.edge(curr_node, destination, label='DNS: ' + str(map_dst) ,color="orange")
                                dns += 1
                                if curr_node not in interactive_graph.get_nodes():
                                    interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                                if destination not in interactive_graph.get_nodes():
                                    status = check_ip_malicious(destination)
                                    if status == 'Malicious':
                                        NodeColour = 'red'
                                    else:
                                        NodeColour = 'blue'
                                    interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                                interactive_graph.add_edge(curr_node, destination, color="pink", title='DNS: ' + str(map_dst), smooth={"type": "curvedCW", "roundness": dns/5})
                                #if edge not in vis_edges:
                                #    vis_edges.append(edge)
                                if edge_present == False:
                                    edge_present = True
                            elif int(port) in [20, 21, 23, 25, 110, 143, 139, 69, 161, 162, 1521]:
                                f.edge(curr_node, destination, label='ClearTextProtocol/'+ port +': ' +  str(map_dst) ,color="violet")
                                clear_text += 1
                                if curr_node not in interactive_graph.get_nodes():
                                    interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                                if destination not in interactive_graph.get_nodes():
                                    status = check_ip_malicious(destination)
                                    if status == 'Malicious':
                                        NodeColour = 'red'
                                    else:
                                        NodeColour = 'blue'
                                    interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                                interactive_graph.add_edge(curr_node, destination, color="#9A2EFE", title='ClearTextProtocol/'+ port +': ' + str(map_dst), smooth={"type": "curvedCW", "roundness": clear_text/4})
                                if edge_present == False:
                                    edge_present = True
                            else:
                                f.edge(curr_node, destination, label='UnknownProtocol/'+ port +': ' + str(map_dst) ,color="brown")
                                unknown += 1
                                if curr_node not in interactive_graph.get_nodes():
                                    interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                                if destination not in interactive_graph.get_nodes():
                                    status = check_ip_malicious(destination)
                                    if status == 'Malicious':
                                        NodeColour = 'red'
                                    else:
                                        NodeColour = 'blue'
                                    interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                                interactive_graph.add_edge(curr_node, destination, color="brown", title='UnknownProtocol/' + port + ': ' + str(map_dst), smooth={"type": "curvedCW", "roundness": unknown/3})
                                if edge_present == False:
                                    edge_present = True
                    else:
                        # This block was just added to handle MAC SPOOF scenario
                        # * Most of the CTF Challenges have fake identical MACs that need to be displayed
                        if map_src in curr_node:
                            other_node = map_dst + "\n" + memory.packet_db[session]["Ethernet"]["dst"].replace(":",".")
                        else:
                            other_node = map_src + "\n" + memory.packet_db[session]["Ethernet"]["src"].replace(":",".")
                        f.node(other_node)
                        interactive_graph.add_node(str(other_node), str(other_node), title=str(other_node+"\n"+get_isp_details(other_node)), color="yellow")
                        f.edge(curr_node, other_node, label='WeirdTraffic/'+ port ,color="pink")
                        unknown += 1
                        if curr_node not in interactive_graph.get_nodes():
                            interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                        if destination not in interactive_graph.get_nodes():
                            status = check_ip_malicious(destination)
                            if status == 'Malicious':
                                NodeColour = 'red'
                            else:
                                NodeColour = 'blue'
                            interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                        interactive_graph.add_edge(curr_node, other_node, color="pink", title='WeirdTraffic/' + port, smooth={"type": "curvedCW", "roundness": unknown/3})
                        if edge_present == False:
                            edge_present = True    

        elif str(option) == "HTTP":
            for session in self.sessions:
                src, dst, port = session.split("/")

                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session]["Ethernet"]["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session]["Ethernet"]["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["src"]]["node"]
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst]["mac"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.destination_hosts[dst]["mac"]]["node"]
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                        else:
                            destination = memory.destination_hosts[dst]["mac"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                    else:
                        if memory.packet_db[session]["Ethernet"]["dst"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["dst"]]["node"]
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session]["Ethernet"]["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""
                    
                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        status = check_ip_malicious(destination)
                        if status == 'Malicious':
                            NodeColour = 'red'
                        else:
                            NodeColour = 'blue'
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)
                    except Exception as e:
                        print("Interactive graph error occurred: "+str(e))

                    if port == "80" and curr_node != destination:
                        f.edge(curr_node, destination, label='HTTP: ' + str(map_dst)+": "+dlabel, color = "green")
                        http += 1
                        if curr_node not in interactive_graph.get_nodes():
                            interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                        if destination not in interactive_graph.get_nodes():
                            status = check_ip_malicious(destination)
                            if status == 'Malicious':
                                NodeColour = 'red'
                            else:
                                NodeColour = 'blue'
                            interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                        interactive_graph.add_edge(curr_node, destination, color="green", smooth={"type": "curvedCW", "roundness": http/10})
                        if edge_present == False:
                            edge_present = True

        elif str(option) == "HTTPS":
            for session in self.sessions:
                src, dst, port = session.split("/")
                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session]["Ethernet"]["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session]["Ethernet"]["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["src"]]["node"]
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst]["mac"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.destination_hosts[dst]["mac"]]["node"]
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                        else:
                            destination = memory.destination_hosts[dst]["mac"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                    else:
                        if memory.packet_db[session]["Ethernet"]["dst"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["dst"]]["node"]
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session]["Ethernet"]["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""
                    
                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        status = check_ip_malicious(destination)
                        if status == 'Malicious':
                            NodeColour = 'red'
                        else:
                            NodeColour = 'blue'
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)
                    except Exception as e:
                        print("Interactive graph error occurred: "+str(e))

                    if port == "443" and curr_node != destination:
                        f.edge(curr_node, destination, label='HTTPS: ' + str(map_dst)+": "+dlabel, color = "blue")
                        https += 1
                        if curr_node not in interactive_graph.get_nodes():
                            interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                        if destination not in interactive_graph.get_nodes():
                            status = check_ip_malicious(destination)
                            if status == 'Malicious':
                                NodeColour = 'red'
                            else:
                                NodeColour = 'blue'
                            interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                        interactive_graph.add_edge(curr_node, destination, color="blue", smooth={"type": "curvedCCW", "roundness": https/10})
                        if edge_present == False:
                            edge_present = True

        elif str(option) == "Tor":
            for session in self.sessions:
                src, dst, port = session.split("/")
                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session]["Ethernet"]["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session]["Ethernet"]["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["src"]]["node"]
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst]["mac"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.destination_hosts[dst]["mac"]]["node"]
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                        else:
                            destination = memory.destination_hosts[dst]["mac"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                    else:
                        if memory.packet_db[session]["Ethernet"]["dst"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["dst"]]["node"]
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session]["Ethernet"]["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""

                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        status = check_ip_malicious(destination)
                        if status == 'Malicious':
                            NodeColour = 'red'
                        else:
                            NodeColour = 'blue'
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)
                    except Exception as e:
                        print("Interactive graph error occurred: "+str(e))

                    if session in memory.possible_tor_traffic and curr_node != destination:
                        f.edge(curr_node, destination, label='TOR: ' + str(map_dst) ,color="white")
                        tor += 1
                        if curr_node not in interactive_graph.get_nodes():
                            interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                        if destination not in interactive_graph.get_nodes():
                            status = check_ip_malicious(destination)
                            if status == 'Malicious':
                                NodeColour = 'red'
                            else:
                                NodeColour = 'blue'
                            interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                        interactive_graph.add_edge(curr_node, destination, color="white", smooth={"type": "curvedCW", "roundness": tor/10})
                        if edge_present == False:
                            edge_present = True

        elif str(option) == "Malicious":
            # TODO: would we need to iterate over and over all the session irrespective of the properties
            for session in self.sessions:
                src, dst, port = session.split("/")

                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    # TODO: Improvise this logic below
                    # * graphviz graph is not very good with the ":" in strings
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session]["Ethernet"]["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session]["Ethernet"]["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["src"]]["node"]
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst]["mac"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.destination_hosts[dst]["mac"]]["node"]
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                        else:
                            destination = memory.destination_hosts[dst]["mac"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                    else:
                        if memory.packet_db[session]["Ethernet"]["dst"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["dst"]]["node"]
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session]["Ethernet"]["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""

                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        status = check_ip_malicious(destination)
                        if status == 'Malicious':
                            NodeColour = 'red'
                        else:
                            NodeColour = 'blue'
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)
                    except Exception as e:
                        print("Interactive graph error occurred: "+str(e))

                    if session in memory.possible_mal_traffic and curr_node != destination:
                        f.edge(curr_node, destination, label='Malicious: ' + str(map_dst) ,color="red")
                        mal += 1
                        if curr_node not in interactive_graph.get_nodes():
                            interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                        if destination not in interactive_graph.get_nodes():
                            status = check_ip_malicious(destination)
                            if status == 'Malicious':
                                NodeColour = 'red'
                            else:
                                NodeColour = 'blue'
                            interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                        interactive_graph.add_edge(curr_node, destination, color="red", smooth={"type": "curvedCW", "roundness": mal/10})                 
                        if edge_present == False:
                            edge_present = True
            
        elif str(option) == "ICMP":
            for session in self.sessions:
                src, dst, protocol = session.split("/")

                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session]["Ethernet"]["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session]["Ethernet"]["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["src"]]["node"]
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst]["mac"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.destination_hosts[dst]["mac"]]["node"]
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                        else:
                            destination = memory.destination_hosts[dst]["mac"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                    else:
                        if memory.packet_db[session]["Ethernet"]["dst"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["dst"]]["node"]
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session]["Ethernet"]["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""

                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        status = check_ip_malicious(destination)
                        if status == 'Malicious':
                            NodeColour = 'red'
                        else:
                            NodeColour = 'blue'
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)
                    except Exception as e:
                        print("Interactive graph error occurred: "+str(e))

                    if protocol == "ICMP" and curr_node != destination:
                        f.edge(curr_node, destination, label='ICMP: ' + str(map_dst) ,color="black")
                        icmp += 1
                        if curr_node not in interactive_graph.get_nodes():
                            interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                        if destination not in interactive_graph.get_nodes():
                            status = check_ip_malicious(destination)
                            if status == 'Malicious':
                                NodeColour = 'red'
                            else:
                                NodeColour = 'blue'
                            interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                        interactive_graph.add_edge(curr_node, destination, color="purple", smooth={"type": "curvedCCW", "roundness": icmp/10})        
                        if edge_present == False:
                            edge_present = True
    
        elif str(option) == "DNS":
            for session in self.sessions:
                src, dst, port = session.split("/")
                if (src == from_ip and dst == to_ip) or \
                    (from_ip == "All" and to_ip == "All") or \
                        (to_ip == "All" and from_ip == src) or \
                            (to_ip == dst and from_ip == "All"):
                    if ":" in src:
                        map_src = src.replace(":",".")
                    else:
                        map_src = src
                    if ":" in dst:
                        map_dst = dst.replace(":", ".")
                    else:
                        map_dst = dst

                    # Lan Host
                    if memory.packet_db[session]["Ethernet"]["src"] not in memory.lan_hosts:
                        curr_node = map_src+"\n"+memory.packet_db[session]["Ethernet"]["src"].replace(":",".")
                        f.node(curr_node)
                    else:
                        curr_node = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["src"]]["node"]
                        f.node(curr_node)

                    # Destination
                    if dst in memory.destination_hosts:
                        if memory.destination_hosts[dst]["mac"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.destination_hosts[dst]["mac"]]["node"]
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                        else:
                            destination = memory.destination_hosts[dst]["mac"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = memory.destination_hosts[dst]["domain_name"]
                    else:
                        if memory.packet_db[session]["Ethernet"]["dst"] in memory.lan_hosts:
                            destination = memory.lan_hosts[memory.packet_db[session]["Ethernet"]["dst"]]["node"]
                            dlabel = ""
                        else:
                            destination = memory.packet_db[session]["Ethernet"]["dst"].replace(":",".")
                            destination += "\n"+"PossibleGateway"
                            dlabel = ""

                    # Interactive Graph on Beta, so for now add safety checks ( potential failures in python2)
                    try:
                        status = check_ip_malicious(destination)
                        if status == 'Malicious':
                            NodeColour = 'red'
                        else:
                            NodeColour = 'blue'
                        interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")
                        interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)
                    except Exception as e:
                        print("Interactive graph error occurred: "+str(e))

                    if port == "53" and curr_node != destination:
                        f.edge(curr_node, destination, label='DNS: ' + str(map_dst) ,color="orange")
                        dns += 1
                        if curr_node not in interactive_graph.get_nodes():
                            interactive_graph.add_node(str(curr_node), str(curr_node), title=str(curr_node+"\n"+get_isp_details(curr_node)), color="yellow")

                        if destination not in interactive_graph.get_nodes():
                            status = check_ip_malicious(destination)
                            if status == 'Malicious':
                                NodeColour = 'red'
                            else:
                                NodeColour = 'blue'
                            interactive_graph.add_node(str(destination), str(destination), title=str(destination+"\n"+get_isp_details(destination)+"\n"+status), color= NodeColour)

                        interactive_graph.add_edge(curr_node, destination, color="pink", smooth={"type": "curvedCW", "roundness": dns/10})        
                        if edge_present == False:
                            edge_present = True

        if edge_present == False:
            f.attr(label="No "+str(option)+" Traffic between nodes!",engine='circo', size="5, 5", dpi="300")

        self.apply_styles(f,self.styles)
            
        f.render()
        interactive_graph.save_graph(self.filename+".html")
        f.clear()

                
def main():
    # draw example
    import datetime
    current_date = datetime.date.today()
    import pcap_reader
    pcapfile = pcap_reader.PcapEngine(f'<Set the Directory>/AdvancePcapXray/zeek/packets_{current_date}/capture.pcap', "scapy")
    details = communication_details_fetch.trafficDetailsFetch("sock")
    import sys
    print(sys.path[0])
    network = plotLan("test", sys.path[0])
    #pcap_reader.clear_memory()

main()
