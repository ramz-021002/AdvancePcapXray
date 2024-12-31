import os 
import sys 
import datetime
import time

if sys.platform == 'darwin':
    import matplotlib
    matplotlib.use('TkAgg')

interactive_graph_support = False
try:
    from cefpython3 import cefpython as cef
    interactive_graph_support = True
except:
    print("Interactive graph in app wont work as python version/platform is not supported (will launch in default browser)")
    pass

if sys.path[0]:
    sys.path.insert(0,sys.path[0]+'/Module/')
else:
    sys.path.insert(0, 'Module/')

import user_interface
import art

# Import 3rd party Libraries -- Needed to be installed using pip
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

def main():
    print(art.Logo)
    user_interface.pcapXrayCLI()
    import pcap_reader
    
main()

    
