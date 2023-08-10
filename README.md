# AdvancePcapXray

This AdvancePcapXray tool is a modified version of https://github.com/Srinivas11789/PcapXray

## Basic Details

The modifications done here are:
1. Automated analysis
2. ISP details of an IP in the interactive graph report
3. Colour coding of the malicious actors, data will be collected from [abuseipdb](https://www.abuseipdb.com) API
4. Fully command line based
5. Live analysis of Zeek-generated Pcap file

## Installation procedure
1. Initially clone the GitHub repository
```
git clone https://github.com/ramz-021002/AdvancePcapXray.git
```
2. Install a few requirements
```
sudo apt install python3-pip sudo apt install python3-tk sudo apt install graphviz sudo apt install python3-pil python3-pil.imagetk
````
3. Install other requirements using pip from the requirements.txt
```
sudo pip3 install -r requirements.txt
```
4. In the file plot_lan_network.py 
  a. Add your API key of [abuseipdb](https://www.abuseipdb.com)
  b. In the main definition add the path you have cloned the repository
5. In user_interface.py add the path you have cloned the repository
6. If Zeek is not present in the machine install Zeek
7. Once Zeek is successfully installed set the directory using the following command
```
cd <your-path>/AdvancePcapXray/zeek
```
8. Run capture.sh file (modify the command as per your machine)
```
./capture.sh
```
9. You can observe a file will be created with the current date, with pcap and other log files.
10. Now open a new terminal window and set the directory as follows
```
cd <your-path>/AdvancePcapXray
```
11. Run main.sh with sudo access (modify the command as per machine)
```
sudo ./main.sh
```
12. Once the analysis of an iteration is done you can see the report file generated in the Report file inside the Module file.
13. You can view the interactive graph and look over the ISP details of every IP node present

##Zeek Installation Procedure
1. Update and Upgrade the ubuntu machine
```
sudo apt-get update
sudo apt-get upgrade
```
2.  Install the dependencies
```
sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev swig zlib1g-dev
```
3. Go to [zeek](https://zeek.org/get-zeek/) website and download source file of zeek.
4.  Change the directory to the downloaded folder, and run uncompress the file
```
tar -xzf zeek-<version>.tar.gz
```
5. Change the directory to the Zeek folder and run
```
./configure
```
7.  Now run make and then sudo make install
```
make
sudo make install
```
8.  Once the above commands are done executing now edit to bashrc using
```
nano ~/.bashrc
```
10. Add the path using
```
export PATH=/usr/local/zeek/bin:$PATH
```
11. Run the source command and check the zeek path and zeek version
```
source ~./bashrc
which zeek
zeek --version
```
12. Change the directory to /usr/local/zeek/etc folder and check your interface name using ifconfig
```
cd /usr/local/zeek/etc
```
```
ifconfig
```
13. Change the interface to the system assigned interface in the node.cfg
```
nano node.cfg
```
14. Now change directory to bin file and check the zeekctl
```
cd ..
cd bin
sudo ./zeekctl check
```
15. Once you get zeek scripts are ok as output deploy zeekctl
```
sudo ./zeekctl deploy
```
16. To check the status of zeek
```
sudo ./zeekctl status
``` 
