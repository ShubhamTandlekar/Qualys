import qualysapi  #basis to be able to make the requests to the Qualys API
import argparse  #used for the initial input on running the program
import re  #regex tester for the MAC addrs
import socket #for tesing IP's to see if they are actual IPs
import os  #for the scan function
import sys  #for the Ipv6 scan
import json     #used for formatting when API calls are made to access the Body
import requests     #for the elements calls 
import xmltodict    #for parsing once the scans bodyies are returned
import urllib3

#might not need
import time
import pycurl

urllib3.disable_warnings()

#put in config file
username = ''
password = ''
QUser = ""
QPass = ""
QURL = "https://qualysapi.qg2.apps.qualys.com"

#these are the port scan range for the v6 scan 
Port1 = 7510
Port2 = 7560

class Qualys_API(object):

    def __init__(self, username, password, session_url):
        self.username = username
        self.password = password
        self.login_url = f"{session_url}/api/2.0/fo/session/"
        self.req_sess = requests.session()
        self.session_ID = self.req_sess.post(self.login_url, auth={},
                                        data={'action': "login", "username": self.username, "password": self.password},
                                        timeout=10, headers={"X-Requested-With": "Curl Sample"})
        # print(self.session_ID.headers)
        # print()
        # print()

    def logout(self):
        out = self.req_sess.post(self.login_url, auth={}, data={'action': "logout"},
                                 headers={"X-Requested-With": "Curl Sample"})
        print(out.text)

    def scan(self, scan_title, ip_addr, asset_groups="Shubham - Test IP Range",
             exclude_ip_per_scan="10.10.10.10", iscanner_name="Greenville_DC", option_title="CPE Curated Port List",
             priority=4):
        scan_data = {"action": "launch",
                     "scan_title": scan_title,
                     "target_from": "assets",
                     "ip": ip_addr,
                     "asset_groups": asset_groups,
                     "exclude_ip_per_scan": exclude_ip_per_scan,
                     "iscanner_name": iscanner_name,
                     "option_title": option_title,
                     "priority": priority
                     }
        response_output = self.req_sess.post("https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/scan/", data=scan_data,
                                             headers={"X-Requested-With": "Curl Sample"})
        response_output = xmltodict.parse(response_output.text)
        output_dict = {}
                
        for value in response_output['SIMPLE_RETURN']['RESPONSE']['ITEM_LIST']['ITEM']: #when entering a sinlgle IPv4 this dict does not exist!!
            for index, data in value.items():
                if index == "KEY":
                    key = data
                else:
                    dict_data = data
            output_dict[key] = dict_data
        return output_dict

    def download_results(self, scan_reference):
        scan_data = {"action": "fetch",
                     "echo_request": 1,
                     "output_format": "csv",
                     "scan_ref": scan_reference
        }
        response_output = self.req_sess.post("https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/scan/", data=scan_data,
                                             headers={"X-Requested-With": "Curl Sample"})
        return response_output


class ElementsAPI(object):
    def __init__(self, username, password, url, timeout, verify):
        self.username = username
        self.password = password
        self.url = url
        self.timeout= timeout
        self.verify = verify
        self.auth = requests.post(url + "api/login/", auth = (username, password), data = {}, timeout = self.timeout, verify = self.verify)
        self.auth_token = f"Token {json.loads(self.auth.text)['token']}"
        self.headers = {'Authorization': self.auth_token}

    def dlqps_lookup(self, lookup: str):
        dlpqs_url = f'api/dlpqs/{lookup}'
        return json.loads(requests.get(self.url + dlpqs_url, headers=self.headers, data={}, timeout = self.timeout, verify = self.verify).text)

def portScan(ip,sprange,eprange):
    #Function to Scan port ranges, Returns Open Ports and Filtered Ports
    #if the Qscan works only use this function for the IPV6 addr
    open = []
    filtered = []
    try:
        if is_ipv4(ip) == True:
            for port in range(sprange,eprange):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(.4)
                result = sock.connect_ex((ip, port))
                if result == 11:
                    filtered.append(port)
                elif result == 0:
                    open.append(port)
                sock.close()    
        elif is_ipv6(ip) == True:
            for port in range(sprange,eprange):
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(.4)
                result = sock.connect_ex((ip, port))
                if result == 11:
                    filtered.append(port)
                elif result == 0:
                    open.append(port)
                sock.close()
        else:
            print("Invalid IP Given %s" % ip)
            
            
    except KeyboardInterrupt:
        print ("You pressed Ctrl+C")
        sys.exit()
        
    except:
        err = sys.exc_info()[0]
        print ("Unable to scan %s, %s" % (ip,err))
        return
    
    return(open,filtered)

def is_mac(string):
    rule = re.compile(r'''[0-9a-f]{2}([:])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$''', re.IGNORECASE)  #working as of now for colon delimited macs
    rule1 = re.compile(r'''([0-9a-f]{2}){6}$''',re.IGNORECASE)  #might work testing (for macs that are not colon delimited)
    
    if rule.match(string) is not None:
        return True
    elif rule1.match(string) is not None:
        return True
    else:
        return False

def is_ipv4(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False
    return True

def is_ipv6(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True

def test_string(string):
    if is_mac(string) == True:
        return 0
    elif is_ipv6(string) == True:
        return 1
    elif is_ipv4(string) == True:
        return 2
    else:
        return 3

def file_info(filename):
    MACList = []
    v4List = []
    v6List = []
    container = []
    File = open(filename, 'r')
    lines = File.readlines()

    #get a container will all the Address types as strings in one place with no newline chars
    for index, line in enumerate(lines):
        if index != len(lines)-1:
            line = line[:-1]
        addresses = line.split(" ")
        if len(addresses) > 1:
            for add in addresses:
                container.append(add)
        else:
            container.append(addresses[0])

    #just tests each address in  the container for type of address
    for addr in container:
        if test_string(addr) == 0:
            MACList.append(addr.lower())
        if test_string(addr) == 1:
            v6List.append(addr.lower())
        if test_string(addr) == 2:
            v6List.append(addr.lower())
        if test_string(addr) == 3:
            print("Sorry the " + str(addr) + " address is not vaild. Please check format.")

    File.close()
    return MACList, v4List, v6List

def make_parse():
    parser = argparse.ArgumentParser(description = "API Information")
    parser.add_argument('-f', action='store', dest='filename', help='store a file with multiple mac addresses')
    parser.add_argument('-m', action='store', dest='oneMAC', help='store a single MAC address')
    parser.add_argument('-M', action='store', dest='allMACs', nargs= '*', help='store a space sperated list of MAC addresses')
    parser.add_argument('-i', action='store', dest='oneIP', help='store a single ip address')
    parser.add_argument('-I', action='store', dest='allIPs', nargs='*', help='store a list of IP adresses')
    parser.add_argument('-p', action='store', dest='filePath', help= 'Enter in full file path name to store path for data extraction')
    return parser.parse_args()

def preprosses(args):
    ListofMacs = []
    ListofIPs = []
    
    #using all if statments due to worst case senario a cmdln entry you use all argparse commands
    if args.filename != None:
        MACS, V4, V6 = file_info(args.filename)
        ListofMacs += MACS
        ListofIPs += V4 + V6
        
    if args.oneMAC != None:
        ListofMacs.append(args.oneMAC)
        
    if args.allMACs != None:
        for addr in args.allMACs:
            ListofMacs.append(addr)
            
    if args.oneIP != None:
        ListofIPs.append(args.oneIP)
        
    if args.allIPs != None:
        for IP in args.allIPs:
            ListofIPs.append(IP)
            
    if args.filePath != None:
        MACS, V4, V6 = file_info(args.filePath)
        ListofMacs += MACS
        ListofIPs += V4 + V6
        
    if len(ListofIPs) == 0 and len(ListofMacs) == 0: #worst case senario so we stop the program.
        print("There are no adresses to scan from any form of input")
        exit()

    return ListofMacs, ListofIPs

def Q_Scan(addr, ScanSession):
    scan_info = ScanSession.scan("Presentation+Test+Scan", addr)#the scan completes and creates an account of the scan this can be viewed in the download or in the GUI

    #these would be the lines to download the results but for now just return the reference number of securitys review later
    #print(scan_info)
    #download_results = ScanSession.download_results(scan_info["REFERENCE"])
    #print(download_results.text)

    return scan_info["REFERENCE"]

def get_IPs(MACs):
    newIPs = []
    combined = []
    for mac in MACs:
        print("Searching for devices...")
        elements = ElementsAPI(username, password, 'https://api.elements.charter.com/', timeout = 10, verify = False)
        Body = elements.dlqps_lookup(mac)
        
        if Body['success'] == False:
            print(mac + " was not found")
            
        else:
            info = False
            print("Gathering device information now...")
            for data in Body['response']['data']:
                if 'ip' in data != False:
                    newIPs.append(data['ip'])
                if info is False:
                    vendor = data['deviceInfo']['vendor']
                    model = data['deviceInfo']['model']
                    firmware = data['deviceInfo']['firmwareVersion']
            combined.append([mac, vendor, model, firmware, newIPs])
            newIPs = []
            
    return combined

def main(): #best way test this is to have a mac in the file and read and show the both API requests
    args = make_parse()
    IPs = []
    MACs = [] 
    MACs, IPs = preprosses(args)
    Data = get_IPs(MACs)
    Ref_File = open('Scan_References.txt', 'w')
    # print(Data)

    if len(Data) > 0:
        ScanSession = Qualys_API(QUser, QPass, QURL)
        for device in Data:
            for ip in device[4]:
                
                #this will be where the qualyus call is made
                if is_ipv4(ip) is True:
                    #vendor model firmware ip
                    print("Scanning: {} {} {} {}".format(device[1], device[2], device[3], ip))
                    Scan_ID = Q_Scan(ip, ScanSession)
                    print(Scan_ID)
                    Ref_File.write(Scan_ID+"\n")

                elif is_ipv6(ip) is True:#it's a v6 scan MAKE SURE TO TEST CORRECTLY BE ON THE VPN TO ENABLE V6 SCAN
                    print("Scanning: {} {} {} {} for open ports".format(device[1], device[2], device[3], ip))
                    OpenPorts = portScan(ip, Port1, Port2)
                    print(OpenPorts)
                    Ref_File.write("{} {} {} {} {}\n".format(device[1], device[2], device[3], ip, OpenPorts))
        ScanSession.logout()

    if len(IPs) > 0:
        print(IPs)
        ScanSession = Qualys_API(QUser, QPass, QURL)
        for ip in IPs:
            ip = str(ip)
            #this will be where the qualyus call is made
            if is_ipv4(ip) is True:
                print("Scanning: {} address for vulnerabiltiies".format(ip))
                Scan_ID = Q_Scan(ip, ScanSession)
                print(Scan_ID)
                Ref_File.write(Scan_ID+"\n")

            elif is_ipv6(ip) is True:
                print("Scanning: {} address for open ports".format(ip))
                stuff1 = portScan(ip, Port1, Port2)
                print(stuff1)
                Ref_File.write("{} {}\n".format(ip, stuff1))
        ScanSession.logout()
        
    Ref_File.close()
    
if __name__ == "__main__":
    main() 