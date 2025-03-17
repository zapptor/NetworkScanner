import os
from scapy.all import getmacbyip, conf, Ether, srp, sendp, send, ARP, get_if_addr, get_if_list
from scapy.layers.inet import IP, TCP, sr, ICMP, UDP
import time
import ipaddress
import sys
import socket
import nmap
import signal
from time import sleep
from concurrent.futures import ThreadPoolExecutor, as_completed

#Global cache to store inputs and outputs for later use
arp_cache = {}

#Global variables
TCP_1000_PORTS = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389]

TCP_200_PORTS = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083]

TCP_100_PORTS = [1,3,7,9,13,17,19,20,21,22,23,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,110,111,113,119,125,135,139,143,144,179,199,389,427,443,444,445,465,512,513,514,515,543,544,548,554,587,631,636,646,873,990,993,995,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,3306,3389,5900,8080,8081,8443]

TCP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

DEFAULT_TCP_PORTS = TCP_100_PORTS

TCP_PORTS = TCP_100_PORTS    

IFACE = None

VERBOSE = False

SCAN_CANCELLED = False



DEFAULT_TCP_SCAN_CONFIG = {
    'timeout': 1,
    'retries': 0,
    'threads': 100,
    'stealth_delay': 0.1,
    'verbose': False,
}


TCP_SCAN_CONFIG = {
    'timeout': 2,
    'retries': 0,
    'threads': 100,
    'stealth_delay': 0.1,
    'verbose': False,
}


DEFAULT_BANNER_SCAN_CONFIG = {
    'Version intensity': 0,
    'threads': 100,
    'timeout': 2,
    'retries': 1,
}



BANNER_SCAN_CONFIG = {
    'Version intensity': 0,
    'threads': 100,
    'timeout': 2,
    'retries': 1,
}


HOST_SCAN_CONFIG = {
    'timeout': 1,
    'retries': 1,
    'verbose': True
}


GET_MAC_CONFIG = {
    'timeout': 1,
    'retries': 1,
    'verbose': False,
}


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def signal_handler(sig, frame):
    global SCAN_CANCELLED
    SCAN_CANCELLED = True
    print("\nInterrupted by user. Cancelling scan...\n")

# Register the signal handler (ctrl + C)
signal.signal(signal.SIGINT, signal_handler)


def reset_tcp_scan_config():
    global TCP_SCAN_CONFIG
    global TCP_PORTS

    TCP_PORTS = DEFAULT_TCP_PORTS.copy()
    TCP_SCAN_CONFIG = DEFAULT_TCP_SCAN_CONFIG.copy()
    print("TCP scan configuration reset to default.")


def reset_banner_scan_config():
    global BANNER_SCAN_CONFIG

    BANNER_SCAN_CONFIG = DEFAULT_BANNER_SCAN_CONFIG.copy()
    print("Banner scan configuration reset to default.")


def tcp_port_labels():
    if TCP_PORTS == TCP_1000_PORTS:
        port_label = "Top 1000 ports"
    elif TCP_PORTS == TCP_200_PORTS:
        port_label = "Top 200 ports"
    elif TCP_PORTS == TCP_100_PORTS:
        port_label = "Top 100 ports"
    elif TCP_PORTS == TCP_20_PORTS:
        port_label = "Top 20 ports"
    else:
        port_label = "Custom ports"   

    return port_label



def validate_port(port: str) -> bool:
    #Function to validate port
    try:
        port_num = int(port)
        if 0 <= port_num <= 65535:
            return True
        else:
            return False
    except ValueError:
        return False


def validate_network(network: str) -> ipaddress.IPv4Network:
    """
    Validate the network input and return an IPv4Network object if valid.
    If the input is a single IP address, convert it to a /32 network.
    """
    
    try:
        network = network.strip()
        if "/" in network:
            return ipaddress.IPv4Network(network, strict=False)
        else:
            return ipaddress.IPv4Network(f"{network}/32", strict=False)
        
    except ValueError:
        return None


def validate_version(version: str) -> bool:
    """
    Validate the version detection input and return True if valid, otherwise return None.
    """
    
    try:
        version_num = int(version)
        if 0 <= version_num <= 9:
            return True
        else:
            return None
    except ValueError:
        return None


def get_correct_iface(network: str) -> str:
    """
    Get the correct interface from the local IP address.
    Return the interface name if found, otherwise return the default interface.
    """
    ip_interface = ipaddress.IPv4Interface(network)
    #print(ip_interface)
    host_ip = str(ip_interface.ip)
    #print(host_ip)
    
    default_iface = conf.route.route(host_ip)[0]
    default_local_ip = get_if_addr(default_iface)
    
    # If the host IP is not private, return the default interface immediately
    if not ipaddress.ip_address(host_ip).is_private:
        return default_iface
    
    # If the default interface is not loopback, return it immediately
    if not ipaddress.ip_address(default_local_ip).is_loopback:
        return default_iface
    
    # Otherwise, iterate over the interfaces to find one that isn't loopback.
    for iface in get_if_list():
        try:
            iface_ip = get_if_addr(iface)
            # Check if the interface has an IP and it's not loopback
            if iface_ip and not ipaddress.ip_address(iface_ip).is_loopback:
                return iface
            
        except Exception:
            continue
        
    #fall back if no match
    return default_iface



def get_active_hosts(network) -> list:
    """
    Get active hosts on the network using ARP requests.
    Return a list of active IP addresses.
    """
    global IFACE
    
    if not IFACE:
        IFACE = get_correct_iface(network)
    
    iface = IFACE


    print(f"get active hosts on {network} using interface {iface}")

    active_hosts = []
    
    network_cidr = str(network)


    print(network_cidr)

    #send arp request to broadcast address
    try:
        arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr)
        #print("send packet arp")
        responses, _ = srp(arp, timeout=HOST_SCAN_CONFIG["timeout"], verbose=HOST_SCAN_CONFIG["verbose"], iface=iface)
        for sent, received in responses:
            if received.haslayer(ARP):
                ip = received.psrc
                mac = received.hwsrc
                #store ip and mac in cache
                conf.netcache.arp_cache[ip] = mac
                active_hosts.append(ip)
                if VERBOSE:
                    print(f"Active host: {ip}")
            
    except Exception as e:
        print(f"Host discovery error: {e}")

    return list(set(active_hosts))

    
def get_target_mac(ip: str, network: ipaddress.IPv4Network) -> str:
    """
    Get the MAC address of the target IP address.
    Return the MAC address if found, otherwise return None.
    """
    global IFACE

    if not IFACE:
        IFACE = get_correct_iface(network)
    
    iface = IFACE

    try:
        is_local = network and ipaddress.IPv4Address(ip) in network
        if is_local:
            #get local mac with arp 
            mac = conf.netcache.arp_cache.get(ip, None)
            if not mac:
                arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                response = srp(arp, timeout=GET_MAC_CONFIG["timeout"], 
                            verbose=GET_MAC_CONFIG["verbose"], iface=iface)[0]
                if response:
                    mac = response[0][1].hwsrc
                    #store ip and mac in cache
                    conf.netcache.arp_cache[ip] = mac
                    return mac   
                else:
                    #print(f"\nCould not resolve MAC for {ip}")
                    return None
            return mac
        else:
            """
            If remote ip provided, get gateway mac, its not neede since we use layer 3 
            for external ips, but nice to have to funciton always return the right mac
            incase of future changes
            """
            #iface, netmask, gateway = conf.route.route("0.0.0.0")
            gateway_ip = conf.route.route("0.0.0.0")[2]
            return getmacbyip(gateway_ip)
        
    except Exception as e:
        print(f"Mac resolution failed: {e}")
        return None


def parse_ports_input(ports_input: str) -> list[int]:
    """
    Parse a comma-separated ports input string and return a list of valid port numbers.
    If the input is empty, return the default ports.
    """
    if ports_input:
        ports_str = [port.strip() for port in ports_input.split(",") if port.strip()]
        # Check if all port entries are valid
        if not all(validate_port(port) for port in ports_str):
            return None  # or raise an error/message indicating invalid input
        return [int(port) for port in ports_str]
    else:
        return TCP_PORTS


def parse_config_entry(key_value: str) -> tuple[str, str]:
    """
    Parse a configuration entry in the format "key=value".
    Return a tuple containing the key and value if valid, otherwise raise an error
    """
    global TCP_PORTS

    key_value = key_value.split("=")
    if len(key_value) == 2:
        key, value = key_value[0].strip().lower(), key_value[1].strip().lower()
        if key == "stealth":
            try:
                float(value)
                return "stealth_delay", value
            except ValueError:
                raise ValueError("Invalid value for stealth; must be numeric (float or int).")
        elif value.isdigit() and key in TCP_SCAN_CONFIG:
            return key, value
        elif value in ["true", "false", "20", "100", "200" ,"1000"]:
            return key, value
        else:
            raise ValueError("Invalid configuration entry value.")
    else:
        raise ValueError("Invalid configuration entry format.")
    
        

def prompt_network_input(v_detection = None) -> tuple[list[ipaddress.IPv4Network], int]:
    """
    Prompt the user to input a network range or IP address, and Version detection.
    Return a tuple containing the list of network ranges and the version detection number.

    """

    while True:
        print("You can enter:")
        print("  • A network range in CIDR notation \n\te.g. 192.168.0.1/24")
        print("  • A single IP address \n\te.g. 192.168.0.1")
        print("  • A comma-separated list of IP addresses \n\te.g. 192.168.0.1, 192.168.0.2")
        if v_detection:
            print("  • Version Detection Append -v0-9")
            print("\te.g. 192.168.1.100 -v3")
            print("\t0-9 least to most aggressive")
        print("\nType 'b' to return to the main menu.")
        print("PRESS CTRL + C TO CANCEL SCAN")
        network_input = input(f"\nEnter network range/ip(s): ")

        if network_input == "b":
            return None
        
        if v_detection:
            if "-v" in network_input:
                ip, version_nr = network_input.split("-v")
                #print(ip)
                #print(version_nr)
                
                validated_network = validate_network(ip)
                if validated_network is None:
                    print(f"\nInvalid ip: {ip}. Please try again.")
                    sleep(2)
                    clear_screen()
                    continue
                
                if not validate_version(f"{version_nr}"):
                    print(f"\nInvalid version detection: -v{version_nr}. Please try again.")
                    sleep(2)
                    clear_screen()
                    continue
                else:
                    BANNER_SCAN_CONFIG["Version intensity"] = int(version_nr)
                    return [validated_network], version_nr

        if ","  in network_input:
            networks = []
            for ip_str in [ip.strip() for ip in network_input.split(",") if ip.strip()]:
                validated_network = validate_network(ip_str)
                if validated_network is None:
                    print(f"\nInvalid ip: {ip_str}. Please try again.")
                    sleep(2)
                    continue
                else:
                    networks.append(validated_network)

            return networks, None
    
        else:
            validated_network = validate_network(network_input)
            if validated_network is None:
                print(f"\nInvalid ip: {network_input}. Please try again.")
                sleep(2)
                continue
            else:
                return [validated_network], None


def prompt_ports_input() -> list[str]:
    """
    Prompt the user to input a list of ports to scan.
    Return the list of ports if valid, otherwise reprompts.
    """
    while True:
        target_ports_input = input("Enter ports to scan (comma separated) Leave blank for default: ").strip()
        if target_ports_input.lower() == "b":
            return None
        target_ports = parse_ports_input(target_ports_input)
        if target_ports is None:
            print("\nInvalid port(s). Please try again.")
            sleep(2)
            continue
        else:
            break

    return target_ports


def connect_scan_tcp(ip: str, ports: list[int], network: ipaddress.IPv4Network) -> tuple[str, list[str], float]:
    """
    Scan a single IP address for open TCP ports.
    Return a tuple containing the IP address, a list of open ports, and the scan duration.
    Send syn, get syn-ack, send ack on layer 2, fallback to layer 3 if external.
    Using socket module for layer 3, scapy for layer 2. Dont need root for socket module.
    """
    global SCAN_CANCELLED
    global IFACE
    
    if not IFACE:
        IFACE = get_correct_iface(network)
    
    iface = IFACE



    start_time = time.perf_counter()
    open_ports = []
    target_mac = get_target_mac(ip, network)
    is_local = network and ipaddress.IPv4Address(ip) in network
    if is_local:
        if not target_mac:
            return ip, open_ports, 0  # Return three values consistently
        for port in ports:
            if SCAN_CANCELLED:
                break
                
            try:
                syn = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port, flags="S")
                response = srp(syn, timeout=TCP_SCAN_CONFIG["timeout"], 
                            retry=TCP_SCAN_CONFIG["retries"], 
                            verbose=TCP_SCAN_CONFIG["verbose"], iface=iface)[0]
                print(f"  Sending SYN packet to {ip}:{port} LOCAL")
                
                if response:
                    print(f"  Received response for {ip}:{port}")
                    for sent, received in response:
                        if received[TCP].flags == "SA":
                            ack = Ether(dst=target_mac) / IP(dst=ip) / TCP(
                                dport=port, 
                                flags="A",
                                seq=received[TCP].ack,
                                ack=received[TCP].seq + 1
                                )
                            sendp(ack, verbose=TCP_SCAN_CONFIG["verbose"], iface=iface)

                            rst = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port,
                                flags="R",
                                seq=received[TCP].ack,
                                ack=received[TCP].seq + 1
                                )
                            sendp(rst, verbose=TCP_SCAN_CONFIG["verbose"], iface=iface)
                            open_ports.append(port)
                            break

                    #time.sleep(TCP_SCAN_CONFIG['stealth_delay'])

            except Exception as e:
                print(f"Error scanning IP Layer 2{ip}: {e}")                               
                continue

        duration = time.perf_counter() - start_time
        #print(f"Scan of {ip} took {duration:.2f} seconds.")
        return ip, open_ports, duration                    

    else:
        for port in ports:
            if SCAN_CANCELLED:
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(TCP_SCAN_CONFIG["timeout"])
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except Exception as e:
                print(f"Error scanning IP Layer 3 {ip}:{port} {e}")
                continue

        duration = time.perf_counter() - start_time   
        return ip, open_ports, duration  # Return three values even in exception


def syn_scan_tcp(ip: str, ports: list[int], network: ipaddress.IPv4Network) -> tuple[str, list[str], float]:
    """
    Scan a single IP address for open TCP ports,.
    Return a tuple containing the IP address, a list of open ports, and the scan duration.
    send syn, get syn-ack, send rst on layer 2, fallback to layer 3 if external.
    """
    global SCAN_CANCELLED
    global IFACE

    if not IFACE:
        IFACE = get_correct_iface(network)
    
    iface = IFACE
    
    start_time = time.perf_counter()
    open_ports = []
    target_mac = get_target_mac(ip, network)
    is_local = network and ipaddress.IPv4Address(ip) in network
    if not target_mac:
        return ip, open_ports, 0  # Return three values consistently
    for port in ports:
        if SCAN_CANCELLED:
            break
        try:
            if is_local:
                syn = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port, flags="S")
                response = srp(syn, timeout=TCP_SCAN_CONFIG["timeout"], 
                            retry=TCP_SCAN_CONFIG["retries"], 
                            verbose=TCP_SCAN_CONFIG["verbose"], iface=iface)[0]
                print(f"  Sending SYN packet to {ip}:{port} LOCAL")
            else:
                syn = IP(dst=ip) / TCP(dport=port, flags="S")
                response = sr(syn, timeout=TCP_SCAN_CONFIG["timeout"], 
                            retry=TCP_SCAN_CONFIG["retries"], 
                            verbose=TCP_SCAN_CONFIG["verbose"], iface=iface)[0]
                print(f"  Sending SYN packet to {ip}:{port} EXTERNAL")
            
            if response:
                print(f"  Received response for {ip}:{port}")
                for sent, received in response:
                    if received[TCP].flags == "SA":
                        open_ports.append(port)
                        if is_local:
                            rst = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port, flags="R")
                            sendp(rst, verbose=TCP_SCAN_CONFIG["verbose"], iface=iface)
                        else:
                            rst = IP(dst=ip) / TCP(dport=port, flags="R")
                            send(rst, verbose=TCP_SCAN_CONFIG["verbose"], iface=iface)
                        break

                time.sleep(TCP_SCAN_CONFIG['stealth_delay'])

        except Exception as e:
            print(f"Error scanning IP {ip}:{port} {e}")   
            continue

    duration = time.perf_counter() - start_time
    #print(f"Scan of {ip} took {duration:.2f} seconds.")
    return ip, open_ports, duration


#Not used, incase of adding udp scan
def banner_scan_nmap_udp(ip: str, open_ports: int) -> dict:
    """
    Use nmap to grab banners for open UDP ports.
    Return a dictionary containing the open ports as keys and the banners as values.
    """
    scanner = nmap.PortScanner()

    ports_str = ",".join(str(port) for port in open_ports)
    scanner.scan(ip, ports=ports_str, arguments=f"-sU --version-intensity {BANNER_SCAN_CONFIG['Version intensity']}")
    
    banners = {}
    try:
        udp_info = scanner[ip].get('udp', {})
    except KeyError:
        udp_info = {}

    for port in open_ports:
        port_info = udp_info.get(port, {})
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        extrainfo = port_info.get("extrainfo", "")
        banner = f"{product} {version} {extrainfo}".strip()
        banners[port] = banner if banner else "No banner information available"

    return banners


def banner_scan_nmap_tcp(ip: str, open_ports: int) -> dict:
    """
    Use nmap to grab banners for open TCP ports.
    Return a dictionary containing the open ports as keys and the banners as values.
    
    banners = banner_scan_nmap_tcp(ip, open_ports)
    for port, banner in banners.items():
        print(f"Port {port}: {banner}")
    """
    scanner = nmap.PortScanner()

    ports_str = ",".join(str(port) for port in open_ports)
    scanner.scan(ip, ports=ports_str, arguments=f"-sV --version-intensity {BANNER_SCAN_CONFIG['Version intensity']}")
    
    banners = {}
    try:
        tcp_info = scanner[ip].get('tcp', {})
    except KeyError:
        tcp_info = {}

    for port in open_ports:
        #print(f"Grabbing banner {ip}:{port}")
        port_info = tcp_info.get(port, {})
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        extrainfo = port_info.get("extrainfo", "")
        banner = f"{product} {version} {extrainfo}".strip()
        banners[port] = banner if banner else "No banner information available"

    return banners


def concurrent_banner_scan(ip_to_open_ports: dict[str, list[int]], scan_function) -> tuple[dict, float]:
    """
    Run banner scanning concurrently for multiple IPs,
    where ip_to_open_ports is a dictionary mapping each IP to its list of open ports.
    Returns a dictionary mapping IPs to banner dictionaries and the total duration.
    """
    results = {}
    start_time = time.perf_counter()
    with ThreadPoolExecutor(max_workers=BANNER_SCAN_CONFIG["threads"]) as executor:
        futures = {executor.submit(scan_function, ip, open_ports): ip for ip, open_ports in ip_to_open_ports.items()}
        for future in futures:
            ip = futures[future]
            try:
                banner_dict = future.result()
                results[ip] = banner_dict
            except Exception as e:
                print(f"Error banner {ip}: {e}")
    scan_duration = time.perf_counter() - start_time
    return results, scan_duration


def concurrent_port_scan(ports: list, scan_function, ip_network_pairs) -> tuple[dict, float]:
    """
    Scan multiple IP addresses concurrently for open TCP ports.
    Return a dictionary containing the IP addresses as keys and a tuple of open ports and scan duration as values.
    Supports interruption with partial results.
    """
    global SCAN_CANCELLED
    
    results = {}
    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=TCP_SCAN_CONFIG['threads']) as executor:
        # Submit all scan tasks and map futures to IPs
        futures = {executor.submit(scan_function, ip, ports, network): ip for ip, network in ip_network_pairs}
        
        # Process futures as they complete, checking for cancellation
        while futures:
            if SCAN_CANCELLED:
                break  # Exit if scan is cancelled
            try:
                # Use a short timeout to remain responsive to interrupts
                for future in as_completed(futures, timeout=0.1):
                    ip = futures.pop(future)  # Remove the future from the dict
                    try:
                        ip, open_ports, duration = future.result()
                        results[ip] = (open_ports, duration)
                    except Exception as e:
                        print(f"Error scanning {ip}: {e}")
            except TimeoutError:
                pass  # No futures completed within timeout, loop again to check SCAN_CANCELLED

    scan_duration = time.perf_counter() - start_time
    return results, scan_duration


def submenu_scan_tcp_ips(scan_function, scan_protocol, 
                         menu_name: str,):

    """
    Display the scan IPs menu and handle user input.
    Prompt the user to input a list of IP addresses and scan for open TCP ports.
    """
    global SCAN_CANCELLED
    
    while True:
        print("=" * 31)
        print(f"\t{menu_name}")
        print("=" * 31)
        result = prompt_network_input(v_detection=True)
        if result is None:
            return

        networks, version_nr = result

        #Build mapping: ip -> network from all provided networks.
        ip_network_pairs = []
        for network in networks:
            if network.prefixlen == 32:
                ip_network_pairs.append((str(network.network_address), network))
            else:
                for ip in network.hosts():
                    ip_network_pairs.append((str(ip), network))


        target_ports = prompt_ports_input()
        if target_ports is None:
            return
        
        #reset scan cancelled flag
        SCAN_CANCELLED = False
        
        # Create the executor explicitly so we can control its shutdown
        
        # Call functions to perform the scan and display the results
        if scan_protocol == "TCP":
            tcp_scan_result, scan_duration = concurrent_port_scan(
                ip_network_pairs=ip_network_pairs, 
                ports=target_ports, 
                scan_function=scan_function,
                    )
        
        if SCAN_CANCELLED:
            print("\nScan was interrupted by user. Displaying partial results.")   
            
        if tcp_scan_result:  #proceed if we have results
              
            #If version detection is enabled, concurrent scan for banners
            #and print the ip, open ports and banners
            if version_nr:
                
                ip_to_open_ports = { ip: open_ports for ip, (open_ports, _) in tcp_scan_result.items() if open_ports }
                banner_result, banner_duration = concurrent_banner_scan(ip_to_open_ports=ip_to_open_ports, scan_function=banner_scan_nmap_tcp)
                
                for ip, banners in banner_result.items():
                    duration = tcp_scan_result[ip][1]
                    print(f"\nIP Address: {ip}")
                    for port, banner in banners.items():
                        print(f"Port: {port:<5} is open - {banner}")
                    print(f"Scan duration: {duration:.2f} seconds")
                print(f"\nScan duration for Banners: {banner_duration:.2f} seconds")
                
            
            #If version detection is not enabled/version nr not selected, print open ports
            else:
                banner_duration = 0
                for ip, (open_ports, duration) in tcp_scan_result.items():
                    if open_ports:
                        print(f"\nIP Address: {ip}")
                        for port in open_ports:
                            print(f"Port: {port:<5} is open")
                        print(f"Scan duration: {duration:.2f} seconds")
            total_scan = scan_duration + banner_duration            
            print(f"\nTotal scan duration: {total_scan:.2f} seconds")
            input("\nPress Enter to continue...")


def menu_tcp_port_scanner():
    """
    Display the TCP port scanner menu and handle user input.
    """
    #try:
    while True:
        clear_screen()
        print("=" * 31)
        print("       TCP Port Scanner")
        print("=" * 31)
        print("1. SYN Scan (Stealth Scan)")
        print("2. CONNECT scan (Full TCP Handshake)")
        print("3. Configurations")
        print("\nType 'b' to return to the main menu.")
        choice = input("\nChoose an option: ").strip().lower()
        if choice == "1":
            clear_screen()
            menu_name = "   SYN Scan"
            submenu_scan_tcp_ips(syn_scan_tcp, "TCP", menu_name)
        elif choice == "2":
            clear_screen()
            menu_name = " CONNECT Scan"
            submenu_scan_tcp_ips(connect_scan_tcp, "TCP", menu_name)
        elif choice == "3":
            clear_screen()
            menu_configurations_tcp_scan()
        elif choice == "b":
            break
        else:
            print("\nInvalid option. Please try again.")
            sleep(2)
            continue

        
def menu_active_host_scanner():
    """
    Display the active IP hosts menu and handle user input.
    Prompt the user to input a network range and scan for active hosts.
    """
    while True:  
        #clear_screen()
        print("=" * 31)
        print("     Scan for Active Hosts")
        print("=" * 31)
        result = prompt_network_input()
        if result is None:
            break

        networks, _ = result

        network = networks[0]

        active_hosts = get_active_hosts(network=network)
        if not active_hosts:
            print("\nNo active hosts found.")
        

        #initializing the index before loop so it resets.
        index = 0
        for index, host in enumerate(active_hosts, start=1):
                print(f"{index}. IP: {host}")
        print(f"\nNr of Active Hosts: {index}")
        user_input = input("\nPress Enter to continue...(b to main menu): ").strip().lower()
        if user_input == "b":
            break


def menu_configurations_tcp_scan():
    """
    Display the configurations menu and handle user input.
    """
    global TCP_PORTS

    while True:
        clear_screen()
        print("=" * 31)
        print("      TCP Configurations")
        print("=" * 31)
        print("Format: key=value (e.g. timeout = 2)")
        print(f" •Port scan 'Timeout' = {TCP_SCAN_CONFIG['timeout']}s")
        print(f" •Port scan 'Retries' = {TCP_SCAN_CONFIG['retries']}")
        print(f" •Port scan 'Stealth' = {TCP_SCAN_CONFIG['stealth_delay']}s")
        print(f" •Port scan 'Threads' = {TCP_SCAN_CONFIG['threads']}")
        print(f" •Port scan 'Verbose' = {TCP_SCAN_CONFIG['verbose']}")
        print(f"\nPort options = 20, 100, 200, 1000")
        print(f" •Default   'Ports' = {tcp_port_labels()}")
        
        print("\nType 'r' to reset to default.")
        print("Type 'b' to return to the main menu.")
        user_input = input(f"\nInput: ").lower()
        if user_input == "b":
            break
        if user_input == "r":
            reset_tcp_scan_config()
            sleep(2)
            continue
        try:
            key, value = parse_config_entry(user_input)
            if key in TCP_SCAN_CONFIG or key in ["ports"]:
                if key in  ["timeout", "retries", "threads"]:

                    if int(value) > 100000:
                        raise ValueError("Value must be less then 100 000.")
                    TCP_SCAN_CONFIG[key] = int(value)

                elif key == "stealth_delay":
                    if float(value) > 100000:
                        raise ValueError("Value must be less then 100 000.")
                    TCP_SCAN_CONFIG[key] = float(value)

                elif key == "verbose":
                    TCP_SCAN_CONFIG[key] = value

                elif key == "ports":
                    if value == "20":
                        TCP_PORTS = TCP_20_PORTS
                    elif value == "100":
                        TCP_PORTS = TCP_100_PORTS
                    elif value == "200":
                        TCP_PORTS = TCP_200_PORTS
                    elif value == "1000":
                        TCP_PORTS = TCP_1000_PORTS
                    
            else:
                raise ValueError("Invalid configuration key.")

                    
        except ValueError as e:
            print(f"Error: {e}")
            sleep(2)
            continue    


def main_menu():
    """
    Display the main menu and handle user input.
    """
    while True:
        clear_screen()
        print("=" * 31)
        print("\tNETWORK SCANNER")
        print("=" * 31)
        print("1. Scan for Active Hosts")
        print("2. TCP Port Scanner")
        print("\nType 'q' to quit.")
        choice = input("\nEnter your choice: ").strip().lower()
        if choice == "1":
            clear_screen()
            menu_active_host_scanner() 
               
        elif choice == "2":
            clear_screen()
            menu_tcp_port_scanner()
              
        elif choice == "q":
            sys.exit()
        else:
            print("\nInvalid option. Please try again.")
            sleep(2)
            continue

if __name__ == "__main__":
    main_menu()

