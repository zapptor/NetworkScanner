import os
from scapy.all import getmacbyip, conf, Ether, srp, sendp, send, ARP, get_if_addr, get_if_list
from scapy.layers.inet import IP, TCP, sr, ICMP, UDP
import time
import ipaddress
import sys
import socket
import nmap
from time import sleep
from concurrent.futures import ThreadPoolExecutor

#Global cache to store inputs and outputs for later use
arp_cache = {}

DEFAULT_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080]

VERBOSE = False

CONNECT_SCAN_CONFIG = {
    'timeout': 2,
    'retries': 1,
    'threads': 20,
    'stealth_delay': 0.1,
    'banner_grabbing': True,
    'verbose': False,
}


SYN_SCAN_CONFIG = {
    'timeout': 2,
    'retries': 1,
    'threads': 20,
    'stealth_delay': 0.1,
    'banner_grabbing': True,
    'verbose': False,
}

BANNER_SCAN_CONFIG = {
    'Version intensity': 0,
}

IP_SCAN_CONFIG = {
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
    #Function to validate network or single ip, will return the network object if valid
    #and return a network object with a range of /32 if its a single ip
    try:
        network = network.strip()
        if "/" in network:
            return ipaddress.IPv4Network(network, strict=False)
        else:
            return ipaddress.IPv4Network(f"{network}/32", strict=False)
        
    except ValueError:
        return None


def validate_version(version: str) -> bool:
    #Function to validate version detection input
    try:
        version_num = int(version)
        if 0 <= version_num <= 9:
            return True
        else:
            return None
    except ValueError:
        return None


def get_active_hosts(network) -> list:
    """
    Get active hosts on the network using ARP requests.
    Return a list of active IP addresses.
    """
    #Function to get active hosts on the network, takes prefix or subnetmask

    active_hosts = []
    
    network_cidr = str(network)


    print(network_cidr)
    try:
        arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr)
        #print("send packet arp")
        responses, _ = srp(arp, timeout=IP_SCAN_CONFIG["timeout"], verbose=IP_SCAN_CONFIG["verbose"])
        for sent, received in responses:
            if received.haslayer(ARP):
                ip = received.psrc
                mac = received.hwsrc
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
    
    try:
        is_local = network and ipaddress.IPv4Address(ip) in network
        if is_local:
            #get local ip with arp 
            mac = conf.netcache.arp_cache.get(ip, None)
            if not mac:
                arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                response = srp(arp, timeout=GET_MAC_CONFIG["timeout"], 
                            verbose=GET_MAC_CONFIG["verbose"])[0]
                if response:
                    mac = response[0][1].hwsrc
                    conf.netcache.arp_cache[ip] = mac
                    return mac   
                else:
                    print(f"\nCould not resolve MAC for {ip}")
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
        return DEFAULT_PORTS


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
        print("Type 'b' to return to the main menu.")
        network_input = input(f"\nEnter network range/ip(s): ")

        if network_input == "b":
            return None
        
        if v_detection:
            if "-v" in network_input:
                ip, version_nr = network_input.split("-v")
                print(ip)
                print(version_nr)
                
                validated_network = validate_network(ip)
                if validated_network is None:
                    print(f"\nInvalid ip: {ip}. Please try again.")
                    sleep(2)
                    continue
                if not validate_version(f"{version_nr}"):
                    print(f"\nInvalid version detection: -v{version_nr}. Please try again.")
                    sleep(2)
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
    start_time = time.perf_counter()
    open_ports = []
    target_mac = get_target_mac(ip, network)
    is_local = network and ipaddress.IPv4Address(ip) in network
    if is_local:
        if not target_mac:
            return ip, open_ports, 0  # Return three values consistently
        for port in ports:
            try:
                syn = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port, flags="S")
                response = srp(syn, timeout=CONNECT_SCAN_CONFIG["timeout"], 
                            retry=CONNECT_SCAN_CONFIG["retries"], 
                            verbose=CONNECT_SCAN_CONFIG["verbose"])[0]
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
                            sendp(ack, verbose=CONNECT_SCAN_CONFIG["verbose"])

                            rst = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port,
                                flags="R",
                                seq=received[TCP].ack,
                                ack=received[TCP].seq + 1
                                )
                            sendp(rst, verbose=CONNECT_SCAN_CONFIG["verbose"])
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
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(CONNECT_SCAN_CONFIG["timeout"])
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
    start_time = time.perf_counter()
    open_ports = []
    target_mac = get_target_mac(ip, network)
    is_local = network and ipaddress.IPv4Address(ip) in network
    if not target_mac:
        return ip, open_ports, 0  # Return three values consistently
    for port in ports:
        try:
            if is_local:
                syn = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port, flags="S")
                response = srp(syn, timeout=SYN_SCAN_CONFIG["timeout"], 
                            retry=SYN_SCAN_CONFIG["retries"], 
                            verbose=SYN_SCAN_CONFIG["verbose"])[0]
                print(f"  Sending SYN packet to {ip}:{port} LOCAL")
            else:
                syn = IP(dst=ip) / TCP(dport=port, flags="S")
                response = sr(syn, timeout=SYN_SCAN_CONFIG["timeout"], 
                            retry=SYN_SCAN_CONFIG["retries"], 
                            verbose=SYN_SCAN_CONFIG["verbose"])[0]
                print(f"  Sending SYN packet to {ip}:{port} EXTERNAL")
            
            if response:
                print(f"  Received response for {ip}:{port}")
                for sent, received in response:
                    if received[TCP].flags == "SA":
                        open_ports.append(port)
                        if is_local:
                            rst = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port, flags="R")
                            sendp(rst, verbose=SYN_SCAN_CONFIG["verbose"])
                        else:
                            rst = IP(dst=ip) / TCP(dport=port, flags="R")
                            send(rst, verbose=SYN_SCAN_CONFIG["verbose"])
                        break

                time.sleep(SYN_SCAN_CONFIG['stealth_delay'])

        except Exception as e:
            print(f"Error scanning IP {ip}:{port} {e}")   
            continue

    duration = time.perf_counter() - start_time
    #print(f"Scan of {ip} took {duration:.2f} seconds.")
    return ip, open_ports, duration


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


def concurrent_scan(ports: list, scan_function, ip_network_pairs=None, ips=None) -> tuple[dict, float]:
    """
    Scan multiple IP addresses concurrently for open TCP ports, abel to also scan for banners if ip and ports is provided.
    Return a dictionary containing the IP addresses as keys and a tuple of open ports and scan duration as values.
    """

    #Function to scan multiple IPs concurrently for open TCP ports, or scan for banners if ip and ports is provided.
    results = {}
    start_time = time.perf_counter()

    # Use ThreadPoolExecutor to scan multiple IPs or Banners concurrently
    with ThreadPoolExecutor(max_workers=SYN_SCAN_CONFIG['threads']) as executor:

        #Concurrent Scan for banners
        if scan_function in (banner_scan_nmap_tcp, banner_scan_nmap_udp):
            futures = {executor.submit(scan_function, ip, ports): ip for ip in ips}

            for future in futures:
                ip = futures[future]
                try:
                    banner_dict = future.result()
                    results[ip] = banner_dict
                except Exception as e:
                    print(f"Error banner {ip}: {e}")
            scan_duration = time.perf_counter() - start_time
            return results, scan_duration      


        #Concurrent scan for open ports
        else:
            futures = {executor.submit(scan_function, ip, ports, network): ip for ip, network in ip_network_pairs}

            #Get the results from the futures
            for future in futures:
                ip, open_ports, duration = future.result()
                results[ip] = (open_ports, duration)
        scan_duration = time.perf_counter() - start_time        
        return results, scan_duration


def submenu_scan_tcp_ips(scan_function, scan_protocol, menu_name: str,):

    """
    Display the scan IPs menu and handle user input.
    Prompt the user to input a list of IP addresses and scan for open TCP ports.
    """
    
    while True:
        print("=" * 31)
        print(f"\t{menu_name}")
        print("=" * 31)
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

        # Call functions to perform the scan and display the results
        if scan_protocol == "TCP":
            tcp_scan_result, scan_duration = concurrent_scan(
                ip_network_pairs=ip_network_pairs, 
                ports=target_ports, 
                scan_function=scan_function
                )

            for ip, (open_ports, duration) in tcp_scan_result.items():
                
                if open_ports:
                    #print(f"\nIP Address has open ports: {ip}")
                    #If version detection is enabled, concurrent scan for banners
                    #and print the ip, open ports and banners
                    if version_nr:
                        banner_result, duration = concurrent_scan(ips=[ip], ports=open_ports, scan_function=banner_scan_nmap_tcp)
                        for ip, banners in banner_result.items():
                            print(f"\nIP Address: {ip}")
                            for port, banner in banners.items():
                                print(f"Port: {port} is open - {banner}")
                            print(f"Scan duration: {duration:.2f} seconds")
                            input("\nPress Enter to continue...")
                    
                    #If version detection is not enabled, print open ports
                    else:
                        print(f"\nIP Address: {ip}")
                        for port in open_ports:
                            print(f"Port: {port} is open")
                        print(f"Scan duration: {duration:.2f} seconds")
                    print(f"\nTotal scan duration: {scan_duration:.2f} seconds")
                    input("\nPress Enter to continue...")


def menu_tcp_port_scanner():
    """
    Display the TCP port scanner menu and handle user input.
    """
    #try:
    while True:
        clear_screen()
        print("=" * 31)
        print("\tTCP Port Scanner")
        print("=" * 31)
        print("1. SYN Scan (Stealth Scan)")
        print("2. CONNECT scan (Full TCP Handshake)")
        print("3. ")
        print("Type 'b' to return to the main menu.")
        choice = input("\nChoose an option: ").strip().lower()
        if choice == "1":
            menu_name = "SYN Scan"
            submenu_scan_tcp_ips(syn_scan_tcp, "TCP", menu_name)
        elif choice == "2":
            menu_name = "CONNECT Scan"
            submenu_scan_tcp_ips(connect_scan_tcp, "TCP", menu_name)
        elif choice == "3":
            pass

        elif choice == "b":
            break


def menu_active_host_scanner():
    """
    Display the active IP hosts menu and handle user input.
    Prompt the user to input a network range and scan for active hosts.
    """
    while True:  
        #clear_screen()
        print("=" * 31)
        print("\tScan for Active Hosts")
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
        print("3. Configurations (In Progress)")
        print("Type 'q' to quit.")
        choice = input("\nEnter your choice: ").strip().lower()
        if choice == "1":
            clear_screen()
            menu_active_host_scanner()    
        elif choice == "2":
            clear_screen()
            menu_tcp_port_scanner() 
        elif choice == "3":
            print("NOT AVALIBLE")
            input("press enter to continue....")
        elif choice == "q":
            sys.exit()


if __name__ == "__main__":
    main_menu()
