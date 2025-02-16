import os
from scapy.all import getmacbyip, conf, Ether, srp, sendp, send, ARP, get_if_addr
from scapy.layers.inet import IP, TCP, sr, ICMP, UDP
import time
import ipaddress
import sys
from time import sleep
from concurrent.futures import ThreadPoolExecutor

#Global chace to stor inputs and outputs for later use
cache = {}

DEFAULT_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080]

VERBOSE = False

TCP_SCAN_CONFIG = {
    'timeout': 2,
    'retries': 1,
    'threads': 50,
    'stealth_delay': 0.1,
    'banner_grabbing': True,
    'verbose': False,
}

IP_SCAN_CONFIG = {
    'timeout': 0.1,
    'retries': 1,
    'verbose': False
}

GET_MAC_CONFIG = {
    'timeout': 1,
    'retries': 1,
    'verbose': False,
}


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def validate_port(port: str) -> bool:
    try:
        port_num = int(port)
        if 0 <= port_num <= 65535:
            return True
        else:
            return False
    except ValueError:
        return False


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_subnetmask(subnetmask_prefix: str) -> bool:
    try:
        #handle CIDR
        if subnetmask_prefix.startswith("/"):
            cidr = int(subnetmask_prefix[1:])
            if 0 <= cidr <= 32:
                return True

        #split subnet into octets
        octets = list(map(int, subnetmask_prefix.split(".")))
        if len(octets) != 4:
            return False
        
        #convert to int
        octet_values = [int(octet) for octet in octets]

        #Combine the octets back into a 32bit integer, with bitwise
        #Octet 1: 255 → becomes 11111111 00000000 00000000 00000000 after shifting left 24 bits.
        #Octet 2: 255 → becomes 00000000 11111111 00000000 00000000 after shifting left 16 bits.
        #Octet 3: 255 → becomes 00000000 00000000 11111111 00000000 after shifting left 8 bits.
        #Octet 4: 0 → remains 00000000 00000000 00000000 00000000.
        mask_32bit_int = (
            (octet_values[0] << 24) |
            (octet_values[1] << 16) |
            (octet_values[2] << 8)  |
            octet_values[3]
        )

        #Special case if all zeros 
        if mask_32bit_int == 0 or mask_32bit_int == 0xFFFFFFFF:
            return True


        inverted_32bit_int = (~mask_32bit_int) & 0xFFFFFFFF
        #Take the fliped 32bit int, and check for all consecutive 1's,
        #meaning its a legit subnetmask.
        if (inverted_32bit_int & (inverted_32bit_int + 1)) == 0:
            return True
        else:
            return False
    except (ValueError, AttributeError):
        return False


def get_network_prefix(ip: str, subnetmask: str) -> str:
    network = ipaddress.IPv4Network(f"{ip}/{subnetmask}", strict=False)

    network_address = network.network_address
    prefix_length = network.prefixlen
    #print(network_address, prefix_length)

    return str(network_address), str(prefix_length)


def get_active_hosts(ip: str, prefix: str) -> list[str]:
    active_hosts = []
    network_cidr = f"{ip}/{prefix}"
    #print(network_cidr)
    try:
        #if network.version == 4 and network.prefixlen >= 24:
        arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr)
        #print("send packet arp")
        responses, _ = srp(arp, timeout=IP_SCAN_CONFIG["timeout"], verbose=IP_SCAN_CONFIG["verbose"])
        for sent, received in responses:
            if received.haslayer(ARP):
                ip_address = received.psrc
                mac_address = received.hwsrc
                active_hosts.append(ip_address)
                if VERBOSE:
                    print(f"Active host: {ip_address}")
            
    except Exception as e:
        print(f"Host discovery error: {e}")

    return list(set(active_hosts))


"""
        #external ip discovery with icmp
        else:
            icmp_packet = IP(dst=network_cidr) / ICMP()
            response = sr(icmp_packet, 
                        timeout=IP_SCAN_CONFIG["timeout"], 
                        verbose=IP_SCAN_CONFIG["verbose"], 
                        retry=IP_SCAN_CONFIG["retries"])[0]

            for sent, received in response:
                ip_address = received.src
                active_hosts.append(ip_address)
"""
    
#check if ip is local
def get_target_mac(ip: str) -> str:
    try:
        network = get_local_network(ip)
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
                    print(f"Could not resolve MAC for {ip}")
                    return None
            return mac
        else:
            #If remote ip provided, get gateway mac, its not neede since we use layer 3 
            #for external ips, but nice to have to funciton always return the right mac
            #incase of future changes
            gateway_ip = conf.route.route("0.0.0.0")[2]
            return getmacbyip(gateway_ip)
        
    except Exception as e:
        print(f"Mac resolution failed: {e}")
        return None


def get_local_network(ip: str) -> ipaddress.IPv4Address:
    #Using scapys routing table to detirmen if ip is local, and then returning ip
    try:
        interface = conf.route.route(ip)[0]
        local_ip = get_if_addr(interface)
        netmask = conf.route.route(ip)[1]
        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
        return network
    except Exception as e:
        print(f"Network detection failed: {e}")
        return None


def tcp_port_scanner_optimized(ips: list[str], ports: list[int]):
    results = {}
    
    def scan_ip(ip):
        start_time = time.perf_counter()
        open_ports = []
        target_mac = get_target_mac(ip)
        network = get_local_network(ip)
        is_local = network and ipaddress.IPv4Address(ip) in network
        if not target_mac:
            return ip, open_ports
        try:
            for port in ports:
                if is_local:
                    syn = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port, flags="S")
                    response = srp(syn, timeout=TCP_SCAN_CONFIG["timeout"], 
                                retry=TCP_SCAN_CONFIG["retries"], 
                                verbose=TCP_SCAN_CONFIG["verbose"])[0]
                    print(f"  Sending SYN packet to {ip}:{port} LOCAL")
                else:
                    syn = IP(dst=ip) / TCP(dport=port, flags="S")
                    response = sr(syn, timeout=TCP_SCAN_CONFIG["timeout"], 
                                retry=TCP_SCAN_CONFIG["retries"], 
                                verbose=TCP_SCAN_CONFIG["verbose"])[0]
                    print(f"  Sending SYN packet to {ip}:{port} LOCAL")
                
                if response:
                    print(f"  Received response for {ip}:{port}")
                    for sent, received in response:
                        if received[TCP].flags == "SA":
                            open_ports.append(port)
                            if is_local:
                                rst = Ether(dst=target_mac) / IP(dst=ip) / TCP(dport=port, flags="R")
                                sendp(rst, verbose=TCP_SCAN_CONFIG["verbose"])
                            else:
                                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                                send(rst, verbose=TCP_SCAN_CONFIG["verbose"])
                            break

                    time.sleep(TCP_SCAN_CONFIG['stealth_delay'])
            duration = time.perf_counter() - start_time
            #print(f"Scan of {ip} took {duration:.2f} seconds.")
            return ip, open_ports, duration
        
        except Exception as e:
            print(f"Error scanning {port} on IP {ip}: {e}")

    durations = {}

    with ThreadPoolExecutor(max_workers=TCP_SCAN_CONFIG['threads']) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ips}
        for future in futures:
            ip, open_ports, duration = future.result()

            results[ip] = (open_ports, duration)
            
    return results


def active_ip_hosts_menu():
    while True:  
        #clear_screen()
        print("\n----Scan for Active Hosts----")
        print("b to go to main menu")
        ip = input(f"Enter your ip: ")
        if ip.lower() == "b":
            break
        if not validate_ip(ip):
            print("\nInvalid ip. Please try again.")
            sleep(2)
            continue
        
        while True:
            subnetmask_prefix = input(f"Enter your subnetmask or prefix (e.g 255.255.255.0 or /24): ").strip()
            #input validate the subnetmask
            if not validate_subnetmask(subnetmask_prefix):
                print("\nInvalid Subnetmask/prefix. Please try again.")
                sleep(2) 
                continue
            else:
                 break
        
        #If the input is a prefix
        if subnetmask_prefix.startswith("/"):
            prefix = subnetmask_prefix[1:] #Removing /
            active_hosts = get_active_hosts(ip=ip, prefix=prefix)
        #If the input is a subnetmask
        else:
            network_address, prefix = get_network_prefix(ip=ip, subnetmask=subnetmask_prefix)
            active_hosts = get_active_hosts(ip=network_address, prefix=prefix)

        #if not active_hosts:
            #print("\nNo active hosts found. Please try again.")
            #input("Press Enter to continue...")
            #continue

        #initializing the index before loop so it resets.
        index = 0
        for index, host in enumerate(active_hosts, start=1):
                print(f"{index}. IP: {host}")
        print(f"\nNr of Active Hosts: {index}")
        user_input = input("\nPress Enter to continue...(b to main menu): ").strip().lower()
        if user_input == "b":
            break


def scan_specific_ip():
    #validates the input and breaks out of the loop if true
    while True:
        target_ip = input(f"\nEnter your ip(b to main menu): ")
        if target_ip.lower() == "b":
            break
        if not validate_ip(target_ip):
            print("\nInvalid ip. Please try again.")
            sleep(2)
            continue
        
        #validates the input and breaks out of the loop if true
        target_ports = input("Enter ports to scan (comma separated) Leave blank for default: ").strip()
        if target_ports:
            while True:
                for port in target_ports:
                    if not validate_port(port):
                        continue
                    print("\nInvalid port(s). Please try again..")
                    sleep(2)
                else:
                    break
        else:
            target_ports = DEFAULT_PORTS
        tcp_scan_result = tcp_port_scanner_optimized(ips=[target_ip], ports=target_ports)
        for ip, (open_ports, durations) in tcp_scan_result.items():
            print(f"\nIP Address: {ip}")
            for port in open_ports:
                print(f"Port: {port} is open")
            print(f"Scan duration: {durations:.2f} seconds")
      

def scan_entire_network():
    while True:  
        #clear_screen()
        ip = input(f"\nEnter your ip(b to main menu): ")
        if ip.lower() == "b":
            break
        if not validate_ip(ip):
            print("\nInvalid ip. Please try again.")
            sleep(2)
            continue
        
        while True:
            subnetmask_prefix = input(f"Enter your subnetmask or prefix (e.g 255.255.255.0 or /24): ").strip()
            #input validate the subnetmask
            if not validate_subnetmask(subnetmask_prefix):
                print("\nInvalid Subnetmask/prefix. Please try again.")
                sleep(2) 
                continue
            else:
                break
        target_ports = input("Enter ports to scan (comma separated) Leave blank for default: ").strip()
        if target_ports:
            while True:
                for port in target_ports:
                    if not validate_port(port):
                        continue
                    print("\nInvalid port(s). Please try again..")
                    sleep(2)
                else:
                    break
        else:
            target_ports = DEFAULT_PORTS

        if subnetmask_prefix.startswith("/"):
            prefix = subnetmask_prefix[1:] #Removing /
            active_hosts = get_active_hosts(ip=ip, prefix=prefix)
        #If the input is a subnetmask
        else:
            network_address, prefix = get_network_prefix(ip=ip, subnetmask=subnetmask_prefix)
            active_hosts = get_active_hosts(ip=network_address, prefix=prefix)
        tcp_scan_result = tcp_port_scanner_optimized(ips=active_hosts, ports=target_ports)
        for ip, (open_ports, durations) in tcp_scan_result.items():
            print(f"\nIP Address: {ip}")
            for port in open_ports:
                print(f"Port: {port} is open")
            print(f"Scan duration: {durations:.2f} seconds")


def tcp_port_scanner_menu():
    while True:
        clear_screen()
        print("\nTCP Port Scanner")
        print("1. Scan a specific IP(s) and port(s)")
        print("2. Scan entire network with port(s)")
        print("3. Back to main menu")
        choice = input("Choose an option: ").strip().lower()
        if choice == "1":
            scan_specific_ip()
        elif choice == "2":
            scan_entire_network()
        elif choice == "3":
            break


def main_menu():
    while True:
        clear_screen()
        print("-----NETWORK SCANNER-----")
        print("1. Scan For active hosts")
        print("2. TCP Scanner")
        print("3. Configs(IN PROGRESS)")
        print("q. quit")
        choice = input("Choose an option: ").strip().lower()
        if choice == "1":
            clear_screen()
            active_ip_hosts_menu()    
        elif choice == "2":
            tcp_port_scanner_menu()    
        elif choice == "3":
            print("NOT AVALIBLE")
            input("press enter to continue....")
        elif choice == "q":
            sys.exit()


if __name__ == "__main__":
    main_menu()
