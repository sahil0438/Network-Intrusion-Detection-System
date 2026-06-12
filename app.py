import os
import threading
import time
from datetime import datetime
from collections import deque, defaultdict
from flask import Flask, render_template, request, jsonify
# Scapy imports - now including IPv6 and ICMPv6
from scapy.all import sniff, IP, TCP, UDP, Raw, Ether, ICMP, DNS, DNSQR, DNSRR, wrpcap, rdpcap, Packet, get_if_list, IPv6
try:
    from scapy.layers.inet6 import ICMPv6
except ImportError:
    # Fallback for older Scapy versions or specific environments
    print("Warning: Could not import ICMPv6 directly. Attempting to import _ICMPv6 from scapy.layers.inet6.")
    from scapy.layers.inet6 import _ICMPv6 as ICMPv6

import socket
import re
import binascii
import traceback
import tempfile
import subprocess
import sys
import platform
import json

# --- Helper function for payload content extraction ---
def get_payload_content(packet, max_len=256):
    content = {"text": "N/A", "hex": "N/A", "raw_bytes": b''}
    if Raw in packet:
        payload_bytes = bytes(packet[Raw])
        content["raw_bytes"] = payload_bytes
        try:
            content["text"] = payload_bytes[:max_len].decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            content["text"] = payload_bytes[:max_len].decode('latin-1', errors='ignore')
        content["hex"] = binascii.hexlify(payload_bytes[:max_len]).decode('ascii')
        if len(payload_bytes) > max_len:
            content["text"] += " (truncated)"
            content["hex"] += "..."
    elif packet.haslayer(DNS):
        dns_layer = packet[DNS]
        content_lines = []
        if dns_layer.qr == 0 and dns_layer.qd and dns_layer.qd.qname: # DNS Query
            qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.') if dns_layer.qd.qname else "N/A"
            content_lines.append(f"DNS Query: {qname}")
            content["raw_bytes"] = dns_layer.qd.qname # Store DNS query name as raw bytes for pattern matching
        if dns_layer.qr == 1 and dns_layer.an: # DNS Response
            for rr in dns_layer.an:
                rrname = rr.rrname.decode('utf-8', errors='ignore').rstrip('.') if rr.rrname else "N/A"
                rdata = str(rr.rdata) if hasattr(rr, 'rdata') else "N/A"
                content_lines.append(f"DNS Answer: {rrname} -> {rdata}")
        full_dns_content = "\n".join(content_lines)
        content["text"] = full_dns_content[:max_len]
        if len(full_dns_content) > max_len:
            content["text"] += " (truncated)"
        content["hex"] = "N/A (DNS details in text)" # Hex not relevant for DNS summary
    return content

# --- IP Address Type Check ---
def is_ipv6(ip_address):
    """Checks if a string is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
        return True
    except socket.error:
        return False

# --- Domain Resolution Helper ---
def resolve_domain_to_ips(domain):
    """Resolves a single domain name to its IPv4 and IPv6 addresses."""
    resolved_ips = set()
    try:
        # Use AF_UNSPEC to resolve both IPv4 and IPv6 addresses
        info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC)
        for res in info:
            ip_address = res[4][0]
            resolved_ips.add(ip_address)
    except socket.gaierror:
        pass # Domain not found or other resolution error
    return resolved_ips

# --- IPTables/Windows Firewall Management Functions ---
def apply_iptables_block(ip, direction):
    """
    Applies a firewall rule to drop traffic for a specific IP.
    Requires root/administrator privileges.
    Direction can be 'INPUT' (for source IPs) or 'OUTPUT' (for destination IPs).
    """
    if direction not in ['INPUT', 'OUTPUT']:
        print(f"[-] Invalid direction '{direction}' for firewall block.")
        return False
    
    try:
        current_os = platform.system()
        is_ip6 = is_ipv6(ip)

        if current_os == "Linux":
            if is_ip6:
                cmd_tool = 'ip6tables'
                chain = 'INPUT' if direction == 'INPUT' else 'OUTPUT'
                cmd = [cmd_tool, '-A', chain, '-d' if direction == 'OUTPUT' else '-s', ip, '-j', 'DROP']
            else:
                cmd_tool = 'iptables'
                chain = 'INPUT' if direction == 'INPUT' else 'OUTPUT'
                cmd = [cmd_tool, '-A', chain, '-d' if direction == 'OUTPUT' else '-s', ip, '-j', 'DROP']
        elif current_os == "Windows":
            # For Windows, netsh advfirewall supports both IPv4 and IPv6 with the same syntax.
            # Create a unique rule name to allow specific deletion later.
            # Replace non-alphanumeric chars for rule naming, especially colons in IPv6
            safe_ip = ip.replace(':', '_').replace('.', '_')
            rule_name = f"PacketSnifferIDS_Block_{safe_ip}_{direction}"
            
            if direction == 'OUTPUT':
                cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name='+rule_name, 'dir=out', 'action=block', f'remoteip={ip}']
            elif direction == 'INPUT':
                 # Inbound blocking is generally more complex for dynamic rules with netsh.
                 # For simplicity in this app, we'll primarily support outbound blocking.
                 print(f"[-] Warning: Dynamic INPUT blocking for {ip} is not fully supported on Windows with simple netsh rules.")
                 return False
            else:
                 print(f"[-] Invalid direction '{direction}' for Windows netsh block.")
                 return False
        else:
            print(f"[-] Blocking not supported on current OS: {current_os}")
            return False

        print(f"[*] Applying firewall rule: {' '.join(cmd)}")
        # Use CREATE_NO_WINDOW for Windows to prevent a console window from popping up
        creationflags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=creationflags)
        ACTIVE_BLOCKED_IPS.add(ip) # Track successfully applied blocks
        print(f"[+] Successfully blocked {ip} (Direction: {direction})")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Error applying firewall rule for {ip}: {e.stderr.decode()}")
        if current_os == "Linux":
            print(f"    Note: This application must be run with 'sudo' to manage {cmd_tool}.")
        elif current_os == "Windows":
            print("    Note: This application must be run as 'Administrator' to manage Windows Firewall.")
        return False
    except FileNotFoundError:
        print(f"[-] Error: '{cmd_tool if current_os == 'Linux' else 'netsh'}' command not found. Ensure it's installed and in your PATH.")
        return False
    except Exception as e:
        print(f"[-] Unexpected error applying block for {ip}: {e}")
        return False

def apply_all_configured_blocks():
    """Applies all IPs and resolved domains from the BLOCKED sets to iptables/Windows Firewall."""
    global ACTIVE_BLOCKED_IPS
    print("[*] Starting firewall configuration based on block lists.")
    
    # Block Source IPs (INPUT chain for Linux, less direct for Windows)
    for ip in BLOCKED_SOURCE_IPS:
        if platform.system() == "Linux":
            apply_iptables_block(ip, 'INPUT')
        else: # For Windows, we'll just log a note for source IP blocking as it's more complex
            print(f"[*] Note: Source IP blocking for {ip} is configured but will only apply to outbound traffic on Windows for simplicity.")

    # Block Destination IPs (OUTPUT chain)
    for ip in BLOCKED_DEST_IPS:
        apply_iptables_block(ip, 'OUTPUT')
    
    # Block Resolved Domain IPs (OUTPUT chain)
    for ip in BLOCKED_DOMAIN_IPS:
        apply_iptables_block(ip, 'OUTPUT')

def clear_iptables_blocks():
    """Attempts to remove all blocks applied by this script."""
    global ACTIVE_BLOCKED_IPS
    print("[*] Attempting to clear active firewall blocks applied by this session.")
    
    success_count = 0
    
    ips_to_clear = list(ACTIVE_BLOCKED_IPS) # Create a copy as we modify ACTIVE_BLOCKED_IPS
    current_os = platform.system()

    for ip in ips_to_clear:
        is_ip6 = is_ipv6(ip)
        if current_os == "Linux":
            cmd_tool = 'ip6tables' if is_ip6 else 'iptables'
            # Try to delete from INPUT chain
            try:
                subprocess.run([cmd_tool, '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW if current_os == "Windows" else 0)
                print(f"[+] Removed block from {cmd_tool} INPUT chain for {ip}")
                ACTIVE_BLOCKED_IPS.discard(ip) # Remove from active set
                success_count += 1
            except subprocess.CalledProcessError:
                pass # Rule wasn't in INPUT chain, ignore
                
            # Try to delete from OUTPUT chain
            try:
                subprocess.run([cmd_tool, '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW if current_os == "Windows" else 0)
                print(f"[+] Removed block from {cmd_tool} OUTPUT chain for {ip}")
                ACTIVE_BLOCKED_IPS.discard(ip) # Remove from active set
                success_count += 1
            except subprocess.CalledProcessError:
                pass # Rule wasn't in OUTPUT chain, ignore
        elif current_os == "Windows":
            # Delete outbound rule
            try:
                safe_ip = ip.replace(':', '_').replace('.', '_')
                rule_name_out = f"PacketSnifferIDS_Block_{safe_ip}_OUTPUT"
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name='+rule_name_out], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
                print(f"[+] Removed outbound block for {ip} on Windows.")
                ACTIVE_BLOCKED_IPS.discard(ip)
                success_count += 1
            except subprocess.CalledProcessError:
                pass # Rule not found or error, ignore

    if success_count > 0:
        print("[*] Finished clearing firewall rules.")
    else:
        print("[*] No firewall rules were cleared (or none were applied by this script).")
    
    # Ensure ACTIVE_BLOCKED_IPS is truly clean if some rules failed to delete
    ACTIVE_BLOCKED_IPS.clear()


# --- Packet Processing Function ---
def process_packet(packet):
    """
    Extracts relevant information from a Scapy packet, flags targeted and
    intrusion packets, and stores flagged details and the packet itself.
    Also logs if the packet matches a dynamically blocked IP.
    Handles both IPv4 and IPv6.
    """
    packet_info = {
        "timestamp": datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')[:-3],
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "N/A", # Will store name instead of number
        "length": len(packet),
        "summary": packet.summary(),
        "raw_payload": "N/A",
        "is_targeted_flagged": False,
        "targeted_reasons": [],
        "is_intrusion_flagged": False,
        "intrusion_reasons": []
    }

    global captured_packets_data, logged_flagged_packets, flagged_pcap_packets
    global ip_port_counts, ip_last_seen, dns_query_counts, dns_last_query_time
    global BLOCKED_SOURCE_IPS, BLOCKED_DEST_IPS, BLOCKED_DOMAINS, BLOCKED_DOMAIN_IPS

    try:
        current_time = time.time()
        packet_content = get_payload_content(packet)
        packet_info["raw_payload"] = packet_content["text"]

        # Determine IP layer (IPv4 or IPv6)
        ip_layer = None
        if IP in packet:
            ip_layer = packet[IP]
            packet_info["src_ip"] = ip_layer.src
            packet_info["dst_ip"] = ip_layer.dst
            # Protocol mapping for IPv4
            if ip_layer.proto == 6:
                packet_info["protocol"] = "TCP"
            elif ip_layer.proto == 17:
                packet_info["protocol"] = "UDP"
            elif ip_layer.proto == 1:
                packet_info["protocol"] = "ICMP"
            else:
                packet_info["protocol"] = f"IPv4:{ip_layer.proto}"
        elif IPv6 in packet:
            ip_layer = packet[IPv6]
            packet_info["src_ip"] = ip_layer.src
            packet_info["dst_ip"] = ip_layer.dst
            # Protocol mapping for IPv6 Next Header
            if ip_layer.nh == 6:
                packet_info["protocol"] = "TCP"
            elif ip_layer.nh == 17:
                packet_info["protocol"] = "UDP"
            elif ip_layer.nh == 58: # ICMPv6
                packet_info["protocol"] = "ICMPv6"
            else:
                packet_info["protocol"] = f"IPv6:{ip_layer.nh}"
        
        # If no IP layer, skip IP-dependent checks
        if ip_layer:
            src_ip = packet_info["src_ip"]
            dst_ip = packet_info["dst_ip"]

            # --- Check against Active Block Lists ---
            if src_ip in BLOCKED_SOURCE_IPS:
                packet_info["is_intrusion_flagged"] = True
                packet_info["intrusion_reasons"].append(f"Blocked Source IP ({src_ip}) detected in traffic.")
            
            if dst_ip in BLOCKED_DEST_IPS or dst_ip in BLOCKED_DOMAIN_IPS:
                packet_info["is_intrusion_flagged"] = True
                packet_info["intrusion_reasons"].append(f"Traffic directed to Blocked Destination IP ({dst_ip}).")
            
            # --- Targeted Domain Flagging Logic (integrated DNS checks) ---
            try:
                global target_domain_ips, target_domain_names

                if target_domain_ips:
                    if src_ip in target_domain_ips:
                        packet_info["is_targeted_flagged"] = True
                        packet_info["targeted_reasons"].append(f"Source IP ({src_ip}) matches a targeted domain's resolved IP.")
                    if dst_ip in target_domain_ips:
                        packet_info["is_targeted_flagged"] = True
                        reason = f"Destination IP ({dst_ip}) matches a targeted domain's resolved IP."
                        if reason not in packet_info["targeted_reasons"]:
                            packet_info["targeted_reasons"].append(reason)

                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    if dns_layer.qr == 0 and dns_layer.qd and dns_layer.qd.qname:
                        queried_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        # Check for targeted domains and blocked domains
                        for domain in target_domain_names | BLOCKED_DOMAINS:
                            if re.search(r'\b' + re.escape(domain) + r'\b', queried_name, re.IGNORECASE):
                                packet_info["is_targeted_flagged"] = True
                                reason = f"DNS query for '{queried_name}' (related to '{domain}')."
                                if reason not in packet_info["targeted_reasons"]:
                                    packet_info["targeted_reasons"].append(reason)
                                if domain in BLOCKED_DOMAINS:
                                     packet_info["is_intrusion_flagged"] = True
                                     packet_info["intrusion_reasons"].append(f"DNS query to blocked domain '{domain}'.")

                        # Behavioral/Metadata DNS checks (Long queries, TLDs, frequency)
                        for tld in METADATA_THRESHOLDS["dns_suspicious_tld"]:
                            if queried_name.lower().endswith(tld.decode('utf-8')):
                                packet_info["is_intrusion_flagged"] = True
                                reason = f"Suspicious DNS TLD '{tld.decode('utf-8')}' in query for '{queried_name}'."
                                if reason not in packet_info["intrusion_reasons"]:
                                    packet_info["intrusion_reasons"].append(reason)

                        if len(queried_name) > METADATA_THRESHOLDS["dns_long_query"]:
                            packet_info["is_intrusion_flagged"] = True
                            reason = f"Suspiciously long DNS query ({len(queried_name)} chars) for '{queried_name}'."
                            if reason not in packet_info["intrusion_reasons"]:
                                packet_info["intrusion_reasons"].append(reason)

                        # DNS query frequency detection (simple)
                        dns_query_counts[src_ip][queried_name] += 1
                        if (current_time - dns_last_query_time[src_ip]) < METADATA_THRESHOLDS["dns_query_time_window_sec"]:
                            if dns_query_counts[src_ip][queried_name] > METADATA_THRESHOLDS["dns_many_queries_same_domain"]:
                                packet_info["is_intrusion_flagged"] = True
                                reason = f"High frequency DNS queries for '{queried_name}' from {src_ip}."
                                if reason not in packet_info["intrusion_reasons"]:
                                    packet_info["intrusion_reasons"].append(reason)
                        else:
                            dns_query_counts[src_ip].clear()
                        dns_last_query_time[src_ip] = current_time


                    if dns_layer.qr == 1 and dns_layer.an:
                        for ans in dns_layer.an:
                            # A record (IPv4) or AAAA record (IPv6)
                            if ans.type == 1 or ans.type == 28: 
                                response_ip = str(ans.rdata)
                                response_name = ans.rrname.decode('utf-8', errors='ignore').rstrip('.')

                                # Targeted IP match in DNS response
                                if target_domain_ips and response_ip in target_domain_ips:
                                    packet_info["is_targeted_flagged"] = True
                                    reason = f"DNS response for '{response_name}' resolves to targeted IP ({response_ip})."
                                    if reason not in packet_info["targeted_reasons"]:
                                        packet_info["targeted_reasons"].append(reason)

                                # Targeted Domain name match in DNS response
                                for domain in target_domain_names:
                                    if re.search(r'\b' + re.escape(domain) + r'\b', response_name, re.IGNORECASE):
                                        packet_info["is_targeted_flagged"] = True
                                        reason = f"DNS response for domain '{response_name}' (related to targeted domain '{domain}')."
                                        if reason not in packet_info["targeted_reasons"]:
                                            packet_info["targeted_reasons"].append(reason)
                                        break

            except Exception as e:
                print(f"!!! Error in TARGETED/DNS flagging for packet ({packet.summary()}): {e}")
                traceback.print_exc()

            # --- Intrusion Detection Logic (Signature and Metadata) ---
            try:
                # 1. Pattern-based detection (on raw bytes payload)
                raw_payload_bytes = packet_content["raw_bytes"]
                if raw_payload_bytes:
                    for pattern in DETECTION_PATTERNS:
                        if pattern.search(raw_payload_bytes):
                            packet_info["is_intrusion_flagged"] = True
                            reason = f"Pattern match: '{pattern.pattern.decode(errors='ignore')}' found in raw payload."
                            if reason not in packet_info["intrusion_reasons"]:
                                packet_info["intrusion_reasons"].append(reason)

                # 2. Keyword-based detection (on text payload)
                text_payload = packet_content["text"].lower()
                if text_payload != "n/a":
                    for keyword in DETECTION_KEYWORDS:
                        if keyword in text_payload:
                            packet_info["is_intrusion_flagged"] = True
                            reason = f"Keyword match: '{keyword}' found in text payload."
                            if reason not in packet_info["intrusion_reasons"]:
                                packet_info["intrusion_reasons"].append(reason)

                # 3. Metadata-based detection (on IP, TCP, UDP, ICMP/ICMPv6 headers)
                # IP Length check (applies to both IPv4 and IPv6 length fields)
                if ip_layer.len > METADATA_THRESHOLDS["max_ip_len"]:
                    packet_info["is_intrusion_flagged"] = True
                    reason = f"Suspiciously large IP packet length ({ip_layer.len} > {METADATA_THRESHOLDS['max_ip_len']})."
                    if reason not in packet_info["intrusion_reasons"]:
                        packet_info["intrusion_reasons"].append(reason)
                elif ip_layer.len < METADATA_THRESHOLDS["min_ip_len_unusual"]:
                     packet_info["is_intrusion_flagged"] = True
                     reason = f"Suspiciously small IP packet length ({ip_layer.len} < {METADATA_THRESHOLDS['min_ip_len_unusual']})."
                     if reason not in packet_info["intrusion_reasons"]:
                         packet_info["intrusion_reasons"].append(reason)

                # TTL/Hop Limit check
                ttl_or_hlim = ip_layer.ttl if IP in packet else ip_layer.hlim # 'hlim' for IPv6
                if ttl_or_hlim <= METADATA_THRESHOLDS["suspicious_ttl_min"]:
                    packet_info["is_intrusion_flagged"] = True
                    reason = f"Suspiciously low IP TTL/Hop Limit ({ttl_or_hlim} <= {METADATA_THRESHOLDS['suspicious_ttl_min']})."
                    if reason not in packet_info["intrusion_reasons"]:
                        packet_info["intrusion_reasons"].append(reason)
                # Check for zero TTL/Hop Limit
                if METADATA_THRESHOLDS["zero_ttl"] and ttl_or_hlim == 0:
                    packet_info["is_intrusion_flagged"] = True
                    reason = "IP TTL/Hop Limit is 0 (often seen in malformed packets or evasion attempts)."
                    if reason not in packet_info["intrusion_reasons"]:
                        packet_info["intrusion_reasons"].append(reason)

                if TCP in packet:
                    tcp_flags = packet[TCP].flags
                    
                    # TCP Flags check (Xmas Scan: URG, PSH, FIN all set; ACK, SYN, RST not set)
                    if METADATA_THRESHOLDS["suspicious_tcp_flags_xmas"] and \
                       'U' in tcp_flags and 'P' in tcp_flags and 'F' in tcp_flags and \
                       not ('A' in tcp_flags or 'S' in tcp_flags or 'R' in tcp_flags):
                        packet_info["is_intrusion_flagged"] = True
                        reason = "Intrusion: Xmas Scan detected (URG, PSH, FIN flags set, others not)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

                    # TCP Flags check (Null Scan: No flags set)
                    if METADATA_THRESHOLDS["suspicious_tcp_flags_null"] and \
                       not tcp_flags: # If flags string is empty
                        packet_info["is_intrusion_flagged"] = True
                        reason = "Intrusion: Null Scan detected (no TCP flags set)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

                    # TCP Flags check (FIN Scan: Only FIN set)
                    if METADATA_THRESHOLDS["suspicious_tcp_flags_fin_only"] and \
                       tcp_flags == 'F':
                        packet_info["is_intrusion_flagged"] = True
                        reason = "Intrusion: FIN Scan detected (only FIN flag set)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

                    # TCP Flags check (SYN and FIN together)
                    if METADATA_THRESHOLDS["suspicious_tcp_flags_syn_fin"] and \
                       'S' in tcp_flags and 'F' in tcp_flags:
                        packet_info["is_intrusion_flagged"] = True
                        reason = "Intrusion: SYN and FIN flags set (unusual TCP behavior/stealth scan)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)
                    
                    # TCP Flags check (FIN, PSH, URG together)
                    if METADATA_THRESHOLDS["suspicious_tcp_flags_fin_psh_urg"] and \
                       'F' in tcp_flags and 'P' in tcp_flags and 'U' in tcp_flags:
                        packet_info["is_intrusion_flagged"] = True
                        reason = "Intrusion: FIN, PSH, URG flags set (common for some stealth scans)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

                    # Simple Port Scan Detection (stateful)
                    if packet.haslayer(TCP) and packet[TCP].sport and packet[TCP].dport:
                        ip_port_counts[src_ip][packet[TCP].dport] += 1
                        # If more unique destination ports than threshold within time window
                        if (current_time - ip_last_seen[src_ip]) < METADATA_THRESHOLDS["port_scan_time_window_sec"]:
                            if len(ip_port_counts[src_ip]) > METADATA_THRESHOLDS["high_dst_port_count_threshold"]:
                                packet_info["is_intrusion_flagged"] = True
                                reason = f"Potential port scan from {src_ip} (hits {len(ip_port_counts[src_ip])} unique ports)."
                                if reason not in packet_info["intrusion_reasons"]:
                                    packet_info["intrusion_reasons"].append(reason)
                        else:
                            # Reset counts if outside time window
                            ip_port_counts[src_ip].clear()
                        ip_last_seen[src_ip] = current_time # Update last seen time for this IP

                if UDP in packet and Raw in packet:
                    udp_payload_len = len(packet[Raw])
                    if udp_payload_len > METADATA_THRESHOLDS["max_udp_payload_len"]:
                        packet_info["is_intrusion_flagged"] = True
                        reason = f"Suspiciously large UDP payload ({udp_payload_len} bytes) possibly for exfiltration."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)
                
                # ICMP and ICMPv6 checks
                if ICMP in packet:
                    icmp_layer = packet[ICMP]
                    # Large ICMP packets (ping flood / data exfil)
                    if len(packet) > METADATA_THRESHOLDS["icmp_large_size"]:
                        packet_info["is_intrusion_flagged"] = True
                        reason = f"Suspiciously large ICMP packet ({len(packet)} bytes)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)
                    
                    # Fragmentation Needed (Type 3, Code 4) - IPv4 specific
                    if METADATA_THRESHOLDS["icmp_fragmentation_needed"] and \
                       icmp_layer.type == 3 and icmp_layer.code == 4:
                        packet_info["is_intrusion_flagged"] = True
                        reason = "ICMP 'Destination Unreachable - Fragmentation Needed' (Type 3, Code 4) detected. Can be used for path MTU discovery in attacks."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

                    # ICMP Redirect (Type 5) - IPv4 specific
                    if METADATA_THRESHOLDS["icmp_redirect"] and icmp_layer.type == 5:
                        packet_info["is_intrusion_flagged"] = True
                        reason = "ICMP Redirect (Type 5) detected. Can indicate a malicious actor trying to alter routing."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)
                
                if ICMPv6 in packet:
                    icmpv6_layer = packet[ICMPv6]
                    # Large ICMPv6 packets
                    if len(packet) > METADATA_THRESHOLDS["icmp_large_size"]:
                        packet_info["is_intrusion_flagged"] = True
                        reason = f"Suspiciously large ICMPv6 packet ({len(packet)} bytes)."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)
                    
                    # Packet Too Big (Type 2)
                    if METADATA_THRESHOLDS["icmpv6_packet_too_big"] and icmpv6_layer.type == 2:
                        packet_info["is_intrusion_flagged"] = True
                        reason = "ICMPv6 'Packet Too Big' (Type 2) detected. Could be used in attacks."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

                    # Redirect (Type 137)
                    if METADATA_THRESHOLDS["icmpv6_redirect"] and icmpv6_layer.type == 137:
                        packet_info["is_intrusion_flagged"] = True
                        reason = "ICMPv6 Redirect (Type 137) detected. Can indicate a malicious actor trying to alter routing."
                        if reason not in packet_info["intrusion_reasons"]:
                            packet_info["intrusion_reasons"].append(reason)

            except Exception as e:
                print(f"!!! Error in INTRUSION detection for packet ({packet.summary()}): {e}")
                traceback.print_exc()

        captured_packets_data.append(packet_info)

        if packet_info["is_targeted_flagged"] or packet_info["is_intrusion_flagged"]:
            logged_flagged_packets.append(packet_info)
            flagged_pcap_packets.append(packet)

    except Exception as e:
        print(f"!!! CRITICAL ERROR processing packet ({packet.summary() if 'packet' in locals() else 'unknown packet'}): {e}")
        traceback.print_exc()

# --- Scapy Capture Function (runs in a separate thread) ---
def start_capture_scapy(interface=None, pkt_count=0, BPF_filter=""):
    global is_capturing
    print(f"Starting capture on interface: {interface if interface else 'any'}, filter: '{BPF_filter}'")
    is_capturing = True
    try:
        # This line requires Npcap/WinPcap to be installed on Windows
        sniff(iface=interface, prn=process_packet, store=0, count=pkt_count,
              filter=BPF_filter, stop_filter=lambda x: capture_stop_event.is_set())
    except Exception as e:
        print(f"Error during capture: {e}")
        print("On Windows, live packet capture requires Npcap (or WinPcap) to be installed.")
        print("Please ensure Npcap is installed and running as Administrator/sudo.")
    finally:
        is_capturing = False
        print("Live capture stopped.")

# --- PCAP Analysis Function (runs in a separate thread) ---
def analyze_pcap_file(filepath, domains_input_raw):
    global is_analyzing_pcap, \
                   target_domain_ips, target_domain_names, \
                   captured_packets_data, logged_flagged_packets, flagged_pcap_packets, \
                   ip_port_counts, ip_last_seen, dns_query_counts, dns_last_query_time

    print(f"Starting analysis of PCAP file: {filepath}")
    is_analyzing_pcap = True

    # Clear previous data for a fresh analysis
    target_domain_ips.clear()
    target_domain_names.clear()
    captured_packets_data.clear()
    logged_flagged_packets.clear()
    flagged_pcap_packets.clear()
    ip_port_counts.clear()
    ip_last_seen.clear()
    dns_query_counts.clear()
    dns_last_query_time.clear()
    
    # We also clear BLOCKED lists during PCAP analysis, as PCAP analysis is passive and doesn't apply firewall blocks.
    BLOCKED_SOURCE_IPS.clear()
    BLOCKED_DEST_IPS.clear()
    BLOCKED_DOMAINS.clear()
    BLOCKED_DOMAIN_IPS.clear()

    if domains_input_raw:
        domains_list = [d.strip() for d in re.split(r'[,\n]', domains_input_raw) if d.strip()]
        resolved_count = 0
        failed_domains = []
        for domain in set(domains_list):
            target_domain_names.add(domain)
            resolved_ips_for_domain = resolve_domain_to_ips(domain)
            if resolved_ips_for_domain:
                target_domain_ips.update(resolved_ips_for_domain)
                resolved_count += 1
            else:
                failed_domains.append(domain)

        print(f"[*] Total target domains to flag: {len(target_domain_names)}, Successfully resolved: {resolved_count}")
        if failed_domains:
            print(f"[-] Failed to resolve IPs for domains during PCAP analysis: {', '.join(failed_domains)}.")

    try:
        packets = rdpcap(filepath)
        print(f"[*] Loaded {len(packets)} packets from {filepath}")
        for i, packet in enumerate(packets):
            if capture_stop_event.is_set():
                print("PCAP analysis stopped by user request.")
                break
            # Ensure packet.time is a float for datetime.fromtimestamp
            if not isinstance(packet.time, (float, int)):
                packet.time = time.time() # Assign current time if missing or malformed
            process_packet(packet)
        print("[*] PCAP analysis complete.")
    except Exception as e:
        print(f"Error during PCAP file analysis: {e}")
        traceback.print_exc()
    finally:
        is_analyzing_pcap = False
        write_flagged_data_to_pcap_file()
        if os.path.exists(filepath):
            os.unlink(filepath)
            print(f"[*] Cleaned up temporary PCAP file: {filepath}")
        print("PCAP analysis finished.")

# --- PCAP File Writing Function ---
def write_flagged_data_to_pcap_file():
    """Writes all collected flagged Scapy packets to a PCAP file."""
    global flagged_pcap_packets, OUTPUT_FLAGGED_PCAP_FILE
    if not flagged_pcap_packets:
        print("[*] No flagged packets to write to PCAP file.")
        return
    try:
        wrpcap(OUTPUT_FLAGGED_PCAP_FILE, flagged_pcap_packets)
        print(f"[+] Flagged packets saved to '{OUTPUT_FLAGGED_PCAP_FILE}'")
    except Exception as e:
        print(f"[-] Error writing flagged packets to PCAP file: {e}")
        traceback.print_exc()


app = Flask(__name__) # Flask app initialization should be after helper functions

# --- Configuration ---
OUTPUT_FLAGGED_PCAP_FILE = "flagged_packets.pcap"

# --- Intrusion Detection Configuration ---
# (DETECTION_PATTERNS and DETECTION_KEYWORDS remain here as they are global constants)
DETECTION_PATTERNS = [
    # ... (your existing patterns) ...
    re.compile(b'(?i)admin:admin'),
    re.compile(b'(?i)root:toor'),
    re.compile(b'(?i)ftp:ftp'),
    re.compile(b'(?i)user:password'),
    re.compile(b'(?i)guest:guest'),
    re.compile(b'(?i)(?:login|user|pass|pwd)=[\'"]?(?:admin|root|test|user)[\'"]?&?(?:password|pass|pwd)=[\'"]?(?:admin|root|test|password)[\'"]?'), # Common param bypass
    re.compile(b'(?i)(?:union all select|union select)'), # More specific SQLi union
    re.compile(b'(?i)\'\\s*or\\s*\'\\s*=\\s*\''), # SQLi 'or' ' = '
    re.compile(b'(?i)or\\s+[0-9]=[0-9]'), # SQLi 1=1
    re.compile(b'(?i)or\\s+true'), # SQLi or true
    re.compile(b'(?i)(?:sleep|waitfor delay)\\s*\\('), # Time-based SQLi
    re.compile(b'(?i)substr\\(|substring\\(|mid\\('), # String manipulation for SQLi
    re.compile(b'(?i)@@version|version\\(\\)'), # Version disclosure via SQLi
    re.compile(b'(?i)load_file\\(|outfile\\(|dumpfile\\('), # SQL file operations
    re.compile(b'(?i)into\\s+(?:outfile|dumpfile)'), # SQL file write
    re.compile(b'(?i)convert\\((?:int|char|varchar|decimal)'), # SQL type conversion injections
    re.compile(b'(?i)sqlmap(?:\\.(?:py|sh|exe))?'), # SQLMap user-agent/signature
    re.compile(b'(?i)nmap\\s+-sV'), # Nmap service detection
    re.compile(b'(?i)nikto'), # Nikto web scanner
    re.compile(b'(?i)wpscan'), # WordPress scanner
    re.compile(b'(?i)dirb|gobuster|ffuf|wfuzz'), # Directory bruteforcing tools
    re.compile(b'(?i)joomscan|drupalscan'), # CMS specific scanners
    re.compile(b'(?i)nessus|openvas|acunetix|burp\\s+suite|zap'), # Common vulnerability scanners/proxies

    # --- Command Injection Patterns ---
    re.compile(b'(?i)(?:\\|\\||\\&\\&|\\;)\\s*(?:cat|ls|pwd|id|whoami|echo|rm|mkdir|nc|python|perl|php|bash|sh|cmd|powershell)'),
    re.compile(b'(?i)\\$\\((?:[a-zA-Z0-9_\\-]+\\s?){1,5}\\)'), # Command substitution $(command)
    re.compile(b'`[^`]{1,50}`'), # Backtick command substitution `command`
    re.compile(b'(?i)phpinfo\\(\\)'), # PHP info disclosure
    re.compile(b'(?i)eval\\s*\\('), # Code evaluation
    re.compile(b'(?i)shell_exec\\s*\\('), # PHP shell execution
    re.compile(b'(?i)system\\s*\\('), # PHP system command execution
    re.compile(b'(?i)passthru\\s*\\('), # PHP passthru command execution
    re.compile(b'(?i)execve\\s*\\('), # C-style execve
    re.compile(b'(?i)Runtime\\.getRuntime\\(\\)\\.exec\\('), # Java command execution
    re.compile(b'(?i)os\\.system\\s*\\('), # Python os.system
    re.compile(b'(?i)open\\(\\|\\s*-\\s*\\)'), # Pipe to shell command

    # --- Path Traversal / Local File Inclusion (LFI) / Remote File Inclusion (RFI) ---
    re.compile(b'(?i)(?:\\.\\./|\\.\\.\\\\){2,}'), # Multiple directory traversals
    re.compile(b'(?i)file:///(?:etc/passwd|windows/win.ini|boot.ini)'), # Absolute path LFI
    re.compile(b'(?i)php://filter/read=convert\\.base64-encode/resource='), # PHP filter LFI
    re.compile(b'(?i)data:text/plain;base64,'), # Base64 encoded data via URL
    re.compile(b'(?i)expect://'), # Expect wrapper for command execution
    re.compile(b'(?i)zip://|phar://'), # Archive wrappers for LFI/deserialization attacks
    re.compile(b'(?i)http://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/(?:.*\\.txt|.*\\.log|.*\\.conf)'), # Simple RFI to IP
    re.compile(b'(?i)(?:passwd|shadow|id_rsa|my.cnf|config\\.inc\\.php)'), # Sensitive file names
    re.compile(b'(?i)/proc/self/environ'), # LFI for environment variables
    re.compile(b'(?i)/WEB-INF/web.xml'), # Java web config

    # --- Cross-Site Scripting (XSS) ---
    re.compile(b'(?i)<script[^>]*>'), # Basic <script> tag
    re.compile(b'(?i)javascript:(?:alert|confirm|prompt|eval|document\\.cookie)'), # Javascript pseudo-protocol
    re.compile(b'(?i)onerror=|onload=|onmouseover=|onfocus=|onclick=|oninput='), # Common event handlers
    re.compile(b'(?i)expression\\(|data:(?:text/html|image/svg\\+xml);base64,'), # CSS/SVG XSS
    re.compile(b'(?i)<!\\[CDATA\\[<svg/onload=alert'), # CDATA XSS
    re.compile(b'(?i)<img\\s+src=["\']x["\']\\s+onerror=["\']'), # Image XSS
    re.compile(b'(?i)&(?:lt|gt);script&(?:lt|gt);/script&(?:lt|gt);'), # HTML encoded XSS

    # --- XML External Entity (XXE) Injection ---
    re.compile(b'(?i)<!DOCTYPE\\s+\\w+\\s+\\[\\s*<!ENTITY\\s+%\\s+\\w+\\s+SYSTEM\\s+[\'"]'), # Standard XXE DTD
    re.compile(b'(?i)file:///(?:etc/passwd|windows/win.ini)'), # XXE to local file
    re.compile(b'(?i)http://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/(?:.*\\.dtd|.*\\.xml)'), # XXE to external DTD

    # --- Serialization/Deserialization Vulnerabilities ---
    re.compile(b'(?i)java\\.io\\.ObjectInputStream'), # Java deserialization
    re.compile(b'(?i)php_serialize'), # PHP serialization functions
    re.compile(b'(?i)__payload__|__wakeup|__destruct'), # PHP magic methods often involved
    re.compile(b'(?i)python(?: pickle| marshal)'), # Python serialization

    # --- Server-Side Request Forgery (SSRF) ---
    re.compile(b'(?i)http://127\\.0\\.0\\.1|http://localhost'), # Localhost access
    re.compile(b'(?i)http://169\\.254\\.169\\.254'), # AWS Metadata Service
    re.compile(b'(?i)dict://|ftp://|gopher://|ldap://'), # Various protocols for SSRF
    re.compile(b'(?i)file:///dev/random'), # Common SSRF target
    re.compile(b'(?i)url=https?:\\/\\/[0-9a-zA-Z\\-.]+'), # 'url' parameter with external URL

    # --- Web Shells / Backdoors / Remote Access Tools ---
    re.compile(b'(?i)nc\\s+-(?:l|L)[vVpP]+'), # Netcat listener
    re.compile(b'(?i)bash\\s+-i\\s+>\\&\\d+>&1'), # Corrected: Reverse shell common pattern (changed \1 to 1)
    re.compile(b'(?i)python\\s+-c\\s+[\'"](?:import|socket|subprocess).*?[\'"]'), # Python reverse shell
    re.compile(b'(?i)powershell\\s+-NoP\\s+-NonI\\s+-W\\s+Hidden\\s+-Exec\\s+Bypass\\s+-e\\s+[a-zA-Z0-9+/=]+'), # Base64 encoded PowerShell
    re.compile(b'(?i)meterpreter|cobaltstrike|empire|sliver|beacon'), # C2/Post-exploitation tools
    re.compile(b'(?i)(?:cmd\\.aspx|shell\\.php| backdoor\\.jsp|r57.php|c99.php)'), # Common web shell names
    re.compile(b'(?i)(?:X-Shell|X-Admin-ID|X-Wget-Client)'), # Custom HTTP headers for shells

    # --- Malware Communication / C2 Indicators ---
    re.compile(b'(?i)c2server|c2\\.php|command\\.php|getconfig\\.php'), # Generic C2 communication
    re.compile(b'(?i)beacon|heartbeat|update_check'), # Beaconing activity
    re.compile(b'(?i)upload_file|download_file|get_file|put_file'), # File transfer commands
    re.compile(b'(?i)execute_cmd|run_cmd|cmd_output'), # Command execution indicators
    re.compile(b'(?i)encrypted_data=|data=[a-zA-Z0-9+/=]+'), # Encoded/encrypted data in cleartext requests
    re.compile(b'(?i)User-Agent:\\s*(?:Mozilla/4.0\\s+\\(compatible;\\s+MSIE\\s+6.0\\)|WinHTTP|libwww-perl|python-requests|Go-http-client)'), # Suspicious User-Agents
    re.compile(b'(?i)(?:\\.exe|\\.dll|\\.bin)\\s*HTTP/(?:1\\.0|1\\.1)\\s+200\\s+OK\\s*Content-Disposition:\\s*attachment'), # Executable download

    # --- Obfuscation / Encoding Indicators ---
    re.compile(b'(?i)%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}'), # Double URL encoding
    re.compile(b'(?i)(?:base64(?:_decode)?|gzinflate|str_rot13|hex2bin)\\s*\\('), # Encoding/decoding functions
    re.compile(b'(?i)(?:document\\.write|innerHTML|eval)\\s*\\(atob\\('), # JS Base64 decoding
    re.compile(b'(?i)(?:\\\\x[0-9a-fA-F]{2}){4,}'), # Hexadecimal encoding in string
    re.compile(b'(?i)%u[0-9a-fA-F]{4}'), # Unicode encoding

    # --- Network Scanning / Reconnaissance ---
    re.compile(b'(?i)Nmap|Nikto|WPScan|Acunetix|BurpSuite|ZAP|Nessus|OpenVAS|Masscan'), # Scanner User-Agents
    re.compile(b'(?i)ZmEu'), # ZmEu scanner
    re.compile(b'(?i)sana-scan'), # Sana Security scanner
    re.compile(b'(?i)masscan|zmap'), # Fast scanning tools
    re.compile(b'(?i)X-Requested-With:\\s*XMLHttpRequest'), # AJAX requests (often used in web scanners)

    # --- Sensitive Data Leakage (Caution: high false positive potential) ---
    re.compile(b'(?i)(?:api_key|secret_key|private_key|aws_access_key_id|aws_secret_access_key|client_secret)\\s*=\\s*[a-zA-Z0-9\\-_]+'),
    re.compile(b'(?i)(?:password|passwd|pwd)[:=][a-zA-Z0-9!@#$%^&*()_+\\-=]{6,50}'),
    re.compile(b'(?i)Bearer\\s+[a-zA-Z0-9\\-_\\.]+'), # OAuth/JWT tokens
    re.compile(b'(?i)Basic\\s+[a-zA-Z0-9+/=]+'), # Basic Auth credentials
    re.compile(b'(?i)credit\\s*card|cc\\s*num|cvv|expiration|expiry'),
    re.compile(b'(?i)social\\s*security\\s*number|ssn'),
    re.compile(b'(?i)bank_account|routing_number'),
    re.compile(b'(?i)-----BEGIN\\s+(?:RSA|DSA|EC)\\s+PRIVATE\\s+KEY-----'), # Private key export
]

DETECTION_KEYWORDS = [
    # ... (your existing keywords) ...
    "exploit", "malware", "shell", "attack", "vulnerable",
    "unauthorized", "inject", "credential", "phishing", "ransom", "cryptolocker",
    "virus", "worm", "trojan", "rootkit", "botnet", "ddos", "zero-day",
    "backdoor", "keylogger", "spyware", "adware", "cnc", "c2", "commandandcontrol",

    # --- SQL Injection Keywords ---
    "sql error", "syntax error", "mysql_fetch", "pg_query", "sqli", "mssql", "postgres",
    "oracle", "union", "select", "from", "where", "and 1=1", "group by", "order by",

    # --- Command Injection Keywords ---
    "cmd.exe", "/bin/bash", "/bin/sh", "cmdline", "systeminfo", "whoami", "id",
    "ifconfig", "ipconfig", "netstat", "route", "tasklist", "ps aux", "cat /etc/passwd",
    "wget", "curl", "certutil", "powershell", "python", "perl", "ruby", "nc",

    # --- File/Directory Access Keywords ---
    "htpasswd", "shadow", "config.php", "web.config", "database.yml",
    "robots.txt", "sitemap.xml", ".git/config", ".env", ".bash_history", ".ssh",
    "id_rsa", "nginx.conf", "apache2.conf", "httpd.conf",

    # --- Web Attack Specifics ---
    "csrf_token", "jwt", "cookie", "referer", "user-agent",
    "xss", "lfi", "rfi", "ssrf", "xxe", "deserialization", "cve", "exploit-db",

    # --- Remote Access / Scanning ---
    "rdp", "ssh", "vnc", "teamviewer", "anydesk", "splashtop",
    "portscan", "reconnaissance", "vulnerability scan", "penetration test",
    "proxy", "tunnel", "vpn", "tor",

    # --- DNS related anomalies (for context-aware detection) ---
    "nxdomain", "servfail", "refused", "dns leak",

    # --- Cloud / Container related ---
    "ec2-metadata", "kube-api", "docker.sock", "kubernetes", "consul", "vault",

    # --- Specific vulnerability mentions (often found in attacks) ---
    "log4j", "struts2", "heartbleed", "shellshock", "wannacry", "notpetya", "eternalblue",

    # --- Suspicious file types in requests/responses ---
    ".exe", ".dll", ".vbs", ".ps1", ".jar", ".zip", ".tar.gz", ".rar", ".7z",
    ".php", ".jsp", ".asp", ".aspx", ".py", ".pl", ".sh", ".bash", ".bat",
]


# --- More Advanced Metadata-based Detection ---
METADATA_THRESHOLDS = {
    # Packet size anomalies
    "max_ip_len": 1500, # Standard MTU for Ethernet (applies to IPv4 and IPv6 effectively)
    "min_ip_len_unusual": 20, # Very small packets might be probes/scans
    "max_udp_payload_len": 1024, # Larger UDP payloads can be suspicious (e.g., DNS exfil)

    # TTL anomalies (indicative of hops, network topology, or evasion)
    "suspicious_ttl_min": 5, # Very low TTL/Hop Limit
    "suspicious_ttl_max_web_server": 64, # Common Linux TTL/Hop Limit (for non-local)
    "suspicious_ttl_max_windows_server": 128, # Common Windows TTL/Hop Limit (for non-local)
    "zero_ttl": True, # Packets with TTL/Hop Limit = 0

    # TCP Flag combinations (stealth scans, malformed packets)
    "suspicious_tcp_flags_xmas": True, # Xmas Scan (URG, PSH, FIN all set, ACK=0, SYN=0, RST=0)
    "suspicious_tcp_flags_null": True, # Null Scan (No flags set)
    "suspicious_tcp_flags_fin_only": True, # FIN scan
    "suspicious_tcp_flags_syn_fin": True, # SYN and FIN set together
    "suspicious_tcp_flags_fin_psh_urg": True, # Another common combination for scans

    # Port scanning indicators (can be noisy, combine with other rules)
    "high_dst_port_count_threshold": 10, # Number of unique destination ports per source IP in a short time
    "high_src_port_count_threshold": 10, # Number of unique source ports per dest IP (for C2/beaconing)
    "port_scan_time_window_sec": 5, # Time window for port scan detection

    # ICMP anomalies (now applies to ICMP and ICMPv6)
    "icmp_large_size": 1024, # Large ICMP/ICMPv6 echo requests/replies (ping floods/data exfil)
    "icmp_fragmentation_needed": True, # ICMP type 3 code 4 (fragmentation needed, can be abused) - IPv4 only
    "icmp_redirect": True, # ICMP type 5 (redirect, can be malicious) - IPv4 only
    "icmpv6_packet_too_big": True, # ICMPv6 Type 2 (Packet Too Big)
    "icmpv6_redirect": True, # ICMPv6 Type 137 (Redirect)

    # DNS anomalies
    "dns_long_query": 100, # Very long DNS query name (DNS tunneling)
    "dns_many_queries_same_domain": 10, # Many queries for subdomains of the same parent in short time
    "dns_query_time_window_sec": 5, # Time window for DNS query frequency
    "dns_suspicious_tld": [b'.onion', b'.bit', b'.lib', b'.i2p'], # Tor/Darknet TLDs
}


# --- Global Variables for Packet Capture and Analysis ---
MAX_PACKETS_DISPLAY = 1000
MAX_LOGGED_PACKETS = 500
captured_packets_data = deque(maxlen=MAX_PACKETS_DISPLAY)
logged_flagged_packets = deque(maxlen=MAX_LOGGED_PACKETS)
flagged_pcap_packets = []
is_capturing = False
is_analyzing_pcap = False
capture_thread = None
pcap_analysis_thread = None
capture_stop_event = threading.Event()

target_domain_ips = set()
target_domain_names = set()

# --- State for behavioral detection ---
ip_port_counts = defaultdict(lambda: defaultdict(int))
ip_last_seen = defaultdict(float)
dns_query_counts = defaultdict(lambda: defaultdict(int))
dns_last_query_time = defaultdict(float)

# --- Blocking Configuration and State ---
BLOCKED_SOURCE_IPS = set()
BLOCKED_DEST_IPS = set()
BLOCKED_DOMAINS = set()
BLOCKED_DOMAIN_IPS = set() # Resolved IPs for BLOCKED_DOMAINS

ACTIVE_BLOCKED_IPS = set() # IPs that have been successfully blocked via firewall


# --- Scapy Capture Function (runs in a separate thread) ---
def start_capture_scapy(interface=None, pkt_count=0, BPF_filter=""):
    global is_capturing
    print(f"Starting capture on interface: {interface if interface else 'any'}, filter: '{BPF_filter}'")
    is_capturing = True
    try:
        # This line requires Npcap/WinPcap to be installed on Windows
        sniff(iface=interface, prn=process_packet, store=0, count=pkt_count,
              filter=BPF_filter, stop_filter=lambda x: capture_stop_event.is_set())
    except Exception as e:
        print(f"Error during capture: {e}")
        print("On Windows, live packet capture requires Npcap (or WinPcap) to be installed.")
        print("Please ensure Npcap is installed and running as Administrator/sudo.")
    finally:
        is_capturing = False
        print("Live capture stopped.")

# --- PCAP Analysis Function (runs in a separate thread) ---
def analyze_pcap_file(filepath, domains_input_raw):
    global is_analyzing_pcap, \
                   target_domain_ips, target_domain_names, \
                   captured_packets_data, logged_flagged_packets, flagged_pcap_packets, \
                   ip_port_counts, ip_last_seen, dns_query_counts, dns_last_query_time

    print(f"Starting analysis of PCAP file: {filepath}")
    is_analyzing_pcap = True

    # Clear previous data for a fresh analysis
    target_domain_ips.clear()
    target_domain_names.clear()
    captured_packets_data.clear()
    logged_flagged_packets.clear()
    flagged_pcap_packets.clear()
    ip_port_counts.clear()
    ip_last_seen.clear()
    dns_query_counts.clear()
    dns_last_query_time.clear()
    
    # We also clear BLOCKED lists during PCAP analysis, as PCAP analysis is passive and doesn't apply firewall blocks.
    BLOCKED_SOURCE_IPS.clear()
    BLOCKED_DEST_IPS.clear()
    BLOCKED_DOMAINS.clear()
    BLOCKED_DOMAIN_IPS.clear()

    if domains_input_raw:
        domains_list = [d.strip() for d in re.split(r'[,\n]', domains_input_raw) if d.strip()]
        resolved_count = 0
        failed_domains = []
        for domain in set(domains_list):
            target_domain_names.add(domain)
            resolved_ips_for_domain = resolve_domain_to_ips(domain)
            if resolved_ips_for_domain:
                target_domain_ips.update(resolved_ips_for_domain)
                resolved_count += 1
            else:
                failed_domains.append(domain)

        print(f"[*] Total target domains to flag: {len(target_domain_names)}, Successfully resolved: {resolved_count}")
        if failed_domains:
            print(f"[-] Failed to resolve IPs for domains during PCAP analysis: {', '.join(failed_domains)}.")

    try:
        packets = rdpcap(filepath)
        print(f"[*] Loaded {len(packets)} packets from {filepath}")
        for i, packet in enumerate(packets):
            if capture_stop_event.is_set():
                print("PCAP analysis stopped by user request.")
                break
            # Ensure packet.time is a float for datetime.fromtimestamp
            if not isinstance(packet.time, (float, int)):
                packet.time = time.time() # Assign current time if missing or malformed
            process_packet(packet)
        print("[*] PCAP analysis complete.")
    except Exception as e:
        print(f"Error during PCAP file analysis: {e}")
        traceback.print_exc()
    finally:
        is_analyzing_pcap = False
        write_flagged_data_to_pcap_file()
        if os.path.exists(filepath):
            os.unlink(filepath)
            print(f"[*] Cleaned up temporary PCAP file: {filepath}")
        print("PCAP analysis finished.")

# --- PCAP File Writing Function ---
def write_flagged_data_to_pcap_file():
    """Writes all collected flagged Scapy packets to a PCAP file."""
    global flagged_pcap_packets, OUTPUT_FLAGGED_PCAP_FILE
    if not flagged_pcap_packets:
        print("[*] No flagged packets to write to PCAP file.")
        return
    try:
        wrpcap(OUTPUT_FLAGGED_PCAP_FILE, flagged_pcap_packets)
        print(f"[+] Flagged packets saved to '{OUTPUT_FLAGGED_PCAP_FILE}'")
    except Exception as e:
        print(f"[-] Error writing flagged packets to PCAP file: {e}")
        traceback.print_exc()


# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_interfaces')
def get_interfaces():
    """
    Returns a list of available network interfaces with user-friendly names.
    On Windows, this version attempts to use PowerShell to get friendly names and GUIDs.
    On Linux/macOS, it falls back to Scapy's get_if_list.
    
    IMPORTANT: This function lists interfaces. For live packet capture, Npcap must still be installed on Windows.
    """
    user_friendly_interfaces = []
    current_os = platform.system()

    if current_os == "Windows":
        try:
            # Use PowerShell to get network adapter information
            # Select Name (friendly), InterfaceDescription, and InterfaceGuid
            ps_cmd = "Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid | ConvertTo-Json"
            # Use creationflags to hide the PowerShell window
            creationflags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, check=True, creationflags=creationflags)
            adapters_info = json.loads(result.stdout)

            for adapter in adapters_info:
                friendly_name = adapter.get('Name') or adapter.get('InterfaceDescription', 'Unknown Adapter')
                guid = adapter.get('InterfaceGuid') # This will be in {GUID} format

                # Scapy's internal representation on Windows is typically \Device\NPF_{GUID}
                # We need to provide this format as the 'name' for Scapy's sniff function.
                scapy_compatible_name = f"\\Device\\NPF_{guid}" if guid else friendly_name # Fallback if no GUID

                user_friendly_interfaces.append({
                    'name': scapy_compatible_name,
                    'display_name': friendly_name
                })
            
            # Note: The "Any" option is handled in the frontend JavaScript for consistency.
            return jsonify(user_friendly_interfaces)

        except subprocess.CalledProcessError as e:
            print(f"[-] Error getting interfaces via PowerShell: {e.stderr.decode()}")
            print("    Ensure PowerShell is available and you have administrative privileges.")
            return jsonify({"error": str(e), "message": "Failed to get interfaces via PowerShell. Run as Administrator."}), 500
        except FileNotFoundError:
            print("[-] Error: 'powershell' command not found. Ensure PowerShell is installed and in your PATH.")
            return jsonify({"error": "PowerShell not found", "message": "PowerShell is required to list interfaces on Windows."}), 500
        except json.JSONDecodeError as e:
            print(f"[-] Error decoding PowerShell JSON output: {e}")
            print(f"    PowerShell output: {result.stdout}")
            return jsonify({"error": "JSON parse error", "message": "Failed to parse PowerShell output for interfaces."}), 500
        except Exception as e:
            print(f"[-] Unexpected error getting interfaces on Windows: {e}")
            traceback.print_exc()
            return jsonify({"error": str(e), "message": "An unexpected error occurred while listing interfaces."}), 500
    else: # For Linux/macOS
        try:
            # On Linux/macOS, get_if_list() usually returns friendly names (e.g., 'eth0', 'wlan0')
            raw_interfaces = get_if_list()
            # For Linux/macOS, we can just return the string names directly.
            # The frontend JavaScript will handle adding the "Any" option and
            # differentiating between string names and {name, display_name} objects.
            return jsonify(raw_interfaces)
        except Exception as e:
            print(f"Error getting interfaces on Linux/macOS: {e}")
            return jsonify({"error": str(e), "message": "Could not retrieve network interfaces. Ensure Scapy is correctly installed and you have necessary permissions (e.g., run with sudo)."}), 500


@app.route('/start_capture', methods=['POST'])
def start_capture():
    global is_capturing, capture_thread, capture_stop_event, \
                   target_domain_ips, target_domain_names, \
                   captured_packets_data, logged_flagged_packets, flagged_pcap_packets, \
                   is_analyzing_pcap, ip_port_counts, ip_last_seen, dns_query_counts, dns_last_query_time

    if is_capturing:
        return jsonify({"status": "already_capturing", "message": "Capture is already active."}), 200
    if is_analyzing_pcap:
        return jsonify({"status": "analysis_in_progress", "message": "PCAP analysis is in progress. Please wait."}), 200

    interface = request.form.get('interface', 'any')
    bpf_filter = request.form.get('filter', '')
    domains_input_raw = request.form.get('domain_filter', '').strip()

    # Clear all data structures for a new capture/analysis session
    captured_packets_data.clear()
    logged_flagged_packets.clear()
    flagged_pcap_packets.clear()
    ip_port_counts.clear()
    ip_last_seen.clear()
    dns_query_counts.clear()
    dns_last_query_time.clear()
    target_domain_ips.clear()
    target_domain_names.clear()

    # Configure Targeted Domains
    if domains_input_raw:
        domains_list = [d.strip() for d in re.split(r'[,\n]', domains_input_raw) if d.strip()]
        resolved_count = 0
        failed_domains = []
        for domain in set(domains_list):
            target_domain_names.add(domain)
            resolved_ips_for_domain = resolve_domain_to_ips(domain)
            if resolved_ips_for_domain:
                target_domain_ips.update(resolved_ips_for_domain)
                resolved_count += 1
            else:
                failed_domains.append(domain)

        print(f"[*] Total target domains to flag: {len(target_domain_names)}, Successfully resolved: {resolved_count}")
        if failed_domains:
            print(f"[-] Failed to resolve IPs for domains: {', '.join(failed_domains)}. Will only be flagged via DNS queries/responses.")

    # Apply firewall rules for existing blocks before starting capture
    apply_all_configured_blocks()

    capture_stop_event.clear()

    capture_thread = threading.Thread(
        target=start_capture_scapy,
        args=(interface, 0, bpf_filter),
        daemon=True
    )
    capture_thread.start()

    return jsonify({"status": "success", "message": "Live capture started successfully."}), 200

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_capturing, capture_stop_event, capture_thread, is_analyzing_pcap, pcap_analysis_thread
    if not is_capturing and not is_analyzing_pcap:
        return jsonify({"status": "not_active", "message": "No active capture or analysis to stop."}), 200

    print("Stopping active operation...")
    capture_stop_event.set()

    if capture_thread and capture_thread.is_alive():
        print("Waiting for live capture thread to finish...")
        capture_thread.join(timeout=5)
        if capture_thread.is_alive():
            print("Warning: Live capture thread did not stop gracefully within timeout.")

    if pcap_analysis_thread and pcap_analysis_thread.is_alive():
        print("Waiting for PCAP analysis thread to finish...")
        pcap_analysis_thread.join(timeout=5)
        if pcap_analysis_thread.is_alive():
            print("Warning: PCAP analysis thread did not stop gracefully within timeout.")
    
    # Write flagged packets and clear firewall blocks (if any were applied)
    write_flagged_data_to_pcap_file()
    clear_iptables_blocks() # Clean up firewall rules

    capture_stop_event.clear()

    return jsonify({"status": "success", "message": "Active operation stopped and firewall rules cleared."}), 200

@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    global is_capturing, is_analyzing_pcap, pcap_analysis_thread, capture_stop_event

    if is_capturing:
        return jsonify({"status": "capture_in_progress", "message": "Live capture is active. Please stop it before uploading a PCAP."}), 400
    if is_analyzing_pcap:
        return jsonify({"status": "analysis_in_progress", "message": "Another PCAP analysis is in progress. Please wait."}), 400

    if 'pcap_file' not in request.files:
        return jsonify({"status": "error", "message": "No file part in the request."}), 400

    file = request.files['pcap_file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file."}), 400

    if not file.filename.lower().endswith('.pcap') and not file.filename.lower().endswith('.pcapng'):
        return jsonify({"status": "error", "message": "Invalid file type. Please upload a .pcap or .pcapng file."}), 400

    domains_input_raw = request.form.get('domain_filter', '').strip()
    
    # We clear the active blocks, as PCAP analysis is passive
    clear_iptables_blocks() 

    temp_filepath = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as temp_file_obj:
            file.save(temp_file_obj.name)
            temp_filepath = temp_file_obj.name

        capture_stop_event.clear()

        pcap_analysis_thread = threading.Thread(
            target=analyze_pcap_file,
            args=(temp_filepath, domains_input_raw),
            daemon=True
        )
        pcap_analysis_thread.start()

        return jsonify({"status": "success", "message": f"PCAP file '{file.filename}' uploaded and analysis started. Results will appear shortly."}), 202
    except Exception as e:
        print(f"Error handling PCAP upload: {e}")
        traceback.print_exc()
        if temp_filepath and os.path.exists(temp_filepath):
            os.unlink(temp_filepath)
            print(f"[*] Cleaned up failed temporary PCAP file: {temp_filepath}")
        return jsonify({"status": "error", "message": f"Failed to process PCAP file: {e}"}), 500

@app.route('/manage_blocks', methods=['POST'])
def manage_blocks():
    """Route to receive and configure IPs and domains for blocking."""
    global BLOCKED_SOURCE_IPS, BLOCKED_DEST_IPS, BLOCKED_DOMAINS, BLOCKED_DOMAIN_IPS

    # Clear current blocks first (this is for the configuration lists, not firewall)
    BLOCKED_SOURCE_IPS.clear()
    BLOCKED_DEST_IPS.clear()
    BLOCKED_DOMAINS.clear()
    BLOCKED_DOMAIN_IPS.clear()

    # Parse Source IPs to Block
    source_ips_raw = request.form.get('source_ips_block', '').strip()
    if source_ips_raw:
        BLOCKED_SOURCE_IPS.update(
            [ip.strip() for ip in re.split(r'[,\n]', source_ips_raw) if ip.strip()]
        )
    
    # Parse Destination IPs to Block
    dest_ips_raw = request.form.get('dest_ips_block', '').strip()
    if dest_ips_raw:
        BLOCKED_DEST_IPS.update(
            [ip.strip() for ip in re.split(r'[,\n]', dest_ips_raw) if ip.strip()]
        )

    # Parse Domains to Block and Resolve them
    domains_raw = request.form.get('domains_block', '').strip()
    resolved_count = 0
    failed_domains = []
    if domains_raw:
        domains_list = [d.strip() for d in re.split(r'[,\n]', domains_raw) if d.strip()]
        for domain in set(domains_list):
            BLOCKED_DOMAINS.add(domain)
            resolved_ips = resolve_domain_to_ips(domain) # This now resolves both IPv4 and IPv6
            if resolved_ips:
                BLOCKED_DOMAIN_IPS.update(resolved_ips)
                resolved_count += 1
            else:
                failed_domains.append(domain)
    
    print(f"[*] Block Configuration Updated:")
    print(f"    Source IPs: {len(BLOCKED_SOURCE_IPS)}")
    print(f"    Destination IPs: {len(BLOCKED_DEST_IPS)}")
    print(f"    Domains: {len(BLOCKED_DOMAINS)} (Resolved {resolved_count} to IPs)")
    if failed_domains:
        print(f"    Warning: Failed to resolve domains: {', '.join(failed_domains)}")

    # If a live capture is active, immediately apply the new firewall rules.
    if is_capturing:
        clear_iptables_blocks() # Clear old rules before applying new ones
        apply_all_configured_blocks()
        return jsonify({"status": "success", "message": "Block lists updated and applied to active capture.", "applied": True}), 200
    
    return jsonify({"status": "success", "message": "Block lists updated. Start a capture to apply firewall rules.", "applied": False}), 200

@app.route('/get_blocks_status')
def get_blocks_status():
    """Returns the current configuration of blocked IPs and domains."""
    return jsonify({
        "source_ips_configured": list(BLOCKED_SOURCE_IPS),
        "dest_ips_configured": list(BLOCKED_DEST_IPS),
        "domains_configured": list(BLOCKED_DOMAINS),
        "resolved_domain_ips": list(BLOCKED_DOMAIN_IPS),
        "active_iptables_blocks": list(ACTIVE_BLOCKED_IPS),
    })

@app.route('/clear_packets', methods=['POST'])
def clear_packets():
    """Clears the captured packets data from the display buffer and behavioral state."""
    global captured_packets_data, logged_flagged_packets, flagged_pcap_packets, \
           ip_port_counts, ip_last_seen, dns_query_counts, dns_last_query_time
    captured_packets_data.clear()
    logged_flagged_packets.clear()
    flagged_pcap_packets.clear()
    ip_port_counts.clear()
    ip_last_seen.clear()
    dns_query_counts.clear()
    dns_last_query_time.clear()
    print("[*] All captured/analyzed packet data cleared from display and export buffer.")
    return jsonify({"status": "success", "message": "All packet data cleared."}), 200

# NEW ROUTE: To get only flagged packets for a separate log display
@app.route('/get_flagged_packets')
def get_flagged_packets():
    """Returns only the captured packets that were flagged as targeted or intrusion."""
    return jsonify(list(logged_flagged_packets))

@app.route('/get_packets')
def get_packets():
    # Return the currently captured packets for display in the UI
    return jsonify(list(captured_packets_data))

@app.route('/get_status')
def get_status():
    # Return the current capture status
    return jsonify({
        "is_capturing": is_capturing,
        "is_analyzing_pcap": is_analyzing_pcap
    })

if __name__ == '__main__':
    # Determine the operating system
    current_os = platform.system()

    # Important warning for running with root/administrator privileges
    if current_os == "Linux":
        print("WARNING: You must run this Flask app with sudo for packet capture privileges AND to manage iptables/ip6tables blocks.")
        print("Example: sudo python3 app.py")
        if os.getuid() != 0:
            print("\nERROR: Not running as root. Live capture and blocking functionality will not work.")
    elif current_os == "Windows":
        print("WARNING: You must run this Flask app as Administrator for packet capture privileges AND to manage Windows Firewall rules.")
        print("WARNING: Live packet capture on Windows also requires Npcap (or WinPcap) to be installed.")
        print("Example (from Administrator Command Prompt/PowerShell): python app.py")
        # A direct programmatic check for Windows Administrator privileges is more complex in Python.
        # We rely on the user running it correctly and the subprocess calls failing if privileges are insufficient.
    else:
        print(f"WARNING: Running on unsupported OS: {current_os}. Packet capture and blocking may not work as expected.")
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)

