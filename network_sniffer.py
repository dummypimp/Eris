
"""
Network Sniffer Module
Advanced network analysis with packet capture, SSL/TLS interception,
WiFi scanning, and cellular network information gathering.
"""

import subprocess
import socket
import json
import time
import threading
import re
import os
import ssl
import tempfile
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PacketInfo:
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    length: int
    payload: str = ""

@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str
    frequency: str
    signal_level: str
    encryption: str
    quality: str
    password: str = ""

@dataclass
class CellularInfo:
    carrier: str
    signal_strength: str
    technology: str
    cell_id: str
    location_area_code: str
    mobile_country_code: str
    mobile_network_code: str

class NetworkSniffer:
    def __init__(self):
        self.is_sniffing = False
        self.captured_packets = []
        self.wifi_networks = []
        self.cellular_info = None
        self.ssl_context = None
        self.cert_file = None
        
    def check_root_permissions(self) -> bool:
        """Check if running with root permissions"""
        return os.geteuid() == 0
    
    def install_ssl_cert(self, cert_data: str, cert_name: str = "custom_cert") -> bool:
        """Install SSL certificate for interception"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file:
                cert_file.write(cert_data)
                self.cert_file = cert_file.name
            

            self.ssl_context = ssl.create_default_context()
            self.ssl_context.load_verify_locations(self.cert_file)
            
            logger.info(f"SSL certificate installed: {self.cert_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to install SSL certificate: {e}")
            return False
    
    def capture_packets_tcpdump(self, interface: str = "any", duration: int = 60,
                               packet_filter: str = "") -> List[PacketInfo]:
        """Capture packets using tcpdump"""
        if not self.check_root_permissions():
            logger.warning("Root permissions required for packet capture")
            return []
        
        packets = []
        try:

            cmd = [
                "tcpdump", "-i", interface, "-n", "-tttt", "-l",
                "-c", "1000",
            ]
            
            if packet_filter:
                cmd.append(packet_filter)
            
            logger.info(f"Starting packet capture on interface {interface}")
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, universal_newlines=True
            )
            
            start_time = time.time()
            while time.time() - start_time < duration:
                line = process.stdout.readline()
                if line:
                    packet = self._parse_tcpdump_line(line.strip())
                    if packet:
                        packets.append(packet)
                        self.captured_packets.append(packet)
            
            process.terminate()
            logger.info(f"Captured {len(packets)} packets")
            
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")
        
        return packets
    
    def capture_packets_netcat(self, host: str, port: int, duration: int = 30) -> List[str]:
        """Capture network traffic using netcat"""
        captured_data = []
        try:
            cmd = ["nc", "-l", "-p", str(port)]
            logger.info(f"Starting netcat listener on port {port}")
            
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True
            )
            
            start_time = time.time()
            while time.time() - start_time < duration:
                if process.poll() is not None:
                    break
                

                try:
                    output = process.stdout.readline()
                    if output:
                        captured_data.append(output.strip())
                except:
                    break
            
            process.terminate()
            logger.info(f"Netcat captured {len(captured_data)} lines")
            
        except Exception as e:
            logger.error(f"Netcat capture failed: {e}")
        
        return captured_data
    
    def _parse_tcpdump_line(self, line: str) -> Optional[PacketInfo]:
        """Parse tcpdump output line into PacketInfo"""
        try:


            

            timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
            if not timestamp_match:
                return None
            
            timestamp = timestamp_match.group(1)
            

            ip_pattern = r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)'
            ip_match = re.search(ip_pattern, line)
            
            if not ip_match:
                return None
            
            source_ip = ip_match.group(1)
            source_port = int(ip_match.group(2))
            dest_ip = ip_match.group(3)
            dest_port = int(ip_match.group(4))
            

            protocol = "TCP"
            if "UDP" in line:
                protocol = "UDP"
            elif "ICMP" in line:
                protocol = "ICMP"
            

            length_match = re.search(r'length (\d+)', line)
            length = int(length_match.group(1)) if length_match else 0
            
            return PacketInfo(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                length=length,
                payload=line
            )
            
        except Exception as e:
            logger.error(f"Failed to parse tcpdump line: {e}")
            return None
    
    def scan_wifi_networks(self) -> List[WiFiNetwork]:
        """Scan for available WiFi networks"""
        networks = []
        try:

            result = subprocess.run(
                ["iwlist", "scan"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:

                result = subprocess.run(
                    ["nmcli", "dev", "wifi", "list"],
                    capture_output=True, text=True, timeout=30
                )
            
            networks = self._parse_wifi_scan(result.stdout)
            self.wifi_networks = networks
            logger.info(f"Found {len(networks)} WiFi networks")
            
        except subprocess.TimeoutExpired:
            logger.error("WiFi scan timed out")
        except Exception as e:
            logger.error(f"WiFi scan failed: {e}")
        
        return networks
    
    def _parse_wifi_scan(self, scan_output: str) -> List[WiFiNetwork]:
        """Parse WiFi scan output"""
        networks = []
        try:

            if "Cell" in scan_output:

                cells = re.split(r'Cell \d+', scan_output)
                for cell in cells[1:]:
                    network = self._parse_iwlist_cell(cell)
                    if network:
                        networks.append(network)
            else:

                lines = scan_output.strip().split('\n')
                for line in lines[1:]:
                    network = self._parse_nmcli_line(line)
                    if network:
                        networks.append(network)
        
        except Exception as e:
            logger.error(f"Failed to parse WiFi scan: {e}")
        
        return networks
    
    def _parse_iwlist_cell(self, cell_text: str) -> Optional[WiFiNetwork]:
        """Parse individual cell from iwlist output"""
        try:

            bssid_match = re.search(r'Address: ([0-9A-Fa-f:]{17})', cell_text)
            bssid = bssid_match.group(1) if bssid_match else ""
            

            ssid_match = re.search(r'ESSID:"([^"]*)"', cell_text)
            ssid = ssid_match.group(1) if ssid_match else "Hidden"
            

            freq_match = re.search(r'Frequency:([0-9.]+) GHz', cell_text)
            frequency = freq_match.group(1) + " GHz" if freq_match else ""
            

            signal_match = re.search(r'Signal level=(-?\d+)', cell_text)
            signal_level = signal_match.group(1) + " dBm" if signal_match else ""
            

            encryption = "Open"
            if "WPA" in cell_text:
                encryption = "WPA/WPA2"
            elif "WEP" in cell_text:
                encryption = "WEP"
            

            quality_match = re.search(r'Quality=(\d+/\d+)', cell_text)
            quality = quality_match.group(1) if quality_match else ""
            
            return WiFiNetwork(
                ssid=ssid,
                bssid=bssid,
                frequency=frequency,
                signal_level=signal_level,
                encryption=encryption,
                quality=quality
            )
            
        except Exception as e:
            logger.error(f"Failed to parse WiFi cell: {e}")
            return None
    
    def _parse_nmcli_line(self, line: str) -> Optional[WiFiNetwork]:
        """Parse nmcli WiFi line"""
        try:
            parts = line.split()
            if len(parts) < 6:
                return None
            
            return WiFiNetwork(
                ssid=parts[0] if parts[0] != "--" else "Hidden",
                bssid=parts[1],
                frequency=parts[2],
                signal_level=parts[3],
                encryption=parts[5] if len(parts) > 5 else "Unknown",
                quality=parts[4] if len(parts) > 4 else ""
            )
            
        except Exception as e:
            logger.error(f"Failed to parse nmcli line: {e}")
            return None
    
    def extract_wifi_credentials(self) -> Dict[str, str]:
        """Extract saved WiFi credentials"""
        credentials = {}
        try:

            result = subprocess.run(
                ["nmcli", "-s", "connection", "show"],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                connections = result.stdout.strip().split('\n')
                for connection in connections:
                    if "wifi" in connection.lower():
                        name = connection.split()[0]

                        pwd_result = subprocess.run(
                            ["nmcli", "-s", "-g", "802-11-wireless-security.psk",
                             "connection", "show", name],
                            capture_output=True, text=True
                        )
                        if pwd_result.returncode == 0 and pwd_result.stdout.strip():
                            credentials[name] = pwd_result.stdout.strip()
            

            if os.path.exists("/etc/wpa_supplicant/wpa_supplicant.conf"):
                with open("/etc/wpa_supplicant/wpa_supplicant.conf", 'r') as f:
                    content = f.read()
                    networks = re.findall(
                        r'network=\{[^}]*ssid="([^"]+)"[^}]*psk="([^"]+)"[^}]*\}',
                        content, re.DOTALL
                    )
                    for ssid, psk in networks:
                        credentials[ssid] = psk
            
            logger.info(f"Extracted credentials for {len(credentials)} networks")
            
        except Exception as e:
            logger.error(f"Failed to extract WiFi credentials: {e}")
        
        return credentials
    
    def get_cellular_info(self) -> Optional[CellularInfo]:
        """Gather cellular network information"""
        try:
            cellular_info = {}
            

            commands = [
                (["mmcli", "-L"], self._parse_mmcli_output),
                (["qmicli", "-d", "/dev/cdc-wdm0", "--nas-get-serving-system"],
                 self._parse_qmicli_output),
            ]
            
            for cmd, parser in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        info = parser(result.stdout)
                        if info:
                            cellular_info.update(info)
                            break
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            

            if os.path.exists("/proc/net/cellular"):
                with open("/proc/net/cellular", 'r') as f:
                    content = f.read()
                    cellular_info.update(self._parse_proc_cellular(content))
            
            if cellular_info:
                self.cellular_info = CellularInfo(
                    carrier=cellular_info.get("carrier", "Unknown"),
                    signal_strength=cellular_info.get("signal_strength", "Unknown"),
                    technology=cellular_info.get("technology", "Unknown"),
                    cell_id=cellular_info.get("cell_id", "Unknown"),
                    location_area_code=cellular_info.get("lac", "Unknown"),
                    mobile_country_code=cellular_info.get("mcc", "Unknown"),
                    mobile_network_code=cellular_info.get("mnc", "Unknown")
                )
                
                logger.info("Cellular information gathered successfully")
                return self.cellular_info
            
        except Exception as e:
            logger.error(f"Failed to get cellular info: {e}")
        
        return None
    
    def _parse_mmcli_output(self, output: str) -> Dict[str, str]:
        """Parse mmcli command output"""
        info = {}
        try:

            carrier_match = re.search(r'operator name:\s*(.+)', output)
            if carrier_match:
                info["carrier"] = carrier_match.group(1).strip()
            

            signal_match = re.search(r'signal quality:\s*(\d+)%', output)
            if signal_match:
                info["signal_strength"] = signal_match.group(1) + "%"
            

            tech_match = re.search(r'access technology:\s*(.+)', output)
            if tech_match:
                info["technology"] = tech_match.group(1).strip()
                
        except Exception as e:
            logger.error(f"Failed to parse mmcli output: {e}")
        
        return info
    
    def _parse_qmicli_output(self, output: str) -> Dict[str, str]:
        """Parse qmicli command output"""
        info = {}
        try:

            lines = output.split('\n')
            for line in lines:
                if 'Serving System:' in line:

                    continue
                elif 'MCC:' in line:
                    mcc_match = re.search(r'MCC:\s*(\d+)', line)
                    if mcc_match:
                        info["mcc"] = mcc_match.group(1)
                elif 'MNC:' in line:
                    mnc_match = re.search(r'MNC:\s*(\d+)', line)
                    if mnc_match:
                        info["mnc"] = mnc_match.group(1)
                
        except Exception as e:
            logger.error(f"Failed to parse qmicli output: {e}")
        
        return info
    
    def _parse_proc_cellular(self, content: str) -> Dict[str, str]:
        """Parse /proc/net/cellular content"""
        info = {}
        try:
            lines = content.split('\n')
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key.strip().lower()] = value.strip()
        except Exception as e:
            logger.error(f"Failed to parse proc cellular: {e}")
        
        return info
    
    def intercept_ssl_traffic(self, target_host: str, target_port: int = 443,
                             duration: int = 60) -> List[str]:
        """Intercept SSL/TLS traffic"""
        intercepted_data = []
        
        if not self.ssl_context:
            logger.warning("No SSL context configured. Install certificate first.")
            return intercepted_data
        
        try:

            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.bind(('localhost', 0))
            proxy_port = proxy_socket.getsockname()[1]
            proxy_socket.listen(5)
            
            logger.info(f"SSL proxy listening on port {proxy_port}")
            
            def handle_connection(client_socket, client_addr):
                try:

                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server_socket.connect((target_host, target_port))
                    

                    ssl_server_socket = self.ssl_context.wrap_socket(
                        server_socket, server_hostname=target_host
                    )
                    

                    threading.Thread(
                        target=self._relay_data,
                        args=(client_socket, ssl_server_socket, intercepted_data, "C->S")
                    ).start()
                    
                    threading.Thread(
                        target=self._relay_data,
                        args=(ssl_server_socket, client_socket, intercepted_data, "S->C")
                    ).start()
                    
                except Exception as e:
                    logger.error(f"Connection handling error: {e}")
            

            start_time = time.time()
            proxy_socket.settimeout(1.0)
            
            while time.time() - start_time < duration:
                try:
                    client_socket, client_addr = proxy_socket.accept()
                    threading.Thread(
                        target=handle_connection,
                        args=(client_socket, client_addr)
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Accept error: {e}")
                    break
            
            proxy_socket.close()
            logger.info(f"SSL interception completed. Captured {len(intercepted_data)} exchanges")
            
        except Exception as e:
            logger.error(f"SSL interception failed: {e}")
        
        return intercepted_data
    
    def _relay_data(self, source_socket, dest_socket, data_store, direction):
        """Relay data between sockets and store for analysis"""
        try:
            while True:
                data = source_socket.recv(4096)
                if not data:
                    break
                
                dest_socket.send(data)
                

                timestamp = datetime.now().isoformat()
                data_store.append({
                    'timestamp': timestamp,
                    'direction': direction,
                    'data': data.hex(),
                    'size': len(data)
                })
                
        except Exception as e:
            logger.error(f"Data relay error: {e}")
    
    def export_results(self, filename: str = None) -> str:
        """Export all collected data to JSON"""
        if not filename:
            filename = f"network_analysis_{int(time.time())}.json"
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'captured_packets': [asdict(packet) for packet in self.captured_packets],
            'wifi_networks': [asdict(network) for network in self.wifi_networks],
            'cellular_info': asdict(self.cellular_info) if self.cellular_info else None,
            'total_packets': len(self.captured_packets),
            'total_wifi_networks': len(self.wifi_networks)
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Results exported to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return ""
    
    def cleanup(self):
        """Cleanup resources"""
        if self.cert_file and os.path.exists(self.cert_file):
            os.unlink(self.cert_file)
        
        self.is_sniffing = False
        logger.info("NetworkSniffer cleanup completed")


def main():
    """Example usage of NetworkSniffer"""
    sniffer = NetworkSniffer()
    
    try:
        print("Network Sniffer - Advanced Network Analysis")
        print("=" * 50)
        

        print("\n1. Scanning WiFi networks...")
        wifi_networks = sniffer.scan_wifi_networks()
        for network in wifi_networks[:5]:
            print(f"  SSID: {network.ssid} | Signal: {network.signal_level} | Encryption: {network.encryption}")
        

        print("\n2. Extracting WiFi credentials...")
        credentials = sniffer.extract_wifi_credentials()
        print(f"  Found credentials for {len(credentials)} networks")
        

        print("\n3. Gathering cellular information...")
        cellular_info = sniffer.get_cellular_info()
        if cellular_info:
            print(f"  Carrier: {cellular_info.carrier}")
            print(f"  Technology: {cellular_info.technology}")
            print(f"  Signal: {cellular_info.signal_strength}")
        

        if sniffer.check_root_permissions():
            print("\n4. Capturing packets (10 seconds)...")
            packets = sniffer.capture_packets_tcpdump(duration=10)
            print(f"  Captured {len(packets)} packets")
        else:
            print("\n4. Packet capture skipped (requires root permissions)")
        

        print("\n5. Exporting results...")
        output_file = sniffer.export_results()
        if output_file:
            print(f"  Results saved to: {output_file}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sniffer.cleanup()


if __name__ == "__main__":
    main()
