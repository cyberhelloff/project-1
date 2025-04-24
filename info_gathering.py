import socket
import whois
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

class InfoGatherer:
    def __init__(self, target, logger):
        self.target = target
        self.logger = logger
        self.results = {}

    def gather_info(self):
        self.logger.info("Gathering target information...")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.submit(self._get_dns_info)
            executor.submit(self._get_whois_info)
            executor.submit(self._get_headers)
            executor.submit(self._port_scan)
        
        return self.results

    def _get_dns_info(self):
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            self.results['dns'] = [str(rdata) for rdata in answers]
        except Exception as e:
            self.logger.error(f"DNS lookup failed: {str(e)}")

    def _get_whois_info(self):
        try:
            w = whois.whois(self.target)
            self.results['whois'] = w
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {str(e)}")

    def _get_headers(self):
        try:
            r = requests.head(f"http://{self.target}")
            self.results['headers'] = dict(r.headers)
        except Exception as e:
            self.logger.error(f"Headers retrieval failed: {str(e)}")

    def _port_scan(self):
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                continue
        
        self.results['open_ports'] = open_ports
