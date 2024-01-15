#!/usr/bin/env python3

from datetime import datetime, date
import concurrent.futures
import dns.resolver
import OpenSSL
import ssl
import requests
import argparse
import random
import json
import sys
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning

__version__ = '0.1.0'

# Suppress the warnings from urllib3
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# List of user agents for HTTP requests
user_agent = [
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20120101 Firefox/33.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
    'Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)',
]

class HttpStatus:
    def __init__(self, domain, dns=None, useragent=None, timeout=None):
        self.domain = domain
        self.dns = dns if dns else '8.8.8.8'
        self.headers = {'User-Agent': random.choice(user_agent)} if not useragent else {'User-Agent': useragent}
        self.timeout = timeout if timeout else 0.5

    def http_response(self, url):
        try:
            response = requests.get(url, headers=self.headers, allow_redirects=False, timeout=self.timeout, verify=False)
        except requests.RequestException as e:
            """
            # verify=False disable security certificate checks
            # so, this exception is not used
            #
            # certificate error or expired
            if 'CERTIFICATE_VERIFY_FAILED' in str(e):
                # {"https": [200, null, null]}
                return 200, None, None
            """
            return None, None, None
        
        #headers_response = response.headers
        #http_version = response.raw.version
        status_code = response.status_code
        redirect_location = response.headers.get('Location')
        server_name = response.headers.get('Server')

        return status_code, redirect_location, server_name

    def cert_status(self, domain):
        try:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        except Exception as e:
            #print(f"Error connecting to {self.domain}: {e}")
            return None, None
        
        # 0=v1, 1=v2, 2=v3
        #version = x509.get_version()
        bytes = x509.get_notAfter()
        timestamp = bytes.decode('utf-8')
        
        # convert dateobj and datenow to isoformat and compare the values
        dateobj = datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat()
        datenow = datetime.now().date().isoformat()
        is_good = False if dateobj < datenow else True

        return is_good, dateobj

    def domain_resolver(self):
        res = dns.resolver.Resolver()
        res.timeout = self.timeout
        res.lifetime = self.timeout
        res.nameservers = [self.dns]

        try:
            ip_list = []
            for ip in res.resolve(self.domain, 'A'):
                ip_list.append(str(ip))
            
            return ip_list
        except:
            return None

    def scan(self):
        results = {"domain": self.domain}
        ip_list = self.domain_resolver()
        if not ip_list:
            return None
        
        # resolver
        results.update({"ip": ip_list})
        
        # http
        http_status_code, http_redirect_location, server_name = self.http_response(f"http://{self.domain}")
        results.update({"http": [http_status_code, http_redirect_location, server_name]})
        
        # https
        https_status_code, https_redirect_location, server_name = self.http_response(f"https://{self.domain}")
        results.update({"https": [https_status_code, https_redirect_location, server_name]})

        # https exception error
        if http_status_code and http_redirect_location and not https_status_code:
            domain = http_redirect_location.split('://')[1]
            domain = domain.split('/')[0]
            results["domain"] = domain
            https_status_code, https_redirect_location, server_name = self.http_response(f"https://{domain}")
            results.update({"https": [https_status_code, https_redirect_location]})

        is_good, dateobj = None, None
        if https_status_code:
            is_good, dateobj = self.cert_status(results["domain"])
        
        results.update({"cert": [is_good, dateobj]})

        return results


def DIGA(domain, dns=None, useragent=None, timeout=None, threads=None):
    def diga(domain, dns=None, useragent=None, timeout=None):
        return HttpStatus(domain, dns, useragent, timeout).scan()
    
    if isinstance(domain, list):
        if not threads:
            threads = 10
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(diga, d, dns, useragent, timeout) for d in domain]

        results = []
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

        return results

    return diga(domain, dns=None, useragent=None, timeout=None)

def main():
    parser = argparse.ArgumentParser(prog="DIGA", description="Domain Inspector Global Audit")

    # args
    parser.add_argument("-d", "--domain", help="domain to analyze")
    parser.add_argument("-f", "--file", help="domain list from file path")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--dns", help="custom dns", dest="dns", required=False)
    parser.add_argument("--useragent", help="custom useragent", dest="useragent", required=False)
    parser.add_argument("--timeout", help="custom timeout", dest="timeout", type=float, required=False)
    parser.add_argument("--threads", help="custom threads", dest="threads", type=int, required=False)
    parser.add_argument("--pretty", help="json pretty print", action="store_true", required=False)
    args = parser.parse_args()

    #print (args)
    
    if not args.domain and not args.file:
        parser.print_help(sys.stderr)
        sys.exit(0)

    if args.domain:
        results = DIGA(args.domain, args.dns, args.useragent, args.timeout)
        if args.pretty:
            print (json.dumps(results, indent=4))
        else:
            print (json.dumps(results))
    else:
        with open(args.file,'r') as f:
            domains = f.read().splitlines()
        results = DIGA(domains, args.dns, args.useragent, args.timeout)
        if args.pretty:
            print (json.dumps(results, indent=4))
        else:
            print (json.dumps(results))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)