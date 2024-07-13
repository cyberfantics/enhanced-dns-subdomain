# -*- coding: utf-8 -*-
"""
Created on Sat Jul 13 15:42:02 2024

@author: Mansoor
"""

import dns.resolver
import socket
import whois

def reverseDNS(IP):
    """Perform a reverse DNS lookup."""
    try:
        result = socket.gethostbyaddr(IP)
    except socket.herror:
        return []
    
    return [result[0]] + result[1]

def dnsRequest(domain, verbose=False):
    """Perform a DNS request for the given domain."""
    try:
        result = dns.resolver.resolve(domain, "A")
        if result:
            if verbose:
                print(f"\nDomain: {domain}")
            for answer in result:
                ip_address = answer.to_text()
                if verbose:
                    print(f"IP Address: {ip_address}")
                reverse_dns_results = reverseDNS(ip_address)
                if reverse_dns_results:
                    if verbose:
                        print(f"Reverse DNS: {', '.join(reverse_dns_results)}")
                else:
                    if verbose:
                        print("No reverse DNS record found.")
            return domain
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None

def subDomainSearch(domain, dictionary, nums, verbose=False):
    """Search for subdomains using the provided dictionary and optional numeric suffixes."""
    subdomains_found = []
    for word in dictionary:
        subdomain = f"{word}.{domain}"
        result = dnsRequest(subdomain, verbose)
        if result:
            subdomains_found.append(result)
        
        if nums:
            for i in range(0, 10):
                s = f"{word}{i}.{domain}"
                result = dnsRequest(s, verbose)
                if result:
                    subdomains_found.append(result)
    return subdomains_found

def checkDomainAvailability(domain):
    """Check if a domain is available for registration."""
    try:
        whois.whois(domain)
        return False  # Domain is registered
    except whois.parser.PywhoisError:
        return True  # Domain is available

def main():
    """Main function to execute the DNS subdomain search."""
    domain = input("Enter the domain to search subdomains for: ")
    output_choice = input("Would you like to save the output to a file? (yes/no): ").strip().lower()
    verbose_choice = input("Would you like verbose output? (yes/no): ").strip().lower() == 'yes'
    dictionary_file = 'subdomain.txt'
    
    with open(dictionary_file, 'r') as f:
        dictionary = f.read().splitlines()
    
    available = checkDomainAvailability(domain)
    if available:
        print(f"The domain {domain} is available for registration.")
    else:
        print(f"The domain {domain} is already registered.")
    
    subdomains_found = subDomainSearch(domain, dictionary, True, verbose_choice)
    
    if output_choice == 'yes':
        import sys
        original_stdout = sys.stdout
        with open(f"{domain}_subdomains.txt", "w") as f:
            sys.stdout = f
            for subdomain in subdomains_found:
                print(subdomain)
            sys.stdout = original_stdout
        print(f"Output saved to {domain}_subdomains.txt")
    else:
        for subdomain in subdomains_found:
            print(subdomain)

if __name__ == "__main__":
    main()
