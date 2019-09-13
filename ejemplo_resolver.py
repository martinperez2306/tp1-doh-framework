import dns.resolver
import re

# Resolve www.yahoo.com
ips = []
try:
    # get the dns resolutions for this domain
    result = dns.resolver.query('sadsadm')
    ips = [ip.address for ip in result]
except dns.resolver.NXDOMAIN as e:
    # the domain does not exist so dns resolutions remain empty
    pass
except dns.resolver.NoAnswer as e:
    # the resolver is not answering so dns resolutions remain empty
    pass

if not ips:
	print("No existe el dominio")
for ip in ips:
	print(ip)