from diga import DIGA

domain = ['github.com', 'google.com', 'microsoft.com']
#domain = 'github.com'

results = DIGA(domain, dns=None, useragent=None, timeout=None, threads=None)

print (results)