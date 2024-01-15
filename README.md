# Domain Inspector Global Audit

## Install via pip

`pip install git+https://github.com/guelfoweb/diga.git`

## Install via pip requirements

`diga @ git+https://github.com/guelfoweb/diga.git`

## Usage

```
usage: DIGA [-h] [-d DOMAIN] [-f FILE] [-v] [--dns DNS] [--useragent USERAGENT] [--timeout TIMEOUT] [--threads THREADS] [--pretty]

diga v.0.1.0 - Domain Inspector Global Audit
https://github.com/guelfoweb/diga

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        domain to analyze
  -f FILE, --file FILE  domain list from file path
  -v, --version         show program's version number and exit
  --dns DNS             custom dns
  --useragent USERAGENT
                        custom useragent
  --timeout TIMEOUT     custom timeout
  --threads THREADS     custom threads
  --pretty              json pretty print
```