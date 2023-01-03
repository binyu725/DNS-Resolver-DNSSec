External libraries used:
dnspython
cryptography (must install for dnssec)

----------------------------------------

run the program:

part A:

python mydig.py [domain] [query type]

Examples:
python www.google.com A
python google.com MX
python google.com NS


part B:
python dnssec.py [domain]

Examples:
python dnssec.py verisigninc.com
python dnssec.py dnssec-deployment.org
python dnssec.py dnssec-failed.org