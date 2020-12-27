import json
import os
import socket
import sys
import urllib.request, urllib.error, urllib.parse
import urllib.parse

# 4 arguments required - server URL, deploy key, honeypot name and honeypot hostname suffix
if len(sys.argv) != 5:
    print('Usage: python register.py <server_url> <deploy_key> <honeypot_name> <honeypot_hostname_suffix>')
    sys.exit(1)

server_url = sys.argv[1]
deploy_key = sys.argv[2]
honeypot_name = sys.argv[3]
honeypot_hostname_suffix = sys.argv[4]
hostname = socket.gethostname()

try:
    # check if registered
    if os.path.exists('./registered'):
        print('Sensor already registered, exiting')
        sys.exit(0)

    # not registered, do the registration
    registration_data = {
                            'name': hostname + '-' + honeypot_hostname_suffix,
                            'hostname': hostname,
                            'deploy_key': deploy_key,
                            'honeypot': honeypot_name,
                        }
    req = urllib.request.Request(server_url + '/api/sensor/')
    req.add_header('Content-Type', 'application/json')
    resp = urllib.request.urlopen(req, json.dumps(registration_data))
    registration = json.loads(resp.read())
    resp.close()

    # write hpfeeds data to configuration file
    with open('./registered', 'w') as regfile:
        regfile.write('HPF_HOST=%s%c' % (urllib.parse.urlparse(server_url).hostname, '\n'))
        regfile.write('HPF_PORT=10000\n')
        regfile.write('HPF_IDENT=%s%c' % (registration['identifier'], '\n'))
        regfile.write('HPF_SECRET=%s%c' % (registration['secret'], '\n'))
except Exception as msg:
    print(('Error occurred during registration: %s' % (msg)))
