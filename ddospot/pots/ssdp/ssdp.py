#!/usr/bin/env python3

import base64
import http.server
import configparser
import datetime
import json
import logging
import random
import socketserver
import io
import time
import traceback

import core.genpot as genpot
import core.utils as utils


LOGGER_NAME = 'ssdp'


class UPnPDevice(object):
    """Describes UPnP device handled by the server."""
    def __init__(self, device_type, uuid, location):
        self._device_type = device_type
        self._uuid = uuid
        self._location = location

    @property
    def device_type(self):
        return self._device_type

    @device_type.setter
    def device_type(self, dev_type):
        self._device_type = dev_type

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, uuid):
        self._uuid = uuid

    @property
    def location(self):
        return self._location

    @location.setter
    def location(self, loc):
        self._location = loc


class SSDPException(Exception):
    """Exception raised by this module."""
    pass


class SSDPServer(socketserver.BaseRequestHandler):
    # SSDP request and response parsing based on
    # https://gist.github.com/schlamar/2428250
    class SSDPRequest(http.server.BaseHTTPRequestHandler):
        def __init__(self, request_text):
            self.rfile = io.BytesIO(request_text)
            self.raw_requestline = self.rfile.readline()
            self.error_code = self.error_message = None
            self.parse_request()
            self._check_valid()

        def send_error(self, code, message):
            self.error_code = code
            self.error_message = message

        @property
        def host(self):
            return self.headers['HOST']

        @property
        def st(self):
            return self.headers['ST']

        @property
        def man(self):
            return self.headers['MAN']

        @property
        def mx(self):
            return self.headers['MX']

        def _check_valid(self):
            # according to the specification, valid SSDP packet
            # has following characteristics:
            #   M-SEARCH HTTP Verb
            #   URI path set to '*'
            #   HOST header present and set to 239.255.255.250 or 239.255.255.250:1900
            #   ST header present and equal to 'ssdp:all' or 'upnp:rootdevice' or 'uuid:<uuid>' or 'urn:schemas-upnp-org:...'
            #   MAN header present and set to ssdp:discover
            #   MX header present and is integer greater than or equal to 1
            err_msgs = []

            try:
                if self.error_code:
                    err_msgs.append(self.error_message)

                if self.command != 'M-SEARCH':
                    err_msgs.append('Invalid command specified: %s' % self.command)

                if self.path != '*':
                    err_msgs.append('Invalid URI/path specified: %s' % self.path)

                if 'HOST' not in self.headers:
                    err_msgs.append('HOST header not specified')
                elif self.host != '239.255.255.250:1900' and \
                     self.host != '239.255.255.250':
                    err_msgs.append('HOST header has invalid value: %s' % self.host)

                if 'ST' not in self.headers:
                    err_msgs.append('ST header not specified')
                elif self.st != 'ssdp:all' and \
                     self.st != 'upnp:rootdevice' and \
                     not self.st.startswith('uuid:') and \
                     not self.st.startswith('urn:schemas-upnp-org:device:') and \
                     not self.st.startswith('urn:schemas-upnp-org:service:'):
                    err_msgs.append('ST header has invalid value: %s' % self.st)

                if 'MAN' not in self.headers:
                    err_msgs.append('MAN header not specified')
                elif self.man != '"ssdp:discover"':
                    err_msgs.append('Invalid MAN header value: %s' % self.man)

                if 'MX' not in self.headers:
                    err_msgs.append('MX header not specified')
                else:
                    try:
                        mx = int(self.mx)
                        if mx < 1:
                            err_msgs.append('MX header specified but has invalid value: %d' % mx)
                    except ValueError:
                        err_msgs.append('Invalid MX header value: %s' % self.mx)

            except Exception:
                # handled with error msgs
                pass

            if err_msgs:
                err_msg = ''
                for msg in err_msgs:
                    err_msg = msg + '; '
                raise SSDPException(err_msg[:-2])

    # SSDP response parsing based on Pydlnadms (https://code.google.com/p/pydlnadms/)
    class SSDPResponse(object):
        raw_response = (
                        'HTTP/1.1 200 OK\r\n' +
                        'CACHE-CONTROL: max-age=%(max_age)s\r\n'
                        'ST: %(dev_type)s\r\n'
                        'USN: %(usn)s\r\n'
                        'EXT:\r\n'
                        'SERVER: %(server)s\r\n'
                        'LOCATION: %(loc)s\r\n'
                       )

        def __init__(self, dev_type, usn, loc):
            self.dev_type = dev_type
            self.usn = usn
            self.location = loc

        def to_bytes(self):
            return (
                    self.raw_response % dict(
                                            max_age=self.max_age,
                                            dev_type=self.dev_type,
                                            usn=self.usn,
                                            server=self.server_version,
                                            loc=self.location
                                            )
                   ).encode('utf-8')

    # default logger
    logger = logging.getLogger(LOGGER_NAME)

    def log_packet(
            self, msg, addr, port, timestamp, request,
            incoming_pkt, req_size, outgoing_pkt, resp_size, last=False):
        data = {}
        data['time'] = str(timestamp)
        data['src_ip'] = addr
        data['src_port'] = port
        data['st'] = request.st
        data['mx'] = request.mx
        data['req_size'] = req_size
        data['resp_size'] = resp_size
        if self.server.log_req_packets:
            data['req_pkt'] = incoming_pkt.decode('ascii')
        if self.server.log_resp_packets:
            data['resp_pkt'] = outgoing_pkt.decode('ascii')

        raw_json = json.dumps(data)

        self.logger.info('%s - %s' % (msg, raw_json))

        if not last:
            db_params = {
                        'ip': utils.addr_to_int(addr),
                        'port': port,
                        'time': timestamp,
                        'st': request.st,
                        'mx': request.mx,
                        'request_pkt': incoming_pkt,
                        'response_pkt': outgoing_pkt,
                        'input_size': req_size,
                        'output_size': resp_size,
                        }
            self.server.log_queue.put({'type': 'insert', 'db_params': db_params})

        # if last packet, send to hpfeeds and notifier/alerter
        if last:
            if self.server.hpfeeds_client:
                self.server.hpfeeds_client.publish('ssdpot.events', raw_json)

            # send notification if alerter is enabled
            # THIS OPERATION CAN BE SLOW!
            if self.server.alerter:
                self.server.alerter.alert(addr, int(port))


    def _create_response(self, request_target, device):
        # set USN to device uuid (default when request target is device uuid)
        usn = device.uuid
        if request_target != device.uuid and request_target != 'ssdp:all':
            usn += '::' + request_target

        return SSDPServer.SSDPResponse(device.device_type, usn, device.location).to_bytes()

    def handle(self):
        try:
            addr = self.client_address[0]
            port = self.client_address[1]
            data = self.request[0]
            sock = self.request[1]
            first = False
            last = False

            # parse request and check if valid packet
            # invalid packets are discarded
            # logging only to output log, not to DB
            try:
                request = SSDPServer.SSDPRequest(data)
            except SSDPException as msg:
                self.logger.error('%s:%d - %s' % (addr, port, msg))
                return

            # IP addresses in transaction log and database will be stored as integers/long
            addr_int = utils.addr_to_int(addr)

            now = datetime.datetime.now()
            log_msg = 'New SSDP packet received'

            # check if SSDP request from this IP address was already received - ENTERING CRITICAL SECTION HERE!
            # IP address and ST are the only criteria useful for disrimination of different attacks on the same host
            # other variables (MX, MAN, HOST headers) should be more or less constant and so irrelevant
            with self.server.tx_log_lock:
                req_key = (
                            addr_int,
                            request.st
                          )
                if req_key in self.server.transaction_log:
                    addr_log = self.server.transaction_log[req_key]

                    # check if this is an already existing attack or a new attack
                    # attack is classified as NEW if more than new_attack_duration_interval
                    # minutes have passed since the last seen packet
                    if addr_log['last_seen'] + self.server.new_attack_interval < now:
                        # consider this as a new attack, reset cache data
                        first = True
                        addr_log['count'] = 1
                        addr_log['last_seen'] = now
                        log_msg = 'New attack detected'
                    else:
                        # update transaction log and database last-seen time and packet count and do not respond to the packet
                        addr_log['last_seen'] = now
                        addr_log['count'] += 1

                        # add the pair to the request cache set - this set will be frequently flushed to DB
                        self.server.ip_log.add(req_key)

                        # if count >= threshold, ignore the packet, never respond
                        if addr_log['count'] > self.server.threshold:
                            return
                        # log reaching of threshold and mark packet as last that will be accepted
                        elif addr_log['count'] == self.server.threshold:
                            last = True
                            self.logger.info(
                                    'Threshold reached for host %s and search target %s - will not respond to this host pair' % (addr, request.st))
                            log_msg = 'Last packet - threshold reached'
                else:
                    # add host to transaction log
                    first = True
                    self.server.transaction_log[req_key] = {}
                    self.server.transaction_log[req_key]['last_seen'] = now
                    self.server.transaction_log[req_key]['count'] = 1

            targets = []
            # send info about all supported devices if ssdp:all is specified as ST
            if request.st == 'ssdp:all':
                targets = self.server.device_list
            else:
                for device in self.server.device_list:
                    if request.st == device.device_type or \
                       request.st == device.uuid:
                        targets.append(device)

            b64_resp = b''
            output_size = 0
            responses = []
            for target in targets:
                response = self._create_response(request.st, target)
                responses.append(response)
                b64_resp += base64.b64encode(response)
                output_size += len(response)

            # log packets to file and database
            # log and then send the packets, because sending is interrupted by sleep
            # this is per specification!
            if first or last:
                b64_req = base64.b64encode(data)
                input_size = len(data)
                self.log_packet(
                                log_msg,
                                addr,
                                port,
                                now,
                                request,
                                b64_req,
                                input_size,
                                b64_resp,
                                output_size,
                                last
                                )

            for response in responses:
                sock.sendto(response, self.client_address)
                # sleep random number of seconds between 1 and the value
                # received in the request - per specification
                time.sleep(random.randint(1, int(request.mx)))

        except Exception:
            t = traceback.format_exc()
            self.logger.error('Unknown error during communication with %s:%d - %s' % (addr, port, base64.b64encode(data)))
            self.logger.error('Stacktrace: %s' % t)


class ThreadedSSDPServer(genpot.ThreadedUDPServer):
    def _flush_ip_info(self, req_key):
        addr_log = self.transaction_log[req_key]
        db_params = {
                    'ip': req_key[0],
                    'st': req_key[1],
                    'last_seen': addr_log['last_seen'],
                    'count': addr_log['count']
                    }
        self.log_queue.put({'type': 'update', 'db_params': db_params})


def _get_available_devices(conf):
    try:
        num_devices = conf.getint('SSDP', 'num_devices')
        if num_devices < 0:
            logging.getLogger(LOGGER_NAME).error('Invalid device number value, must be greater than zero!')
            return

        devices = []
        for i in range(1, num_devices + 1):
            try:
                section = 'device-' + str(i)
                device_type = conf.get(section, 'device_type')
                uuid = conf.get(section, 'uuid')
                location = conf.get(section, 'location')
                device = UPnPDevice(device_type, uuid, location)
                devices.append(device)
            except configparser.NoSectionError:
                logging.getLogger(LOGGER_NAME).warn('No section %s, ignoring device...' % section)
                continue
            except configparser.NoOptionError as msg:
                logging.getLogger(LOGGER_NAME).warn('Option error: %s. Ignoring device...' % msg)
                continue
        return devices
    except configparser.Error as msg:
        logging.getLogger(LOGGER_NAME).error('Error occurred while parsing device section in configuration file: %s' % msg)


def create_server(conf, logger_name, log_queue, output_queue, hpf_client=None, alerter=None):
    global LOGGER_NAME
    LOGGER_NAME = logger_name

    server, ip, port = genpot.create_base_server(
                                                ThreadedSSDPServer,
                                                SSDPServer,
                                                conf,
                                                logger_name,
                                                log_queue,
                                                output_queue,
                                                hpf_client,
                                                alerter
                                                )

    # set static response variables
    SSDPServer.SSDPResponse.max_age = conf.getint('SSDP', 'max_age')
    SSDPServer.SSDPResponse.server_version = conf.get('SSDP', 'server')
    server.device_list = _get_available_devices(conf)

    msg = "SSDPot started at %s:%d" % (ip, port)
    logging.getLogger(LOGGER_NAME).info(msg)
    print(msg)

    return server
