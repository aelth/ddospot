#!/usr/bin/env python3

import base64
import datetime
import json
import logging
import socketserver
import threading
import traceback

import core.genpot as genpot
import core.utils as utils


LOGGER_NAME = 'chargen'


class ChargenServer(socketserver.BaseRequestHandler):
    # default logger
    logger = logging.getLogger(LOGGER_NAME)

    @staticmethod
    def set_response_defaults(response_size=1024, line_len=72):
        if response_size <= 0:
            ChargenServer.logger.warning('Response size cannot be negative (%d), using default value (1024)' % (response_size))
            response_size = 1024
        if line_len <= 0:
            ChargenServer.logger.warning('Line length cannot be negative (%d), using default value (72)' % (line_len))
            line_len = 72
        if line_len > response_size:
            ChargenServer.logger.warning('Line len (%d) > response size (%d), using default values (72, 1024)' % (line_len, response_size))
            response_size = 1024
            line_len = 72
        ChargenServer.response_size = response_size
        ChargenServer.line_len = line_len

    def log_packet(
            self, msg, addr, port, timestamp,
            incoming_pkt, req_size, resp_size, last=False):
        data = {}
        data['time'] = str(timestamp)
        data['src_ip'] = addr
        data['src_port'] = port
        data['req_size'] = req_size
        data['resp_size'] = resp_size
        if self.server.log_req_packets:
            data['req_pkt'] = incoming_pkt.decode('ascii')

        raw_json = json.dumps(data)

        self.logger.info('%s - %s' % (msg, raw_json))

        if not last:
            db_params = {
                        'ip': utils.addr_to_int(addr),
                        'port': port,
                        'time': timestamp,
                        'request_pkt': incoming_pkt,
                        'input_size': req_size,
                        'output_size': resp_size,
                        }
            self.server.log_queue.put({'type': 'insert', 'db_params': db_params})

        # if last packet, send to hpfeeds and notifier/alerter
        if last:
            if self.server.hpfeeds_client:
                self.server.hpfeeds_client.publish('chargenpot.events', raw_json)

            # send notification if alerter is enabled
            # THIS OPERATION CAN BE SLOW!
            if self.server.alerter:
                self.server.alerter.alert(addr, int(port))

    def handle(self):
        try:
            addr = self.client_address[0]
            port = self.client_address[1]
            data = self.request[0]
            sock = self.request[1]
            first = False
            last = False

            # no need to check for validity. any packet is accepted

            # IP addresses in transaction log and database will be stored as integers/long
            addr_int = utils.addr_to_int(addr)

            now = datetime.datetime.now()
            log_msg = 'New chargen packet received'

            # check if the request from this IP address was already received - ENTERING CRITICAL SECTION HERE!
            with self.server.tx_log_lock:
                if addr_int in self.server.transaction_log:
                    addr_log = self.server.transaction_log[addr_int]

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

                        # add the IP address to the request cache set - this set will be frequently flushed to DB
                        self.server.ip_log.add(addr_int)

                        # if count >= threshold, ignore the packet, never respond
                        if addr_log['count'] > self.server.threshold:
                            return
                        # log reaching of threshold and mark packet as last that will be accepted
                        elif addr_log['count'] == self.server.threshold:
                            last = True
                            self.logger.info(
                                    'Threshold reached for host %s - will not respond to this host' % addr)
                            log_msg = 'Last packet - threshold reached'
                else:
                    # add host to transaction log
                    first = True
                    self.server.transaction_log[addr_int] = {}
                    self.server.transaction_log[addr_int]['last_seen'] = now
                    self.server.transaction_log[addr_int]['count'] = 1

            # access needs to be synchronized since multiple threads can transform the alphabet
            # response is shifted alphabet, depending on response size and line length in config
            response = ''
            with self.server.alphabet_lock:
                for i in range(1 + int(self.response_size / self.line_len)):
                    suf_len = min(self.line_len, abs(self.response_size - len(response) - 2))
                    response += self.server.alphabet[0:suf_len] + '\r\n'
                    self.server.alphabet = self.server.alphabet[1:] + self.server.alphabet[0]

                    # last line
                    if suf_len < self.line_len:
                        break

            sock.sendto(response.encode('ascii'), self.client_address)
            if first or last:
                b64_req = base64.b64encode(data)
                input_size = len(data)
                output_size = len(response)
                self.log_packet(
                                log_msg,
                                addr,
                                port,
                                now,
                                b64_req,
                                input_size,
                                output_size,
                                last
                                )
        except Exception:
            t = traceback.format_exc()
            self.logger.error('Unknown error during communication with %s:%d - %s' % (addr, port, base64.b64encode(data)))
            self.logger.error('Stacktrace: %s' % t)


class ThreadedChargenServer(genpot.ThreadedUDPServer):
    # chargen alphabet per RFC 864
    alphabet = ''.join(chr(x) for x in range(33, 126))

    # lock for synchronization of chargen alphabet access and transformation
    alphabet_lock = threading.Lock()

    def _flush_ip_info(self, ip):
        addr_log = self.transaction_log[ip]
        db_params = {
                    'ip': ip,
                    'last_seen': addr_log['last_seen'],
                    'count': addr_log['count']
                    }
        self.log_queue.put({'type': 'update', 'db_params': db_params})


def create_server(conf, logger_name, log_queue, output_queue, hpf_client=None, alerter=None):
    server, ip, port = genpot.create_base_server(
                                                ThreadedChargenServer,
                                                ChargenServer,
                                                conf,
                                                logger_name,
                                                log_queue,
                                                output_queue,
                                                hpf_client,
                                                alerter
                                                )

    response_size = conf.getint('chargen', 'response_size')
    line_len = conf.getint('chargen', 'line_len')
    ChargenServer.set_response_defaults(response_size, line_len)

    msg = "ChargenPot starting at %s:%d" % (ip, port)
    logging.getLogger(logger_name).info(msg)
    print(msg)

    return server
