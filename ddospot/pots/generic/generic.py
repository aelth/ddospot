#!/usr/bin/env python3

import base64
import datetime
import json
import logging
import random
import socketserver
import traceback

import core.genpot as genpot
import core.utils as utils


LOGGER_NAME = 'generic'


class GenericPotServer(socketserver.BaseRequestHandler):
    # default logger
    logger = logging.getLogger(LOGGER_NAME)

    @staticmethod
    def set_response_defaults(response, response_size):
        if response != 'random':
            # response is b64 encoded, so decode it
            GenericPotServer.random = False
            GenericPotServer.response = base64.b64decode(response)
            GenericPotServer.response_size = len(GenericPotServer.response)
        else:
            GenericPotServer.random = True
            # response size can be specified as multiplier or as a fixed size
            if response_size and response_size[-1] == 'x':
                GenericPotServer.response_size = float(response_size[:-1])
            else:
                GenericPotServer.response_size = response_size

    def log_packet(
            self, msg, addr, sport, dport,
            timestamp, incoming_pkt, req_size, resp_size, last=False):
        data = {}
        data['time'] = str(timestamp)
        data['src_ip'] = addr
        data['src_port'] = sport
        data['dst_port'] = dport
        data['req_size'] = req_size
        data['resp_size'] = resp_size
        if self.server.log_req_packets:
            data['req_pkt'] = incoming_pkt.decode('ascii')

        raw_json = json.dumps(data)

        self.logger.info('%s - %s' % (msg, raw_json))

        if not last:
            db_params = {
                        'ip': utils.addr_to_int(addr),
                        'port': sport,
                        'dport': dport,
                        'time': timestamp,
                        'request_pkt': incoming_pkt,
                        'input_size': req_size,
                        'output_size': resp_size,
                        }
            self.server.log_queue.put({'type': 'insert', 'db_params': db_params})

        # if last packet, send to hpfeeds and notifier/alerter
        if last:
            if self.server.hpfeeds_client:
                self.server.hpfeeds_client.publish('genericpot.events', raw_json)

            # send notification if alerter is enabled
            # THIS OPERATION CAN BE SLOW!
            if self.server.alerter:
                self.server.alerter.alert(addr, int(sport))

    def handle(self):
        try:
            addr = self.client_address[0]
            port = self.client_address[1]
            dport = self.server.server_address[1]
            data = self.request[0]
            sock = self.request[1]
            first = False
            last = False

            # no need to check for validity, any packet is accepted
            # IP addresses in transaction log and database will be stored as integers/long
            addr_int = utils.addr_to_int(addr)

            now = datetime.datetime.now()
            log_msg = 'New genericpot packet received'

            # check if the request from this IP address was already received - ENTERING CRITICAL SECTION HERE!
            with self.server.tx_log_lock:
                # since generic pot can be ran on any port, use port that the service is running on for
                # attack discrimination
                req_key = (addr_int, dport)
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

                        # add the IP address to the request cache set - this set will be frequently flushed to DB
                        self.server.ip_log.add(req_key)

                        # if count >= threshold, ignore the packet, never respond
                        if addr_log['count'] > self.server.threshold:
                            return
                        # log reaching of threshold and mark packet as last that will be accepted
                        elif addr_log['count'] == self.server.threshold:
                            last = True
                            self.logger.info(
                                    'Threshold reached for host %s and port %d - will not respond to this host' % (addr, dport))
                            log_msg = 'Last packet - threshold reached'
                else:
                    # add host to transaction log
                    first = True
                    self.server.transaction_log[req_key] = {}
                    self.server.transaction_log[req_key]['last_seen'] = now
                    self.server.transaction_log[req_key]['count'] = 1

            if self.random:
                # if multiplier is specified, response size is multiplied by request size
                # do not create response that is larger than 1 MB!
                resp_size = self.response_size
                if isinstance(resp_size, float):
                    resp_size = min(int(len(data) * self.response_size), 1048576)
                response = random.randbytes(resp_size)
            else:
                # not random, use predefined response
                response = self.response
                resp_size = self.response_size

            sock.sendto(response, self.client_address)
            if first or last:
                b64_req = base64.b64encode(data)
                input_size = len(data)
                self.log_packet(
                                log_msg,
                                addr,
                                port,
                                dport,
                                now,
                                b64_req,
                                input_size,
                                resp_size,
                                last
                                )
        except Exception:
            t = traceback.format_exc()
            self.logger.error('Unknown error during communication with %s:%d - %s' % (addr, port, base64.b64encode(data)))
            self.logger.error('Stacktrace: %s' % t)


class ThreadedGenericServer(genpot.ThreadedUDPServer):
    def _flush_ip_info(self, req_key):
        addr_log = self.transaction_log[req_key]
        db_params = {
                    'ip': req_key[0],
                    'dport': req_key[1],
                    'last_seen': addr_log['last_seen'],
                    'count': addr_log['count']
                    }
        self.log_queue.put({'type': 'update', 'db_params': db_params})


def create_server(conf, logger_name, log_queue, output_queue, hpf_client=None, alerter=None):
    server, ip, port = genpot.create_base_server(
                                                ThreadedGenericServer,
                                                GenericPotServer,
                                                conf,
                                                logger_name,
                                                log_queue,
                                                output_queue,
                                                hpf_client,
                                                alerter
                                                )

    # set static variables from config
    response = conf.get('genpot', 'response')
    response_size = conf.get('genpot', 'response_size')
    GenericPotServer.set_response_defaults(response, response_size)

    msg = "GenericPot starting at %s:%d" % (ip, port)
    logging.getLogger(logger_name).info(msg)
    print(msg)

    return server
