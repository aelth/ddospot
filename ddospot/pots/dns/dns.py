#!/usr/bin/env python3

import base64
import datetime
import json
import logging
import sys
import threading
import time

try:
    from twisted.internet import reactor
    from twisted.names import dns
    from twisted.names import client, server
except ImportError as e:
    exit(
        'Twisted requirement is missing. '
        'Please install it with "pip install twisted". Error: %s' % e
        )
try:
    import schedule
except ImportError:
    print(
        'No schedule module detected - fallback to traditional Timer method for DB flush.'
        'To enable advanced scheduling, do "pip install git+https://github.com/dbader/schedule.git"')

import core.genpot as genpot

LOGGER_NAME = 'dnspot'


class DNSServerFactory(server.DNSServerFactory):
    """DNS honeypot.
    @see: http://notmysock.org/blog/hacks/a-twisted-dns-story.html
    @see: http://blog.inneoin.org/2009/11/i-used-twisted-to-create-dns-server.html
    """

    # key of the request log dictionary is (ip, dns_name, type, class) quartet
    # every request log entry contains count and last seen timestamp
    request_log = {}

    # access to request log is shared between multiple threads
    # lock is used in order to synchronize the access
    request_log_lock = threading.Lock()

    # set of (source IP, dns name) pairs that have not yet been flushed to database
    # db flush is triggered by timer, every packet_flush_interval minutes
    req_cache = set()

    # set of (dns_name, dns_type, dns_cls) tuples that represent the domain that has not yet been updated
    # only first response is recorded to database!
    domain_cache = set()

    # if schedule module is used for periodic database flush, terminate the thread
    # by signaling the event
    flush_db_event = None

    def __init__(self, clients=None, hpf_client=None, alerter=None, verbose=0):
        self.logger = logging.getLogger(LOGGER_NAME)
        self.hpfeeds_client = hpf_client
        self.alerter = alerter
        server.DNSServerFactory.__init__(self, clients=clients, verbose=verbose)

    def run(self):
        # do not install signal handler
        # this enables handling of keyboard interrupts from other threads
        reactor.run(installSignalHandlers=False)

    def stop(self):
        logging.getLogger(LOGGER_NAME).info('DNSPot received shutdown signal, exiting...')

        # flush to database before exit
        self._flush_to_db()

        # set shutdown event for scheduling if schedule module is used
        if self.flush_db_event:
            self.flush_db_event.set()

        # wait for all queue entries to be processed
        self.log_queue.join()

        reactor.callFromThread(reactor.stop)

    def messageReceived(self, message, proto, address=None):
        entry = {}
        if isinstance(proto, dns.DNSProtocol):
            entry['src_ip'] = proto.transport.client[0]
            entry['src_port'] = proto.transport.client[1]
        else:
            entry['src_ip'] = str(address[0])
            entry['src_port'] = address[1]
        entry['opcode'] = message.opCode

        entry['dns_name'], entry['dns_type'], entry['dns_cls'] = self._parse_domain(message)

        # queries from the same IP but for a different name are considered different requests
        # check if pair (src_ip, dns_name) has already been logged - entering critical section
        with self.request_log_lock:
            req_key = (
                        entry['src_ip'],
                        entry['dns_name'],
                        entry['dns_type'],
                        entry['dns_cls']
                      )
            now = datetime.datetime.now()
            if req_key in self.request_log:
                attack = self.request_log[req_key]
                # check if this is an 'old attack' or an old attack,
                # on the same IP address and using the same amplification domain
                if attack['last_seen'] + self.new_attack_interval < now:
                    # this is a new attack, log it and store it
                    # old attack structure will be garbage-collected
                    self.logger.info('New attack started for quartet %s' % (req_key, ))
                    attack['count'] = 1
                    attack['last_seen'] = now
                    attack['response_logged'] = False
                    self._log(entry, False)
                else:
                    attack['count'] += 1
                    attack['last_seen'] = now

                    # add this request to request cache - will be flushed frequently to database
                    self.req_cache.add(req_key)

                    if attack['count'] >= self.request_threshold:
                        # if threshold is just reached, log the 'final' packet and
                        # send attack info via hpfeeds when threshold is reached
                        if attack['count'] == self.request_threshold:
                            self.logger.info(
                                            'Threshold reached for quartet %s '
                                            '- will not respond to this host/query tuple' % (req_key, )
                                            )

                            # log last request and send to hpfeeds (if enabled)
                            self._log(entry, True)
                        else:
                            # do not forward the request if threshold was reached
                            # logging will be flushed separately
                            return
            else:
                # this is a new attack, initialize attack log structure and perform the request
                self.request_log[req_key] = {}
                self.request_log[req_key]['count'] = 1
                self.request_log[req_key]['last_seen'] = now
                self.request_log[req_key]['response_logged'] = False
                self._log(entry, False)

            return self._forward_message(entry['dns_name'], message, proto, address)

    def gotResolverResponse(self, xxx_todo_changeme, protocol, message, address):
        # get number of records/answers in DNS response by taking answer,
        # authority and additional records into account
        (ans, auth, add) = xxx_todo_changeme
        num_entries = len(ans) + len(auth) + len(add)

        # do the important stuff quickly - respond with the message received
        # from the 'upstream' resolver
        response = self._responseFromMessage(
                                            message=message,
                                            rCode=dns.OK,
                                            answers=ans,
                                            authority=auth,
                                            additional=add
                                            )
        self.sendReply(protocol, response, address)

        if self.cache and num_entries:
            self.cache.cacheResult(
                message.queries[0], (ans, auth, add)
            )

        ip = str(address[0])
        dns_name, dns_type, dns_cls = self._parse_domain(message)
        req_key = (
                    ip,
                    dns_name,
                    dns_type,
                    dns_cls
                  )
        with self.request_log_lock:
            # update number of response records and amplification rate
            # ONLY if new attack is detected (i.e. response has not yet been logged)
            if req_key in self.request_log:
                target_req = self.request_log[req_key]
                if 'response_logged' in target_req and target_req['response_logged'] is False:
                    target_req['response_logged'] = True
                    input_size = len(message.toStr())

                    # little hack is used in order to get response size
                    # emulate the behavior of twisted/names/server.py:gotResolverResponse function
                    # (see implementation)
                    resp_string = response.toStr()
                    output_size = len(resp_string)
                    db_params = {
                                'type': 'domain',
                                'ip': ip,
                                'dns_name': dns_name,
                                'dns_type': dns_type,
                                'dns_class': dns_cls,
                                'num_entries': num_entries,
                                'response': base64.b64encode(resp_string),
                                'amp': round(output_size / float(input_size), 2),
                                'last_seen': target_req['last_seen']
                                }
                    self.log_queue.put({'type': 'update', 'db_params': db_params})

    def gotResolverError(self, failure, protocol, message, address):
        # override of base function because base function logs errors directly to screen
        # this implementation is identical to the standard one, but without log.err call
        # there probably exists much more elegant way to solve this problem, but I don't know how to do it:(

        dns_name, dns_type, dns_cls = self._parse_domain(message)
        if failure.check(dns.DomainError, dns.AuthoritativeDomainError):
            rCode = dns.ENAME
            self.logger.warning('Error while resolving domain %s, type %s, class %s' % (dns_name, dns_type, dns_cls))
        else:
            rCode = dns.ESERVER
            self.logger.warning('Query timeout while resolving domain %s, type %s, class %s' % (dns_name, dns_type, dns_cls))

        response = self._responseFromMessage(message=message, rCode=rCode)
        self.sendReply(protocol, response, address)

    def schedule_db_flush(self):
        # check if schedule module is present
        if 'schedule' in sys.modules:
            schedule.every(self.packet_flush_interval).minutes.do(self._flush_to_db)
            self.flush_db_event = self._run_continuously()
        else:
            self.flush_ip_log()

    def flush_ip_log(self):
        self._flush_to_db()
        # packet flush interval is in minutes!
        t = threading.Timer(self.packet_flush_interval * 60, self.flush_ip_log)
        t.daemon = True
        t.start()

    def _run_continuously(self):
        cease_continuous_run = threading.Event()

        class ScheduleThread(threading.Thread):
            @classmethod
            def run(cls):
                while not cease_continuous_run.is_set():
                    schedule.run_pending()
                    time.sleep(5)

                self.logger.info('Database flush scheduler received shutdown signal, exiting...')

        continuous_thread = ScheduleThread()
        continuous_thread.start()
        return cease_continuous_run

    def _flush_to_db(self):
        with self.request_log_lock:
            if len(self.req_cache):
                self.logger.info('Flushing information for %d (IP, dns, type, class) quartets to database...' % len(self.req_cache))
                for req_key in self.req_cache:
                    attack = self.request_log[req_key]
                    db_params = {
                                'type': 'attack',
                                'ip': req_key[0],
                                'dns_name': req_key[1],
                                'dns_type': req_key[2],
                                'dns_class': req_key[3],
                                'count': attack['count'],
                                'last_seen': attack['last_seen']
                                }
                    self.log_queue.put({'type': 'update', 'db_params': db_params})

                self.req_cache.clear()

    def _forward_message(self, name, message, proto, address):
        # handle chaos record - return fake BIND "banner"
        # TODO: this packet is currently malformed and fingerprintable.
        #       "Authoritative" answer is sent, without authority RR
        if name == 'version.bind':
            txt = dns.Record_TXT(self.bind_version)
            message.answer = True
            message.auth = True
            message.authenticData = False
            message.timeReceived = time.time()
            ans = dns.RRHeader(name, message.queries[0].type, message.queries[0].cls, 0, txt)
            return server.DNSServerFactory.gotResolverResponse(self, ([ans], [], []), proto, message, address)
        else:
            return server.DNSServerFactory.messageReceived(self, message, proto, address)

    def _log(self, packet, last=False):
        attack = None
        data = packet
        timestamp = datetime.datetime.now()
        data['time'] = str(timestamp)
        # JSON doesn't like bytes
        #data['dns_name'] = data['dns_name'].decode('ascii')

        raw_json = json.dumps(data)

        if not last:
            self.logger.info('New DNS query - %s' % (raw_json))
            db_params = {
                        'ip': data['src_ip'],
                        'port': data['src_port'],
                        'dns_name': data['dns_name'],
                        'dns_type': data['dns_type'],
                        'dns_class': data['dns_cls'],
                        'opcode': data['opcode'],
                        'time': timestamp
                        }
            self.log_queue.put({'type': 'insert', 'db_params': db_params})

        # if last packet, send to hpfeeds and notifier/alerter
        if last:
            if self.hpfeeds_client:
                self.hpfeeds_client.publish('dnspot.events', raw_json)

            # send notification if alerter is enabled
            # THIS OPERATION CAN BE SLOW!
            if self.alerter:
                self.alerter.alert(data['src_ip'], int(data['src_port']))

        return attack

    def _parse_domain(self, message):
        """Takes DNS request and returns tuple (dns_name, dns_cls, dns_type)."""
        dns_name = ''
        dns_type = ''
        dns_cls = ''
        # it is possible that the query part is empty - handle this situation
        # by returning empty name, type and class
        # (NMAP does such request with status message - opcode 2)
        if len(message.queries):
            dns_name = message.queries[0].name.name.decode('utf-8')
            dns_type = str(dns.QUERY_TYPES.get(message.queries[0].type, dns.EXT_QUERIES.get(message.queries[0].type, 'UNKNOWN (%d)' % message.queries[0].type)))
            dns_cls = str(dns.QUERY_CLASSES.get(message.queries[0].cls, 'UNKNOWN (%d)' % message.queries[0].cls))

        return (dns_name, dns_type, dns_cls)


def create_server(conf, logger_name, log_queue, output_queue, hpf_client=None, alerter=None):
    global LOGGER_NAME
    LOGGER_NAME = logger_name
    ip = conf.get('general', 'listen_ip')
    port = conf.getint('general', 'listen_port')

    # upstream DNS servers are specified as a comma-delimited list
    # make a list of (ip, port) tuples that can be used directly in twisted resolver
    upstream_servers = [(srv.strip(), 53) for srv in conf.get('DNS', 'dns_servers').split(',')]

    # specify timeout during resolving explicitly (default timeout is too big for our purposes, although it is deferred)
    resolver = client.Resolver(servers=upstream_servers, timeout=(1,3,11))
    dns_factory = DNSServerFactory([resolver], hpf_client, alerter)
    dns_protocol = dns.DNSDatagramProtocol(dns_factory)

    dns_factory.log_queue = log_queue
    dns_factory.output_queue = output_queue
    dns_factory.packet_flush_interval = conf.getint('logging', 'packet_flush_interval')
    new_attack_interval = conf.getint('attack', 'new_attack_detection_interval')
    dns_factory.new_attack_interval = datetime.timedelta(minutes=new_attack_interval)
    dns_factory.request_threshold = conf.getint('attack', 'request_threshold')
    dns_factory.bind_version = conf.get('DNS', 'bind_version').encode('utf-8')

    # load request log state from the database
    dns_factory.request_log = genpot._load_state(log_queue, output_queue)

    # bind DNS server to both UDP and TCP ports
    reactor.listenUDP(port, dns_protocol, interface=ip)
    reactor.listenTCP(port, dns_factory, interface=ip)

    msg = "DNSPot started at %s:%d" % (ip, port)
    logging.getLogger(LOGGER_NAME).info(msg)
    print(msg)

    dns_factory.schedule_db_flush()

    return dns_factory
