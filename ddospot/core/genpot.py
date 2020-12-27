#!/usr/bin/env python3

import datetime
import logging
import socketserver
import sys
import threading
import time

try:
    import schedule
except ImportError:
    print(
        'No schedule module detected - fallback to traditional Timer method for DB flush.'
        'To enable advanced scheduling, do "pip install git+https://github.com/dbader/schedule.git"')


LOGGER_NAME = 'genpot'


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        socketserver.UDPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

        # default logger
        self.logger = logging.getLogger(LOGGER_NAME)

        # transaction_log will hold list of scanners/attackers, count of packets and last seen time
        self.transaction_log = {}

        # dict storing statistical info (last packet, highest packet count etc.)
        # access to this dict is also protected by tx_log_lock
        self.transaction_stats = {}
        self.transaction_stats['max'] = ('', 0)
        self.transaction_stats['last'] = ('', datetime.datetime(1900, 1, 1))

        # set of ip addresses that have not yet been flushed to database
        self.ip_log = set()

        # lock for synchronization of transaction log access
        self.tx_log_lock = threading.Lock()

        # if schedule module is used for periodic database flush, terminate the thread
        # by signaling the event
        self.flush_db_event = None


    def stop(self):
        # shutdown UDP server by calling internal function
        self.shutdown()

        # socket is still active because shutdown() inside SocketServer just exits serve_forever
        # need to explicitly close the socket!
        self.server_close()

        # flush transaction log to database
        self._flush_to_db()

        # set shutdown event for scheduling if schedule module is used
        if self.flush_db_event:
            self.flush_db_event.set()

        # wait for all queue entries to be processed
        self.log_queue.join()

    def handle_error(self, request, client_address):
        # overriden base function with the purpose of graceful error handling
        addr = client_address[0]
        port = client_address[1]

        self.logger.error('Error ocurred during communication with client %s:%d' % (addr, port))

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

    def _flush_to_db(self):
        with self.tx_log_lock:
            if len(self.ip_log):
                self.logger.info('Flushing information for %d IP(s) to database...' % len(self.ip_log))
                for ip in self.ip_log:
                    self._flush_ip_info(ip)

                self.ip_log.clear()

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

    def _flush_ip_info(self, ip):
        """Store recorded information about an IP address to database.

        Parameters:
        ip - IP address to be processed in string format
        """
        raise NotImplementedError()


def _load_state(log_queue, output_queue):
    log_queue.put({'type': 'load'})
    while True:
        log = output_queue.get()
        if log['type'] == 'load':
            # signal completion
            output_queue.task_done()
            logging.getLogger(LOGGER_NAME).info('Restored previous DB state - %d unique IPs loaded' % len(log['payload']))
            return log['payload']
        else:
            # item of a different type obtained from the output queue, put it back
            output_queue.task_done()
            output_queue.put(log)


def create_base_server(ThreadedServer, PotServer, conf, logger_name, log_queue, output_queue, hpf_client=None, alerter=None):
    global LOGGER_NAME
    LOGGER_NAME = logger_name
    ip = conf.get('general', 'listen_ip')
    port = conf.getint('general', 'listen_port')
    server = ThreadedServer((ip, port), PotServer)

    server.log_queue = log_queue
    server.output_queue = output_queue
    server.packet_flush_interval = conf.getint('logging', 'packet_flush_interval')
    server.log_req_packets = conf.getboolean('logging', 'log_req_packets')
    # some pots do not have response packets!
    if conf.has_option('logging', 'log_resp_packets'):
        server.log_resp_packets = conf.getboolean('logging', 'log_resp_packets')

    server.hpfeeds_client = hpf_client
    server.alerter = alerter 
    server.transaction_log = _load_state(log_queue, output_queue)

    server.threshold = conf.getint('attack', 'packet_threshold')
    new_attack_interval = conf.getint('attack', 'new_attack_detection_interval')
    server.new_attack_interval = datetime.timedelta(minutes=new_attack_interval)

    server.schedule_db_flush()

    return server, ip, port
