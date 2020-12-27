#!/usr/bin/env python3

# Heavily based on Alessandro Tanasi's (@jekil) UDPot - http://github.com/jekil/UDPot
import os
import signal
import threading

from . import dns
import core.potloader as potloader
import core.utils as utils

from .dblogger import DBThread


class DNSPot(potloader.PotLoader):
    """ Implementation of DNS honeypot open resolver
    """
    # override run because no KeyboardInterrupt handler should be present
    def run(self):
        if self.setup_error:
            msg = 'Error during initialization, DNSPot will not be started...'
            print(msg)
            if self.logger:
                self.logger.error(msg)
            return
        self.state = 'Running'
        self._start_server()

    def name(self):
        return 'dns'

    def _create_server(self):
        return dns.create_server(
                                self.conf,
                                self.name(),
                                self.log_queue,
                                self.output_queue,
                                self.hpfeeds_client,
                                self.alerter
                               )

    def _create_dbthread(self, dbfile, new_attack_interval):
        return DBThread(
                        dbfile,
                        self.name(),
                        self.log_queue,
                        self.output_queue,
                        self.stop_event,
                        new_attack_interval
                        )

    def _start_server(self):
        self.server.run()

    def _get_config_path(self):
        return os.path.join(os.path.dirname(__file__), 'dnspot.conf')

    def _detailed_status(self, status):
        avg_amp = float('{0:.2f}'.format(status['avg_amp']))
        top_amps = tuple(x[0] + ' -- amplification: ' + str(x[1]) + 'x, response size: ' + utils.format_unit(x[2]) for x in status['top5_amp_domains'])
        top_domains = tuple(x[0] + ' -- use count: ' + utils.sep_thousand(x[1]) + ', amplification: ' + str(x[2]) + 'x' for x in status['top5_domains'])
        stats = [
                    ['Average DNS amplification', utils.sep_thousand(avg_amp)],
                    ['Top domains by amp', top_amps],
                    ['Most common domains', top_domains],
                ]
        return stats

if __name__ == "__main__":
    dnspot = DNSPot()
    dnspot.setup()
    t = threading.Thread(target=dnspot.run)
    t.start()
    dnspot.potthread = t
    signal.signal(signal.SIGINT, dnspot.shutdown_signal_wrapper)
    signal.pause()
