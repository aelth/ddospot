#!/usr/bin/env python3

import os
import signal
import threading

from . import ssdp
import core.potloader as potloader
import core.utils as utils
from .dblogger import DBThread


class SSDPot(potloader.PotLoader):
    """ Implementation of SSDP honeypot that responds to M-SEARCH requests.
    """
    def name(self):
        return 'ssdp'

    def _create_server(self):
        return ssdp.create_server(
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
        self.server.serve_forever()

    def _get_config_path(self):
        return os.path.join(os.path.dirname(__file__), 'ssdpot.conf')

    def _detailed_status(self, status):
        avg_amp = float('{0:.2f}'.format(status['avg_amp']))
        pkt_in_bytes = utils.format_unit(status['packets_in_bytes'])
        targets = ()
        for target in status['st']:
            target_str = target[0] + ': ' + utils.sep_thousand(target[1])
            targets += (target_str,)

        stats = [
                    ['Average amplification', utils.sep_thousand(avg_amp)],
                    ['Traffic IN/OUT', pkt_in_bytes],
                    ['SSDP search targets', targets],
                ]
        return stats


if __name__ == "__main__":
    ssdpot = SSDPot()
    ssdpot.setup()
    t = threading.Thread(target=ssdpot.run)
    t.start()
    ssdpot.potthread = t
    signal.signal(signal.SIGINT, ssdpot.shutdown_signal_wrapper)
    signal.pause()
