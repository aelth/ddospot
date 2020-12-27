#!/usr/bin/env python3

import os
import signal
import threading

from . import chargen
import core.potloader as potloader
import core.utils as utils
from .dblogger import DBThread


class CgenPot(potloader.PotLoader):
    """ Implementation of Chargen honeypot that responds to any UDP request with
    characteristic pattern, similar to XINETd implementation of chargen.
    """
    def name(self):
        return 'chargen'

    def _create_server(self):
        return chargen.create_server(
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
        return os.path.join(os.path.dirname(__file__), 'chargenpot.conf')

    def _detailed_status(self, status):
        avg_amp = float('{0:.2f}'.format(status['avg_amp']))
        pkt_in_bytes = utils.format_unit(status['packets_in_bytes'])

        stats = [
                    ['Average amplification', utils.sep_thousand(avg_amp)],
                    ['Traffic IN/OUT', pkt_in_bytes],
                ]

        return stats


if __name__ == "__main__":
    cgenpot = CgenPot()
    cgenpot.setup()
    t = threading.Thread(target=cgenpot.run)
    t.start()
    cgenpot.potthread = t
    signal.signal(signal.SIGINT, cgenpot.shutdown_signal_wrapper)
    signal.pause()
