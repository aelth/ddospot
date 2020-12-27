#!/usr/bin/env python3

import os
import signal
import threading

from . import generic
import core.potloader as potloader
import core.utils as utils
from .dblogger import DBThread


class GenericPot(potloader.PotLoader):
    """ Implementation of generic honeypot that listens on an arbitrary UDP port
        and responds with a random response of a given size or with a predefined pattern.
    """
    def name(self):
        return 'generic'

    def _create_server(self):
        return generic.create_server(
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
        return os.path.join(os.path.dirname(__file__), 'genericpot.conf')

    def _detailed_status(self, status):
        port = self.server.server_address[1]
        avg_amp = float('{0:.2f}'.format(status['avg_amp']))
        pkt_in_bytes = utils.format_unit(status['packets_in_bytes'])

        stats = [
                    ['Average amplification', utils.sep_thousand(avg_amp)],
                    ['Traffic IN/OUT', pkt_in_bytes],
                ]

        return stats

    # override of default function for obtaining payload inside status structure
    # setup function is generic enough for display, but since generic honeypot is
    # port-specific, return structure for the currently bound port
    def _extract_status_payload(self, stats):
        port = self.server.server_address[1]
        payload = stats['payload']
        if port in payload:
            port_stats = payload[port]
            specific = payload['specific']
            port_stats['specific'] = {
                                        'avg_amp': specific['avg_amp'][port],
                                        'packets_in_bytes': specific['packets_in_bytes'][port]
                                     }
            return port_stats
        else:
            utils.print_warn('Port %d not found in the database, statistics not available' % (port))
            # set total_attacks parameter to zero in order to signal empty statistics table
            return {'total_attacks': 0}


if __name__ == "__main__":
    genericpot = GenericPot()
    genericpot.setup()
    t = threading.Thread(target=genericpot.run)
    t.start()
    genericpot.potthread = t
    signal.signal(signal.SIGINT, genericpot.shutdown_signal_wrapper)
    signal.pause()
