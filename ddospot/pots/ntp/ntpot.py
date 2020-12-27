#!/usr/bin/env python3

import os
import signal
import threading

from . import ntp
import core.potloader as potloader
import core.utils as utils
from .dblogger import DBThread


class NTPot(potloader.PotLoader):
    """ Implementation of NTP honeypot that responds to NTP messages type 3, 6 and 7.
    """

    def name(self):
        return 'ntp'

    def _create_server(self):
        # general assumption is that the parameters (log_queue, output_queue)
        # are already properly created/configured prior to calling this function
        return ntp.create_server(
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
        return os.path.join(os.path.dirname(__file__), 'ntpot.conf')

    def _detailed_status(self, status):
        avg_amp = float('{0:.2f}'.format(status['avg_amp']))
        pkt_in_bytes = utils.format_unit(status['packets_in_bytes'])
        modes = ()
        for mode_pair in status['modes']:
            mode = mode_pair[0]
            mode_count = mode_pair[1]
            if mode == 1 or mode == 2:
                mode_str = 'SYMMETRIC (1 or 2): '
            elif mode == 3:
                mode_str = 'CLIENT (3): '
            elif mode == 4:
                mode_str = 'SERVER (4): '
            elif mode == 5:
                mode_str = 'BROADCAST (5): '
            elif mode == 6:
                mode_str = 'CONTROL (6): '
            elif mode == 7:
                mode_str = 'PRIVATE/MONLIST (7): '
            else:
                mode_str = 'UNKNOWN (%s): ' % (mode)

            count = utils.sep_thousand(mode_count)
            mode_str += count
            modes += (mode_str,)

        stats = [
                    ['Average amplification', utils.sep_thousand(avg_amp)],
                    ['Traffic IN/OUT', pkt_in_bytes],
                    ['NTP modes distribution', modes],
                ]
        return stats


if __name__ == "__main__":
    ntpot = NTPot()
    ntpot.setup()
    t = threading.Thread(target=ntpot.run)
    t.start()
    ntpot.potthread = t
    signal.signal(signal.SIGINT, ntpot.shutdown_signal_wrapper)
    signal.pause()
