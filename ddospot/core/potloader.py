import configparser
import datetime
import logging
import logging.handlers
import queue
import threading

try:
    import hpfeeds
except ImportError:
    exit('Please install hpfeeds: "pip install hpfeeds"')

from . import spf
from . import utils


class PotLoader(object, metaclass=spf.MountPoint):
    """Plugins must inherit this mount point in order to be recognized as proper plugins.

    Plugins must implement the following methods:
        * name(self) - returns name of the module
        * _create_server(self) - creates the honeypot instance and returns it to the caller.
            This function is used in setup method and MUST be called after DB thread, logger and blacklist has been properly configured.
        * _start_server(self) - starts the honeypot server instance.
        * _create_dbthread(self, dbfile, name, log_queue, output_queue, stop_event, attack interval) - creates thread responsible for DB interaction
        * _get_config_path(self) - returns full path to pot's configuration file
        * _detailed_status(self, status) - returns list of lists containing honeypot-specific statistics

    Plugins should additionally override following methods if generic implementation is not sufficient:
        * setup(self)
        * run(self)
        * status(self)
        * shutdown(self)
        * get_attacker_blacklist(self, attacker_threshold) - returns dictionary {ip: last_seen}.
          Used for blacklist creation and passed as a function to Blacklist object.
          Takes attacker_threshold parameter - upper packet limit that differentiates between an attack and a target in reflection attacks (specified in configuration file)
        * _extract_status_payload(self, stats) - returns dictionary with predefined statistic parameters extracted from message received from database thread.
                                                 Base implementation should be sufficient for all honeypots, so override only if necessary.
    """
    conf = None
    setup_error = False
    state = 'Undefined'

    def __init__(self):
        pass

    def setup(self):
        try:
            print(('Starting %s, please wait...' % self.name()))
            # load configuration file
            self._load_config()

            # create file logger
            self._setup_logger(self.name())

            # logging to DB will take place in a separate thread
            # all data will be passed through log_queue
            # stop event will be set when keyboard interrupt is triggered
            # DB thread will exit after certain timeout
            self._setup_dbthread()

            # check if blacklist creation is enabled and schedule blacklist creation
            self._setup_blacklist()

            # create hpfeeds client
            self._setup_hpfeeds()

            # create notification 'manager'
            self._setup_alerting()

            # finally, create honeypot server instance - this call MUST be last, since it depends on dbthread etc.
            self.state = 'Starting'
            self.server = self._create_server()
        except configparser.Error as msg:
            out_msg = 'Error occurred while parsing configuration file: %s' % msg
            print(out_msg)
            if self.logger:
                self.logger.error(out_msg)
            self.setup_error = True
            self.state = 'Config-error'
        except Exception as msg:
            out_msg = 'Error occurred during %s initialization: %s' % (self.name(), msg)
            print(out_msg)
            if self.logger:
                self.logger.error(out_msg)
            self.setup_error = True
            self.state = 'Init-error'

    def run(self):
        if self.setup_error:
            msg = 'Error during initialization, %s will not be started...' % (self.name())
            print(msg)
            if self.logger:
                self.logger.error(msg)
            return
        try:
            self.state = 'Running'
            self._start_server()
        except KeyboardInterrupt:
            msg = 'CTRL-C pressed, exiting %s...' % (self.name())
            print(msg)
            self.logger.info(msg)
            self.shutdown()
        except Exception as msg:
            msg = 'Error while running %s, exiting...' % (self.name())
            print(msg)
            self.logger.info(msg)
            self.state = 'Exec-error'

    def status(self, short=True):
        if short:
            return self.state

        # obtain detailed pot status by enqueuing thread task
        self.log_queue.put({'type': 'stats'})
        while True:
            stats_msg = self.output_queue.get()
            if stats_msg['type'] == 'stats':
                try:
                    self.output_queue.task_done()
                    payload = self._extract_status_payload(stats_msg)
                    total_attacks = payload['total_attacks']

                    if total_attacks == 0:
                        total_ips = 0
                        total_packets = 0
                        first_attack_msg = '-'
                        last_attack_msg = '-'
                        avg_attack_msg = '-'
                        longest_attack_msg = '-'
                        largest_attack_msg = '-'
                        top_attack_msg = '-'
                        detailed_stats = []
                    else:
                        total_ips = payload['total_ips']
                        total_packets = payload['total_packets']
                        first_attack = payload['first_attack']
                        first_attack_msg = utils.int_to_addr(first_attack[0]) + ' @ ' + str(first_attack[1])
                        last_attack = payload['last_attack']
                        last_attack_msg = utils.int_to_addr(last_attack[0]) + ' @ ' + str(last_attack[1])
                        avg_attack_msg = utils.format_timedelta(datetime.timedelta(days=payload['avg_attack_duration']))
                        longest_attack = payload['longest_cont_attack']
                        longest_attack_dur = datetime.timedelta(days=longest_attack[1])

                        # handle case when only one packet was received from the given IP (or one packet per multiple IPs are stored in the DB)
                        if longest_attack[2] == longest_attack[3]:
                            longest_attack_msg = utils.int_to_addr(longest_attack[0]) + ', one packet received @ ' + str(longest_attack[2])
                        else:
                            longest_attack_msg = utils.int_to_addr(longest_attack[0]) + ', ' +\
                                                 utils.format_timedelta(longest_attack_dur) + ' (' +\
                                                 str(longest_attack[2]) + ' - ' + str(longest_attack[3]) + '), ' +\
                                                 'pkt. count: ' + utils.sep_thousand(longest_attack[4]) + ' (' +\
                                                 utils.sep_thousand(float('{0:.2f}'.format(longest_attack[4] / longest_attack_dur.total_seconds()))) + ' pps)'
                        largest_attack = payload['largest_cont_attack']
                        largest_attack_dur = datetime.timedelta(days=largest_attack[1])

                        # same as above, case when one packet is received
                        if largest_attack[2] == largest_attack[3]:
                            largest_attack_msg = utils.int_to_addr(largest_attack[0]) + ', one packet received @ ' + str(largest_attack[2])
                        else:
                            largest_attack_msg = utils.int_to_addr(largest_attack[0]) + ', ' +\
                                                 utils.format_timedelta(largest_attack_dur) + ' (' +\
                                                 str(largest_attack[2]) + ' - ' + str(largest_attack[3]) + '), ' +\
                                                 'pkt. count: ' + utils.sep_thousand(largest_attack[4]) + ' (' + \
                                                 utils.sep_thousand(float('{0:.2f}'.format(largest_attack[4] / largest_attack_dur.total_seconds()))) + ' pps)'
                        top_attack = payload['top_attack']
                        top_attack_msg = utils.int_to_addr(top_attack[0]) + ' (' + str(top_attack[1]) + ' - ' + str(top_attack[2]) + '), pkt. count: ' + utils.sep_thousand(top_attack[3])
                        detailed_stats = self._detailed_status(payload['specific'])

                    statistics_list = [
                                        ['Number of IPs', utils.sep_thousand(total_ips)],
                                        ['Number of attacks', utils.sep_thousand(total_attacks)],
                                        ['Total num. of packets recv.', utils.sep_thousand(total_packets)],
                                        ['First attack', first_attack_msg],
                                        ['Latest attack', last_attack_msg],
                                        ['Average attack duration', avg_attack_msg],
                                        ['Longest continuous attack', longest_attack_msg],
                                        ['Largest continuous attack', largest_attack_msg],
                                        ['Top target (by pkt. count)', top_attack_msg],
                                      ]
                    # append detailed (i.e. honeypot-specific) statistics to the list
                    statistics_list.extend(detailed_stats)
                except:
                    # something went wrong when parsing list, just return empty list
                    utils.print_err('Error creating statistics list')
                    return []

                return statistics_list
            else:
                # put it back
                self.output_queue.task_done()
                self.output_queue.put(stats_msg)

    def shutdown(self):
        # shutdown the server, set stop event for DB thread and schedule event (if present)
        # wait for all threads to exit
        self.logger.info('%s received shutdown signal, exiting...' % (self.name()))
        if not self.setup_error:
            self.server.stop()
        self.state = 'Stopped'
        # no harm in signalling the event,
        # even if blacklist and db threads were not initialized
        self.stop_event.set()
        if self.schedule_event:
            self.schedule_event.set()

    def shutdown_signal_wrapper(self, signal, frame):
        msg = 'CTRL-C pressed, exiting %s...' % (self.name())
        print(msg)
        self.logger.info(msg)
        self.shutdown()

        # wait for pot thread to finish
        self.potthread.join()

    def name(self):
        raise NotImplementedError()

    def get_attacker_blacklist(self, attack_threshold):
        # get blacklist from the db thread
        self.log_queue.put({'type': 'blacklist', 'threshold': attack_threshold})
        while True:
            queue_msg = self.output_queue.get()
            if queue_msg['type'] == 'blacklist':
                self.output_queue.task_done()
                return queue_msg['payload']
            else:
                # put it back
                self.output_queue.task_done()
                self.output_queue.put(queue_msg)

    # helper methods that setup generic and standardized logging structure, hpfeeds client etc.
    def _load_config(self):
        # always read configuration file in the current pot directory
        config_path = self._get_config_path()
        self.conf = configparser.RawConfigParser()
        self.conf.read(config_path)

    def _setup_logger(self, name):
        logfile = self.conf.get('logging', 'log')
        rotate_size = self.conf.getint('logging', 'rotate_size') * (1024*1024)
        keep_backup_log_count = self.conf.getint('logging', 'keep_backup_log_count')

        self.logger = logging.getLogger(name)
        handler = logging.handlers.RotatingFileHandler(logfile, maxBytes=rotate_size, backupCount=keep_backup_log_count)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)-5s - %(levelname)-7s - %(message)s',
            '%Y-%m-%d %H:%M:%S'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    def _setup_dbthread(self):
        attack_interval = self.conf.getint('attack', 'new_attack_detection_interval')
        self.log_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.stop_event.clear()
        dbfile = self.conf.get('logging', 'sqlitedb')
        self.dbthread = self._create_dbthread(dbfile, attack_interval)
        self.dbthread.start()

    def _setup_hpfeeds(self):
        hpfeeds_enabled = self.conf.getboolean('hpfeeds', 'enabled')
        hpfeeds_host = self.conf.get('hpfeeds', 'server')
        hpfeeds_port = self.conf.getint('hpfeeds', 'port')
        hpfeeds_ident = self.conf.get('hpfeeds', 'identifier')
        hpfeeds_secret = self.conf.get('hpfeeds', 'secret')

        if hpfeeds_enabled:
            self.hpfeeds_client = hpfeeds.new(
                                        hpfeeds_host,
                                        hpfeeds_port,
                                        hpfeeds_ident,
                                        hpfeeds_secret)
        else:
            self.hpfeeds_client = None

    def _setup_alerting(self):
        alerting_enabled = self.conf.getboolean('alerting', 'enabled')

        self.alerter = None
        if alerting_enabled:
            try:
                from .alerter import Alerter
                self.alerter = Alerter(self.conf, self.name())
            except:
                # handled in Alerter class and alerter already set to None
                pass

    def _setup_blacklist(self):
        bl_enabled = self.conf.getboolean('blacklist', 'enabled')
        self.schedule_event = None
        if bl_enabled:
            from .blacklist import Blacklist
            bl = Blacklist(self.conf, self.name(), self.get_attacker_blacklist)
            self.schedule_event = bl.schedule_blacklist_creation()

    def _extract_status_payload(self, stats):
        if 'payload' in stats:
            return stats['payload']
        return {}

    def _start_server(self):
        raise NotImplementedError()

    def _create_server(self):
        raise NotImplementedError()

    def _create_dbthread(self, dbfile, attack_interval):
        raise NotImplementedError()

    def _get_config_path(self):
        raise NotImplementedError()

    def _detailed_status(self, status):
        raise NotImplementedError()
