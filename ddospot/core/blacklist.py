#!/usr/bin/env python3

import datetime
import logging
import threading
import time

try:
    import schedule
except ImportError:
    exit(
        'Disable blacklists in configuration file or install schedule module '
        'to enable blacklist creation: "pip install git+https://github.com/dbader/schedule.git"')

from . import utils


class Blacklist():
    def __init__(self, conf, name, get_attackers_fn):
        self.conf = conf
        self.name = name
        self.dbfile = self.conf.get('logging', 'sqlitedb')
        self.logger = logging.getLogger(self.name)
        self.get_attackers_fn = get_attackers_fn

    def schedule_blacklist_creation(self):
        schedule_event = None

        run_daily = self.conf.get('blacklist', 'daily_at')
        # do simple format check of blacklist creation intervals
        try:
            time.strptime(run_daily, '%H:%M')
        except ValueError as msg:
            self.logger.error('Illegal blacklist creation interval specified: %s.' % msg)
            self.logger.info('Using default time interval (daily at 16:00)')
            run_daily = '16:00'

        bl_file_base = self.conf.get('blacklist', 'blacklist_file')
        bl_packet_threshold = self.conf.getint('blacklist', 'blacklist_packet_threshold')

        # dump initial blacklist, after startup
        self._dump_blacklists(bl_file_base, bl_packet_threshold)

        # schedule blacklist creation at specified daily interval
        schedule.every().day.at(run_daily).do(
                                                self._dump_blacklists,
                                                bl_file_base,
                                                bl_packet_threshold)
        schedule_event = self._run_continuously()

        return schedule_event

    def _run_continuously(self):
        cease_continuous_run = threading.Event()

        class ScheduleThread(threading.Thread):
            @classmethod
            def run(cls):
                while not cease_continuous_run.is_set():
                    schedule.run_pending()
                    time.sleep(10)

                self.logger.info('Blacklist scheduler received shutdown signal, exiting...')

        continuous_thread = ScheduleThread()
        continuous_thread.start()
        return cease_continuous_run

    def _dump_blacklists(self, blacklist_file, packet_threshold):
        attackers = self.get_attackers_fn(packet_threshold)

        with open(blacklist_file + '-full.txt', 'w+') as bl_full, \
             open(blacklist_file + '-daily.txt', 'w+') as bl_daily, \
             open(blacklist_file + '-weekly.txt', 'w+') as bl_weekly:
            curtime = datetime.datetime.now()
            tdelta_week = datetime.timedelta(weeks=1)
            tdelta_day = datetime.timedelta(days=1)

            bl_full.write(
                    '# %s blacklist\n# '
                    'List of all scanners/attackers\n# '
                    'Generated: %s\n' % (self.name, curtime))

            bl_daily.write(
                    '# %s blacklist\n# '
                    'Daily list of scanners/attackers for period %s - %s\n' % (self.name, curtime - tdelta_day, curtime))
            bl_weekly.write(
                    '# %s blacklist\n# '
                    'Weekly list of scanners/attackers for period %s - %s\n' % (self.name, curtime - tdelta_week, curtime))

            week_attack_count = 0
            day_attack_count = 0

            for ip in sorted(attackers.keys()):
                ip_str = utils.int_to_addr(ip)
                bl_full.write('%s\n' % ip_str)

                scan_date = attackers[ip]
                tdelta = curtime - scan_date
                # write weekly blacklist, all IPs that scanned pot during the last 7 days
                if tdelta <= tdelta_week:
                    bl_weekly.write('%s\n' % ip_str)
                    week_attack_count += 1

                    # write daily blacklist
                    if tdelta <= tdelta_day:
                        bl_daily.write('%s\n' % ip_str)
                        day_attack_count += 1

            self.logger.info('Full blacklist written: %d scanners/attackers detected' % len(attackers))
            self.logger.info('Weekly blacklist written: %d scanners/attackers detected' % week_attack_count)
            self.logger.info('Daily blacklist written: %d scanners/attackers detected' % day_attack_count)
