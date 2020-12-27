#!/usr/bin/env python3

import abc
import datetime
import logging
import queue
import threading

try:
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import create_engine, func, desc
except ImportError as e:
    exit(
        'SQLAlchemy requirement is missing. '
        'Please install it with "pip install SQLAlchemy". Error: %s' % e
        )


class DBBaseThread(threading.Thread, metaclass=abc.ABCMeta):
    def __init__(
                self,
                dbfile,
                decl_base,
                logger_name,
                log_queue,
                output_queue,
                stop_event,
                new_attack_interval
                ):
        threading.Thread.__init__(self)
        if not dbfile.startswith('sqlite:///'):
            dbfile = 'sqlite:///' + dbfile
        self.dbfile = dbfile
        self.log_queue = log_queue
        self.output_queue = output_queue
        self.logger = logging.getLogger(logger_name)
        self.stop_event = stop_event
        self.new_attack_interval = datetime.timedelta(minutes=new_attack_interval)

        # setup database
        self.engine = create_engine(self.dbfile)
        decl_base.metadata.create_all(self.engine)
        decl_base.metadata.bind = self.engine
        DBSession = sessionmaker(bind=self.engine)
        self.session = DBSession()

    def run(self):
        while not self.stop_event.is_set():
            try:
                entry = self.log_queue.get(timeout=5)

                if entry['type'] == 'update':
                    self._update_attack(entry['db_params'])
                elif entry['type'] == 'insert':
                    self._add_attack(entry['db_params'])
                elif entry['type'] == 'load':
                    # load state from the database and put in queue read by the server
                    self.output_queue.put({'type': 'load', 'payload': self._load_requests()})
                elif entry['type'] == 'blacklist':
                    # get ip-timestamp dictionary for blacklist creation
                    attack_threshold = entry['threshold']
                    self.output_queue.put({'type': 'blacklist', 'payload': self._get_hosts_timestamps_by_count(attack_threshold)})
                elif entry['type'] == 'stats':
                    self.output_queue.put({'type': 'stats', 'payload': self._get_statistics()})
                else:
                    self.logger.error('Unknown database thread item: %s' % entry['type'])

                # signal all queue-users that we processed the item
                self.log_queue.task_done()
            except queue.Empty:
                # condition in while statement will determine whether the thread should exit
                pass
            except SQLAlchemyError as msg:
                self.logger.error('Error occurred during DB access: %s' % msg)

        self.logger.info('DB logger received shutdown signal, exiting...')

    def _get_statistics(self):
        # this is the base method for obtaining base statistics about the running honeypot
        # the method has strong coupling because of the database structure assumptions
        # all honeypots utilizing this method must have the same table-object and column names
        # otherwise, the function must be overriden
        stats = {}
        stats['total_ips'] = self.session.query(func.count('*')).select_from(self.Source).scalar()
        stats['total_attacks'] = self.session.query(func.count('*')).select_from(self.Attack).scalar()
        stats['total_packets'] = self.session.query(func.sum(self.Attack.count)).scalar()
        stats['first_attack'] = self.session.query(
                                                  self.Attack.src_id,
                                                  func.min(self.Attack.start)
                                                  ).one_or_none()
        stats['last_attack'] = self.session.query(
                                                  self.Attack.src_id,
                                                  func.max(self.Attack.latest)
                                                  ).one_or_none()
        stats['longest_cont_attack'] = self.session.query(
                                                  self.Attack.src_id,
                                                  func.max(func.julianday(self.Attack.latest) - func.julianday(self.Attack.start)),
                                                  self.Attack.start,
                                                  self.Attack.latest,
                                                  self.Attack.count
                                                  ).one_or_none()
        stats['largest_cont_attack'] = self.session.query(
                                                  self.Attack.src_id,
                                                  func.julianday(self.Attack.latest) - func.julianday(self.Attack.start),
                                                  self.Attack.start,
                                                  self.Attack.latest,
                                                  func.max(self.Attack.count)
                                                  ).one_or_none()
        stats['avg_attack_duration'] = self.session.query(func.avg(func.julianday(self.Attack.latest) - func.julianday(self.Attack.start))).scalar()
        stats['top_attack'] = self.session.query(
                                                 self.Attack.src_id,
                                                 func.min(self.Attack.start).label('start'),
                                                 func.max(self.Attack.latest).label('latest'),
                                                 func.sum(self.Attack.count).label('total_count')
                                                ).group_by(self.Attack.src_id).\
                                                order_by(desc('total_count')).first()

        # detailed (honeypot specific) details will be present as a dictionary under 'specific' key
        stats['specific'] = self._get_detailed_statistics()

        return stats

    @abc.abstractmethod
    def _add_attack(self, db_params):
        '''Add attack details to database.

        Parameters:
        db_params - honeypot-specific database parameters (ip address, timestamp, etc.)
        '''
        return

    @abc.abstractmethod
    def _update_attack(self, db_params):
        '''Update details of an already existing attack.

        Parameters:
        db_params - honeypot-specific database parameters (updated request count etc.)
        '''
        return

    @abc.abstractmethod
    def _load_requests(self):
        '''Load current attack status from the database.

        Returns dictionary with IP as key and mode, last_seen and count as parameters.
        '''
        return

    @abc.abstractmethod
    def _get_detailed_statistics(self):
        '''Load total number of attackers/IPs, attacks, packet counts, etc.
        Base statistics are populated using _get_statistics method whose implementation
        is already provided.

        Note that the statistics are loaded from the database and usually *DO NOT* represent real-time data.'''
        return

    @abc.abstractmethod
    def _get_hosts_timestamps_by_count(self, threshold):
        '''Load (host,last_seen) where request count is less or equal to threshold.

        Parameters:
        threshold - number of packets/requests that represents the limit for attacker/scanner identification (all sources with less requests are considered attackers)
        '''
        return
