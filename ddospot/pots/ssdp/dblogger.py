#!/usr/bin/env python3

import datetime

try:
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Column, ForeignKey, Integer, SmallInteger, String, DateTime, LargeBinary
    from sqlalchemy.orm import relationship
    from sqlalchemy import func, desc
except ImportError as e:
    exit(
        'SQLAlchemy requirement is missing. '
        'Please install it with "pip install SQLAlchemy". Error: %s' % e
        )

import core.dbbase as dbbase


class DBThread(dbbase.DBBaseThread):
    Base = declarative_base()

    class Source(Base):
        __tablename__ = 'ssdpot_sources'

        src_ip = Column(Integer, primary_key=True)
        src_port = Column(Integer)
        first_seen = Column(DateTime, default=datetime.datetime.now())
        last_seen = Column(DateTime, default=datetime.datetime.now())

    class Attack(Base):
        __tablename__ = 'ssdpot_attack'

        src_id = Column(Integer, ForeignKey('ssdpot_sources.src_ip'), primary_key=True)
        st = Column(String, primary_key=True)
        start = Column(DateTime, default=datetime.datetime.now(), primary_key=True)
        latest = Column(DateTime, default=None)
        mx = Column(SmallInteger, default=1)
        request_pkt = Column(LargeBinary)
        response_pkt = Column(LargeBinary)
        request_size = Column(Integer, default=0)
        response_size = Column(Integer, default=0)
        count = Column(Integer, default=1)
        source = relationship('Source', backref='attacks')

    def __init__(
                self,
                dbfile,
                logger_name,
                log_queue,
                output_queue,
                stop_event,
                new_attack_interval
                ):
        dbbase.DBBaseThread.__init__(
                                        self,
                                        dbfile,
                                        self.Base,
                                        logger_name,
                                        log_queue,
                                        output_queue,
                                        stop_event,
                                        new_attack_interval
                                    )

    def _add_attack(self, db_params):
        source = self.session.query(DBThread.Source).\
                filter(DBThread.Source.src_ip == db_params['ip']).one_or_none()
        if not source:
            source = DBThread.Source(
                                    src_ip=db_params['ip'],
                                    src_port=db_params['port'],
                                    first_seen=db_params['time'],
                                    last_seen=db_params['time']
                                    )
            self.session.add(source)
        else:
            # update last_seen timestamp for existing source
            source.last_seen = db_params['time']

        attack = DBThread.Attack(
                                src_id=source.src_ip,
                                st=db_params['st'],
                                start=db_params['time'],
                                latest=db_params['time'],
                                mx=db_params['mx'],
                                request_pkt=db_params['request_pkt'],
                                response_pkt=db_params['response_pkt'],
                                request_size=db_params['input_size'],
                                response_size=db_params['output_size']
                                )

        self.session.add(attack)
        self.session.commit()

    def _update_attack(self, db_params):
        for attack in self.session.query(DBThread.Attack).\
                                   filter(DBThread.Attack.src_id == db_params['ip']).\
                                   filter(DBThread.Attack.st == db_params['st']):
            # check if this is currently active attack
            if attack.latest + self.new_attack_interval >= db_params['last_seen']:
                # update attack and source last seen time
                attack.source.last_seen = db_params['last_seen']
                attack.latest = db_params['last_seen']
                attack.count = db_params['count']
                self.session.add(attack)

        self.session.commit()

    def _load_requests(self):
        request_log = {}
        for attack in self.session.query(
                                        DBThread.Attack.src_id,
                                        DBThread.Attack.st,
                                        func.max(DBThread.Attack.latest).label('latest'),
                                        DBThread.Attack.count,
                                        ).group_by(DBThread.Attack.src_id):
            req_key = (
                        attack.src_id,
                        attack.st
                      )
            request_log[req_key] = {}
            request_log[req_key]['last_seen'] = attack.latest
            request_log[req_key]['count'] = attack.count

        return request_log

    def _get_detailed_statistics(self):
        # statistics specific for SSDP honeypot

        detailed_stats = {}

        detailed_stats['avg_amp'] = self.session.query(func.avg(DBThread.Attack.response_size / DBThread.Attack.request_size)).scalar()
        detailed_stats['packets_in_bytes'] = self.session.query(func.sum(DBThread.Attack.request_size * DBThread.Attack.count)).scalar()
        # TODO: out bytes not correct - we need to know threshold!!!
        #detailed_stats['packets_out_bytes'] = self.session.query(func.sum(DBThread.Attack.request_size * DBThread.Attack.count)).scalar()

        targets = []
        detailed_stats['st'] = targets
        for attack in self.session.query(
                                        DBThread.Attack.st.label('st'),
                                        func.count(DBThread.Attack.st).label('st_count'),
                                        ).group_by('st').order_by(desc('st_count')).limit(5):
            targets.append((attack.st, attack.st_count))

        return detailed_stats

    def _get_hosts_timestamps_by_count(self, threshold):
        sources = {}
        for attack in self.session.query(DBThread.Attack).\
                      filter(DBThread.Attack.count <= threshold):
            sources[attack.source.src_ip] = attack.source.last_seen

        return sources
