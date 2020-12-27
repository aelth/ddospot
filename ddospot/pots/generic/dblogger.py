#!/usr/bin/env python3

import datetime

try:
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Column, ForeignKey, Integer, BigInteger, DateTime, LargeBinary
    from sqlalchemy.orm import relationship
    from sqlalchemy import func, distinct, desc
except ImportError as e:
    exit(
        'SQLAlchemy requirement is missing. '
        'Please install it with "pip install SQLAlchemy". Error: %s' % e
        )

import core.dbbase as dbbase


class DBThread(dbbase.DBBaseThread):
    Base = declarative_base()

    class Source(Base):
        __tablename__ = 'genericpot_sources'

        src_ip = Column(Integer, primary_key=True)
        src_port = Column(Integer)
        first_seen = Column(DateTime, default=datetime.datetime.now())
        last_seen = Column(DateTime, default=datetime.datetime.now())

    class Attack(Base):
        __tablename__ = 'genericpot_attack'

        src_id = Column(Integer, ForeignKey('genericpot_sources.src_ip'), primary_key=True)
        # since generic pot can be started on any port, it is useful to store the port in the DB
        dst_port = Column(Integer, primary_key=True)
        start = Column(DateTime, default=datetime.datetime.now(), primary_key=True)
        latest = Column(DateTime, default=None)
        request_pkt = Column(LargeBinary)
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
                                dst_port=db_params['dport'],
                                start=db_params['time'],
                                latest=db_params['time'],
                                request_pkt=db_params['request_pkt'],
                                request_size=db_params['input_size'],
                                response_size=db_params['output_size']
                                )

        self.session.add(attack)
        self.session.commit()

    def _update_attack(self, db_params):
        for attack in self.session.query(DBThread.Attack).\
                filter(DBThread.Attack.src_id == db_params['ip']).\
                filter(DBThread.Attack.dst_port == db_params['dport']):
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
                                        DBThread.Attack.dst_port,
                                        func.max(DBThread.Attack.latest).label('latest'),
                                        DBThread.Attack.count
                                        ).group_by(DBThread.Attack.src_id):
            key = (attack.src_id, attack.dst_port)
            request_log[key] = {}
            request_log[key]['last_seen'] = attack.latest
            request_log[key]['count'] = attack.count

        return request_log

    def _get_statistics(self):
        # overridden base method because generic honeypot can be ran on any port
        # extract statistics by port!
        stats = {}

        for attack in self.session.query(distinct(self.Attack.dst_port).label('dport')):
            stats[attack.dport] = {}

        for attack in self.session.query(
                                        func.count(self.Attack.src_id).label('src_count'),
                                        self.Attack.dst_port.label('dport')
                                        ).group_by('dport'):
            stats[attack.dport]['total_ips'] = attack.src_count

        for attack in self.session.query(
                                        func.count('*').label('total_count'),
                                        func.sum(self.Attack.count).label('total_packets'),
                                        self.Attack.dst_port.label('dport')
                                        ).group_by('dport'):
            stats[attack.dport]['total_attacks'] = attack.total_count
            stats[attack.dport]['total_packets'] = attack.total_packets

        for attack in self.session.query(
                                        self.Attack.src_id.label('src'),
                                        func.min(self.Attack.start).label('first_start'),
                                        self.Attack.dst_port.label('dport')
                                        ).group_by('dport'):
            stats[attack.dport]['first_attack'] = (attack.src, attack.first_start)

        for attack in self.session.query(
                                        self.Attack.src_id.label('src'),
                                        func.max(self.Attack.latest).label('last_start'),
                                        self.Attack.dst_port.label('dport')
                                        ).group_by('dport'):
            stats[attack.dport]['last_attack'] = (attack.src, attack.last_start)


        for attack in self.session.query(
                                        self.Attack.src_id.label('src'),
                                        func.max(func.julianday(self.Attack.latest) - func.julianday(self.Attack.start)).label('duration'),
                                        self.Attack.start,
                                        self.Attack.latest,
                                        self.Attack.count,
                                        self.Attack.dst_port.label('dport')
                                        ).group_by('dport'):
            stats[attack.dport]['longest_cont_attack'] = (attack.src, attack.duration, attack.start, attack.latest, attack.count)

        for attack in self.session.query(
                                        self.Attack.src_id.label('src'),
                                        (func.julianday(self.Attack.latest) - func.julianday(self.Attack.start)).label('duration'),
                                        self.Attack.start,
                                        self.Attack.latest,
                                        func.max(self.Attack.count).label('pkt_sum'),
                                        self.Attack.dst_port.label('dport')
                                        ).group_by('dport'):
            stats[attack.dport]['largest_cont_attack'] = (attack.src, attack.duration, attack.start, attack.latest, attack.pkt_sum)




        for attack in self.session.query(
                                        func.avg(func.julianday(self.Attack.latest) - func.julianday(self.Attack.start)).label('avg_duration'),
                                        self.Attack.dst_port.label('dport')
                                        ).group_by('dport'):
            stats[attack.dport]['avg_attack_duration'] = attack.avg_duration

        for attack in self.session.query(
                                        self.Attack.src_id.label('src'),
                                        func.min(self.Attack.start).label('start_min'),
                                        func.max(self.Attack.latest).label('latest_max'),
                                        func.sum(self.Attack.count).label('total_count'),
                                        self.Attack.dst_port.label('dport')
                                        ).group_by('src','dport').\
                                        order_by(desc('total_count')):
                if 'top_attack' not in stats[attack.dport] or attack.total_count > stats[attack.dport]['top_attack'][3]:
                        stats[attack.dport]['top_attack'] = (attack.src, attack.start_min, attack.latest_max, attack.total_count)

        # detailed (honeypot specific) details will be present as a dictionary under 'specific' key
        stats['specific'] = self._get_detailed_statistics()

        return stats


    def _get_detailed_statistics(self):
        # statistics specific for generic honeypot
        detailed_stats = {}

        amps = {}
        in_bytes = {}
        detailed_stats['avg_amp'] = amps
        detailed_stats['packets_in_bytes'] = in_bytes
        for attack in self.session.query(
                                        func.avg(DBThread.Attack.response_size / DBThread.Attack.request_size).label('amp_avg'),
                                        func.sum(DBThread.Attack.request_size * DBThread.Attack.count).label('in_bytes'),
                                        DBThread.Attack.dst_port.label('dport')
                                        ).group_by('dport'):
            amps[attack.dport] = attack.amp_avg
            in_bytes[attack.dport] = attack.in_bytes

        return detailed_stats

    def _get_hosts_timestamps_by_count(self, threshold):
        sources = {}
        for attack in self.session.query(DBThread.Attack).\
                      filter(DBThread.Attack.count <= threshold):
            sources[attack.source.src_ip] = attack.source.last_seen

        return sources
