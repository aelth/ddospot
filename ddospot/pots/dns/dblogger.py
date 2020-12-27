#!/usr/bin/env python3

import datetime

try:
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Column, ForeignKey, Integer, SmallInteger, String, DateTime, LargeBinary, Float
    from sqlalchemy.orm import relationship
    from sqlalchemy import func, distinct, desc
except ImportError as e:
    exit(
        'SQLAlchemy requirement is missing. '
        'Please install it with "pip install SQLAlchemy". Error: %s' % e
        )

import core.dbbase as dbbase
import core.utils as utils


class DBThread(dbbase.DBBaseThread):
    Base = declarative_base()

    class Attack(Base):
        __tablename__ = 'dnspot_attack'

        src_id = Column(Integer, ForeignKey('dnspot_sources.src_ip'), primary_key=True)
        domain_id = Column(Integer, ForeignKey('dnspot_domains.id'), primary_key=True)
        start = Column(DateTime, default=datetime.datetime.now(), primary_key=True)
        latest = Column(DateTime, default=None)
        count = Column(Integer, default=1)
        # although number of DNS responses and cached Base64 response
        # are property of a domain, more than a property of an attack,
        # save these attributes with an attack, because of the easier
        # update and correlation with a specific attack
        num_entries = Column(Integer, default=0)
        response = Column(LargeBinary, default=b'')
        amplification = Column(Float, default=0.)
        source = relationship('Source', backref='attacks')
        domain = relationship('Domain', backref='attacks')

    class Source(Base):
        __tablename__ = 'dnspot_sources'

        # IP address is stored as integer
        src_ip = Column(Integer, primary_key=True)
        src_port = Column(Integer)
        first_seen = Column(DateTime, default=datetime.datetime.now())
        last_seen = Column(DateTime, default=datetime.datetime.now())

    class Domain(Base):
        __tablename__ = 'dnspot_domains'

        id = Column(Integer, primary_key=True)
        domain_name = Column(String(255))
        opcode = Column(SmallInteger, default=0)
        dns_type = Column(String(255))
        dns_cls = Column(String(255))
        first_seen = Column(DateTime, default=datetime.datetime.now())

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
        # ip addresses are stored as integers in order to ensure
        # efficient lookups and additions
        addr_int = utils.addr_to_int(db_params['ip'])

        # check if source and domain already exist in the database and add them if necessary
        source = self.session.query(DBThread.Source).\
                      filter(DBThread.Source.src_ip == addr_int).one_or_none()
        domain = self.session.query(DBThread.Domain).\
                      filter(DBThread.Domain.domain_name == db_params['dns_name']).\
                      filter(DBThread.Domain.dns_type == db_params['dns_type']).\
                      filter(DBThread.Domain.dns_cls == db_params['dns_class']).one_or_none()

        if not source:
            source = DBThread.Source(
                                    src_ip=addr_int,
                                    src_port=db_params['port'],
                                    first_seen=db_params['time'],
                                    last_seen=db_params['time']
                                    )
            self.session.add(source)
            self.session.commit()
        else:
            source.last_seen = db_params['time']
        if not domain:
            domain = DBThread.Domain(
                                    domain_name=db_params['dns_name'],
                                    opcode=db_params['opcode'],
                                    dns_type=db_params['dns_type'],
                                    dns_cls=db_params['dns_class'],
                                    first_seen=db_params['time']
                                    )
            self.session.add(domain)
            self.session.commit()

        # add new attack related to the specified source and domain
        attack = DBThread.Attack(
                                src_id=source.src_ip,
                                domain_id=domain.id,
                                start=db_params['time'],
                                latest=db_params['time']
                                )

        self.session.add(attack)
        self.session.commit()

    def _update_attack(self, db_params):
        # two types of update for DNS:
        #   attack - update attack details (query count, last seen, etc.)
        #   domain - update attack domain-related details (number of returned records, amp rate...)
        addr_int = utils.addr_to_int(db_params['ip'])
        for attack in self.session.query(DBThread.Attack).\
                        filter(DBThread.Attack.src_id == addr_int):
            if attack.domain.domain_name == db_params['dns_name'] and\
               attack.domain.dns_type == db_params['dns_type'] and\
               attack.domain.dns_cls == db_params['dns_class']:

                # attack found, check if this is currently active attack
                if attack.latest + self.new_attack_interval >= db_params['last_seen']:
                    if db_params['type'] == 'attack':
                        # update attack and source last seen time
                        attack.source.last_seen = db_params['last_seen']
                        attack.latest = db_params['last_seen']
                        attack.count = db_params['count']
                    elif db_params['type'] == 'domain':
                        attack.num_entries = db_params['num_entries']
                        attack.amplification = db_params['amp']
                        attack.response = db_params['response']

                    self.session.add(attack)

        self.session.commit()

    def _load_requests(self):
        request_log = {}
        for attack in self.session.query(
                                        DBThread.Attack.src_id,
                                        DBThread.Attack.domain_id,
                                        func.max(DBThread.Attack.latest).label('latest'),
                                        DBThread.Attack.count,
                                        ).group_by(DBThread.Attack.src_id):

            for domain in self.session.query(DBThread.Domain).\
                                    filter(DBThread.Domain.id == attack.domain_id):
                ip_str = utils.int_to_addr(attack.src_id)
                req_key = (
                            ip_str,
                            domain.domain_name,
                            domain.dns_type,
                            domain.dns_cls
                          )
                request_log[req_key] = {}
                request_log[req_key]['last_seen'] = attack.latest
                request_log[req_key]['count'] = attack.count

        return request_log

    def _get_detailed_statistics(self):
        # statistics specific for DNS honeypot
        detailed_stats = {}

        # get avg DNS amplification factor
        detailed_stats['avg_amp'] = self.session.query(func.avg(DBThread.Attack.amplification)).scalar()

        # get five domains with biggest amplification factor
        top_amp_domains = []
        detailed_stats['top5_amp_domains'] = top_amp_domains
        for attack in self.session.query(
                                        distinct(DBThread.Attack.amplification).label('amp'),
                                        func.length(DBThread.Attack.response).label('size'),
                                        DBThread.Attack.domain_id
                                        ).group_by('amp').order_by(desc('amp')).limit(5):
            for domain in self.session.query(DBThread.Domain).\
                    filter(DBThread.Domain.id == attack.domain_id):
                # response is stored in Base64 format - MAXIMUM length of plain binary response is (3*b64len)/4
                # if padding exists, number of padding chars must be subtracted from the size calculated above
                # since we don't care about *EXACT* size and do not want to decode the size, the above approximation will suffice
                # see https://en.wikipedia.org/wiki/Base64
                top_amp_domains.append((domain.domain_name, attack.amp, attack.size*3/4))

        # get five most common domains
        top_domains = []
        detailed_stats['top5_domains'] = top_domains
        for attack in self.session.query(
                                        DBThread.Attack.domain_id.label('domain'),
                                        DBThread.Attack.amplification,
                                        func.count(DBThread.Attack.domain_id).label('refs'),
                                        ).group_by('domain').order_by(desc('refs')).limit(5):
            for domain in self.session.query(DBThread.Domain).\
                    filter(DBThread.Domain.id == attack.domain):
                top_domains.append((domain.domain_name, attack.refs, attack.amplification))

        return detailed_stats

    def _get_hosts_timestamps_by_count(self, threshold):
        sources = {}
        for attack in self.session.query(DBThread.Attack).\
                            filter(DBThread.Attack.count <= threshold):
            sources[attack.source.src_ip] = attack.source.last_seen

        return sources
