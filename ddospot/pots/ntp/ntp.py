#!/usr/bin/env python3

import abc
import base64
import configparser
import datetime
import json
import logging
import random
import socketserver
import struct
import time
import traceback

import core.utils as utils
import core.genpot as genpot


LOGGER_NAME = 'ntp'


class NTPException(Exception):
    """Exception raised by this module."""
    pass


class _NTPBasePacket(object, metaclass=abc.ABCMeta):
    mode = 0

    _SYSTEM_EPOCH = datetime.date(*time.gmtime(0)[0:3])
    _NTP_EPOCH = datetime.date(1900, 1, 1)
    """delta between system and NTP time"""
    _NTP_DELTA = (_SYSTEM_EPOCH - _NTP_EPOCH).days * 24 * 3600

    class _Request(object, metaclass=abc.ABCMeta):
        @abc.abstractmethod
        def from_data(self, data):
            """Populate Request instance from a NTP packet payload received from the network.

            Parameters:
            data -- buffer payload

            Raises:
            NTPException -- in case of invalid packet format
            """
            return

    class _Response(object, metaclass=abc.ABCMeta):
        @abc.abstractmethod
        def to_data(self):
            """Convert the Response instance to a buffer that can be sent over a socket.

            Returns:
            buffer representing this packet

            Raises:
            NTPException -- in case of invalid field
            """
            return

    def __init__(self):
        self.logger = logging.getLogger(LOGGER_NAME)

    def get_mode(self):
        """Return NTP packet mode."""
        return self.mode

    def handle(self):
        """Parse request and respond with appropriate response - list of packets

        Returns:
        list of response packets - list will usually contain just 1 element
        """
        # WARNING: both calls can raise exception, handle it in the caller!
        req_packet = self._load_request()
        resp_packet = self._handle_response(req_packet)
        return resp_packet

    def _load_request(self):
        """Load request from raw NTP packet payload received from the network.

        Returns:
        Packet in either raw byte array or in packet response class (see target implementation)

        Raises:
        NTPException -- in case of invalid packet format
        """
        req = self._Request()
        req.from_data(self.data)
        return req

    @staticmethod
    def _system_to_ntp_time(timestamp):
        """Convert a system time to a NTP time.

        Parameters:
        timestamp -- timestamp in system time

        Returns:
        corresponding NTP time
        """
        return timestamp + _NTPBasePacket._NTP_DELTA

    @staticmethod
    def _to_int(timestamp):
        """Return the integral part of a timestamp.

        Parameters:
        timestamp -- NTP timestamp

        Retuns:
        integral part
        """
        return int(timestamp)

    @staticmethod
    def _to_frac(timestamp, n=32):
        """Return the fractional part of a timestamp.

        Parameters:
        timestamp -- NTP timestamp
        n         -- number of bits of the fractional part

        Retuns:
        fractional part
        """
        return int(abs(timestamp - _NTPBasePacket._to_int(timestamp)) * 2**n)

    @staticmethod
    def _to_time(integ, frac, n=32):
        """Return a timestamp from an integral and fractional part.

        Parameters:
        integ -- integral part
        frac  -- fractional part
        n     -- number of bits of the fractional part

        Retuns:
        timestamp
        """
        return integ + float(frac) / 2**n

    @abc.abstractmethod
    def get_mode_name(self):
        """Return text description of NTP mode"""
        return

    @abc.abstractmethod
    def _handle_response(self, req_packet):
        """Internal implementation of NTP response, depending on the NTP mode and request packet data"""
        return


# Data packet format and parsing is based on Fyodor Y NTP Honeypot (https://github.com/fygrave/honeyntp)
class NTPMode3Packet(_NTPBasePacket):
    """Class representing mode 3 (client) NTP packet."""
    mode = 3

    _PACKET_FORMAT = "!B B B b 11I"
    """packet format to pack/unpack"""

    class _Request(_NTPBasePacket._Request):
        def from_data(self, data):
            """Populate this instance from a NTP packet payload received from
            the network.

            Parameters:
            data -- buffer payload

            Raises:
            NTPException -- in case of invalid packet format
            """
            try:
                unpacked = struct.unpack(NTPMode3Packet._PACKET_FORMAT,
                        data[0:struct.calcsize(NTPMode3Packet._PACKET_FORMAT)])
            except struct.error:
                raise NTPException("Invalid NTP mode 3 packet.")

            self.leap = unpacked[0] >> 6 & 0x3
            self.version = unpacked[0] >> 3 & 0x7
            self.mode = unpacked[0] & 0x7
            self.stratum = unpacked[1]
            self.poll = unpacked[2]
            self.precision = unpacked[3]
            self.root_delay = float(unpacked[4])/2**16
            self.root_dispersion = float(unpacked[5])/2**16
            self.ref_id = unpacked[6]
            self.ref_timestamp = _NTPBasePacket._to_time(unpacked[7], unpacked[8])
            self.orig_timestamp = _NTPBasePacket._to_time(unpacked[9], unpacked[10])
            self.orig_timestamp_high = unpacked[9]
            self.orig_timestamp_low = unpacked[10]
            self.recv_timestamp = _NTPBasePacket._to_time(unpacked[11], unpacked[12])
            self.tx_timestamp = _NTPBasePacket._to_time(unpacked[13], unpacked[14])
            self.tx_timestamp_high = unpacked[13]
            self.tx_timestamp_low = unpacked[14]

    class _Response(_NTPBasePacket._Response):
        def to_data(self):
            """Convert the instance to a buffer that can be sent over a socket.

            Returns:
            buffer representing this packet

            Raises:
            NTPException -- in case of invalid field
            """
            try:
                packed = struct.pack(NTPMode3Packet._PACKET_FORMAT,
                    (self.leap << 6 | self.version << 3 | self.mode),
                    self.stratum,
                    self.poll,
                    self.precision,
                    self.root_delay,
                    self.root_dispersion,
                    self.ref_id,
                    _NTPBasePacket._to_int(self.ref_timestamp),
                    _NTPBasePacket._to_frac(self.ref_timestamp),
                    self.orig_timestamp_high,
                    self.orig_timestamp_low,
                    _NTPBasePacket._to_int(self.recv_timestamp),
                    _NTPBasePacket._to_frac(self.recv_timestamp),
                    _NTPBasePacket._to_int(self.tx_timestamp),
                    _NTPBasePacket._to_frac(self.tx_timestamp))
            except struct.error as msg:
                raise NTPException("Invalid NTP packet fields: %s" % msg)

            return packed

    def __init__(self, data):
        _NTPBasePacket.__init__(self)
        self.data = data

    @staticmethod
    def set_response_defaults(
            leap=0, version=4, mode=4, stratum=3,
            poll=4, precision=-13, root_delay=0, dispersion=0,
            ref_id=0, ref_ts=0, recv_ts=0, tx_ts=0, ref_timestamp_offset=5):
        """Load NTP mode 3 related settings from the configuration file"""
        """leap second indicator"""
        NTPMode3Packet._Response.leap = leap
        """version - usually NTPv4"""
        NTPMode3Packet._Response.version = version
        """mode - always 4 for NTP response"""
        NTPMode3Packet._Response.mode = mode
        """stratum"""
        NTPMode3Packet._Response.stratum = stratum
        """poll interval"""
        NTPMode3Packet._Response.poll = poll
        """precision"""
        NTPMode3Packet._Response.precision = precision
        """root delay"""
        NTPMode3Packet._Response.root_delay = root_delay
        """root dispersion"""
        NTPMode3Packet._Response.root_dispersion = dispersion
        """reference clock identifier"""
        NTPMode3Packet._Response.ref_id = ref_id
        """reference timestamp"""
        NTPMode3Packet._Response.ref_timestamp = ref_ts
        """originate timestamp"""
        NTPMode3Packet._Response.orig_timestamp = 0
        NTPMode3Packet._Response.orig_timestamp_high = 0
        NTPMode3Packet._Response.orig_timestamp_low = 0
        """receive timestamp"""
        NTPMode3Packet._Response.recv_timestamp = recv_ts
        """transmit timestamp"""
        NTPMode3Packet._Response.tx_timestamp = tx_ts
        NTPMode3Packet._Response.tx_timestamp_high = 0
        NTPMode3Packet._Response.tx_timestamp_low = 0
        """offset from the reference timestamp
        artificial lag to make the server look more realistic"""
        NTPMode3Packet._Response.ref_timestamp_offset = ref_timestamp_offset

    def get_mode_name(self):
        return 'DATA'

    def _handle_response(self, req_packet):
        recv_timestamp = _NTPBasePacket._system_to_ntp_time(time.time())
        tx_timestamp = _NTPBasePacket._system_to_ntp_time(time.time())

        resp_packet = self._Response()

        # set appropriate timestamps in the response packet and convert it to raw data
        resp_packet.ref_timestamp = recv_timestamp - resp_packet.ref_timestamp_offset
        resp_packet.recv_timestamp = recv_timestamp
        resp_packet.tx_timestamp = tx_timestamp
        resp_packet.orig_timestamp_high = req_packet.tx_timestamp_high
        resp_packet.orig_timestamp_low = req_packet.tx_timestamp_low

        # _handle_response must return a list in order to be compatible with other NTP modes that return > 1 response packet
        return [resp_packet.to_data()]


class NTPMode6Packet(_NTPBasePacket):
    """NTP control packet class.
    Contains INCOMPLETE implementation of NTP control packet.
    """
    mode = 6

    _PACKET_FORMAT = "!B B H H H H H"

    class _Request(_NTPBasePacket._Request):
        def from_data(self, data):
            """Populate this instance from a NTP packet payload received from
            the network.

            Parameters:
            data -- buffer payload

            Raises:
            NTPException -- in case of invalid packet format
            """
            try:
                unpacked = struct.unpack(NTPMode6Packet._PACKET_FORMAT,
                        data[0:struct.calcsize(NTPMode6Packet._PACKET_FORMAT)])
            except struct.error:
                raise NTPException("Invalid NTP control packet.")

            self.leap = unpacked[0] >> 6 & 0x3
            self.version = unpacked[0] >> 3 & 0x7
            self.mode = unpacked[0] & 0x7
            self.response_bit = unpacked[1] >> 7 & 0x1
            self.error_bit = unpacked[1] >> 6 & 0x1
            self.more_bit = unpacked[1] >> 5 & 0x1
            self.opcode = unpacked[1] & 0x1f
            self.sequence = unpacked[2]
            self.status = unpacked[3]
            self.assoc_id = unpacked[4]
            self.offset = unpacked[5]
            self.count = unpacked[6]

    class _Response(_NTPBasePacket._Response):
        def __init__(self, leap=0, version=2, resp=0, err=0, more=0,
                opcode=0, sequence=0, status=0, assoc_id=0, offset=0, count=0):
            self.leap = leap
            self.version = version
            self.mode = NTPMode6Packet.mode
            self.response_bit = resp
            self.error_bit = err
            self.more_bit = more
            self.opcode = opcode
            self.sequence = sequence
            self.status = status
            self.assoc_id = assoc_id
            self.offset = offset
            self.count = count

        def to_data(self):
            """Convert the instance to a buffer that can be sent over a socket.

            Returns:
            buffer representing this packet

            Raises:
            NTPException -- in case of invalid field
            """
            try:
                packed = struct.pack(NTPMode6Packet._PACKET_FORMAT,
                    (self.leap << 6 | self.version << 3 | self.mode),
                    (self.response_bit << 7 | self.error_bit << 6 | self.more_bit << 5 | self.opcode),
                    self.sequence,
                    self.status,
                    self.assoc_id,
                    self.offset,
                    self.count)
            except struct.error as msg:
                raise NTPException("Invalid NTP control packet fields: %s" % msg)

            return packed

    def __init__(self, data):
        _NTPBasePacket.__init__(self)
        self.data = data

    def get_mode_name(self):
        return 'CONTROL'

    def _handle_response(self, req_packet):
        # simple error checking, just to make sure we don't respond to intentionally malformed packet
        if req_packet.offset != 0 or req_packet.response_bit == 1 or \
           req_packet.error_bit == 1 or req_packet.more_bit == 1:
            self.logger.error('Malformed NTP control packet received!')
            return []

        # check opcode - we only handle READVAR operation (opcode 2)
        if req_packet.opcode != 2:
            self.logger.warn(
                    'Received NTP control packet has opcode %d (NOT READVAR)! Ignoring...' % req_packet.opcode)
            return []

        # build and return response packet - NTP control response is different from the request!
        resp_packet = self._Response(
                resp=1,
                opcode=req_packet.opcode,
                sequence=req_packet.sequence,
                assoc_id=req_packet.assoc_id)

        # _handle_response must return a list in order to be compatible with other NTP modes that return > 1 response packet
        return [resp_packet.to_data()]


class NTPMode7Packet(_NTPBasePacket):
    """NTP mode 7 packet base class.
    This represents an implementation of NTP mode 7 base packet - common header for request and response.
    """
    mode = 7

    _PACKET_FORMAT = "!B B B B H H"

    class MonlistPeer(object):

        _MONLIST_PEER_FORMAT = "!7I H B B I I 2Q 2Q"

        def __init__(
                self, avg_int=0, last_int=0, restr=0,
                count=64, addr=0, daddr=0, flags=0,
                port=123, mode=4, version=4, v6_flag=0,
                addr6_high=0, addr6_low=0, daddr6_high=0, daddr6_low=0):
            self.avg_int = avg_int
            self.last_int = last_int
            self.restr = restr
            self.count = count
            self.addr = addr
            self.daddr = daddr
            self.flags = flags
            self.port = port
            self.mode = mode
            self.version = version
            self.v6_flag = v6_flag
            self.unused = 0
            self.addr6_high = addr6_high
            self.addr6_low = addr6_low
            self.daddr6_high = daddr6_high
            self.daddr6_low = daddr6_low

        def to_data(self):
            try:
                packed = struct.pack(self._MONLIST_PEER_FORMAT,
                    self.avg_int,
                    self.last_int,
                    self.restr,
                    self.count,
                    self.addr,
                    self.daddr,
                    self.flags,
                    self.port,
                    self.mode,
                    self.version,
                    self.v6_flag,
                    self.unused,
                    self.addr6_high,
                    self.addr6_low,
                    self.daddr6_high,
                    self.daddr6_low)
            except struct.error as msg:
                raise Exception("Invalid NTP monlist peer structure fields: %s" % msg)
            return packed

    class _Request(_NTPBasePacket._Request):
        def from_data(self, data):
            """Populate this instance from a raw NTP mode 7 packet payload received from
            the network.

            Raises:
            NTPException -- in case of invalid packet format
            """
            try:
                unpacked = struct.unpack(NTPMode7Packet._PACKET_FORMAT,
                        data[0:struct.calcsize(NTPMode7Packet._PACKET_FORMAT)])
            except struct.error:
                raise NTPException("Invalid NTP mode 7 packet.")

            self.response_bit = unpacked[0] >> 7 & 0x1
            self.more_bit = unpacked[0] >> 6 & 0x1
            self.version = unpacked[0] >> 3 & 0x7
            self.mode = unpacked[0] & 0x7
            self.auth = unpacked[1] >> 7 & 0x1
            self.sequence = unpacked[1] & 0x7f
            self.implementation = unpacked[2]
            self.req_code = unpacked[3]
            self.err = unpacked[4] >> 12 & 0xf
            self.nitems = unpacked[4] & 0xfff
            self.mbz = unpacked[5] >> 12 & 0xf
            self.sizeof_data_item = unpacked[5] & 0xfff

    class _Response(_NTPBasePacket._Response):
        def __init__(self, more=0, sequence=0, nitems=0, monitor_data=[]):
            self.more_bit = more
            self.sequence = sequence
            self.nitems = nitems
            self.monitor_data = monitor_data

        def to_data(self):
            """Convert instance to a buffer that can be sent over a socket.

            Returns:
            buffer representing this packet

            Raises:
            NTPException -- in case of invalid field
            """
            try:
                packed = struct.pack(NTPMode7Packet._PACKET_FORMAT,
                    (self.response_bit << 7 | self.more_bit << 6 | self.version << 3 | self.mode),
                    (self.auth << 7 | self.sequence),
                    self.implementation,
                    self.req_code,
                    (self.err << 12 | self.nitems),
                    (self.mbz << 12 | self.sizeof_data_item))

                # next, pack all monitor data structures and concatenate them with the header
                for monitor_elem in self.monitor_data:
                    elem_packed = monitor_elem.to_data()
                    packed += elem_packed
            except struct.error as msg:
                raise NTPException("Invalid NTP mode 7 packet fields: %s" % msg)

            return packed

    def __init__(self, data):
        _NTPBasePacket.__init__(self)
        self.data = data

    @staticmethod
    def set_response_defaults(
            resp=1, more=0, version=2, auth=0,
            sequence=0, implementation=3, req_code=42, err=0,
            nitems=0, mbz=0, sizeof_data_item=0x48, peer_lists=[]):
        """Set monitor data/monlist peer lists that will be returned in response to mode 7 request."""
        NTPMode7Packet._Response.response_bit = resp
        NTPMode7Packet._Response.more_bit = more
        NTPMode7Packet._Response.mode = NTPMode7Packet.mode
        NTPMode7Packet._Response.version = version
        NTPMode7Packet._Response.auth = auth
        NTPMode7Packet._Response.sequence = sequence
        NTPMode7Packet._Response.implementation = implementation
        NTPMode7Packet._Response.req_code = req_code
        NTPMode7Packet._Response.err = err
        NTPMode7Packet._Response.nitems = nitems
        NTPMode7Packet._Response.mbz = mbz
        NTPMode7Packet._Response.sizeof_data_item = sizeof_data_item

        # peer lists/monitor lists are static per NTP server and they're initialized at startup
        NTPMode7Packet.peer_lists = peer_lists

    def get_mode_name(self):
        return 'MONLIST'

    def _handle_response(self, req_packet):
        response = []

        # simple error checking, just to make sure we don't respond to intentionally malformed packet
        if req_packet.response_bit == 1 or req_packet.more_bit == 1 or \
           req_packet.err != 0 or req_packet.implementation not in (0, 2, 3):
            self.logger.error('Malformed NTP mode 7 packet received!')
            return response

        # check request code - we only handle MON_GETLIST or MON_GETLIST_1 operations (request codes 20 and 42)
        if req_packet.req_code != 20 and req_packet.req_code != 42:
            self.logger.warn(
                    'Received NTP mode 7 packet has request code %d (NOT MON_GETLIST)! Ignoring...' % (req_packet.req_code))
            return response

        # one mode 7 response can contain 6 peers
        # if there are more peers, multiple packets must be sent and all must have 'more' bit equal to 1, except the last one
        # additionally, sequence number must be set to appropriate packet index
        packet_index = 0
        for peers in self.peer_lists:
            more = 1
            if packet_index == len(self.peer_lists) - 1:
                more = 0

            # build mode 7 response packet - NTP mode 7 response is different from the request!
            resp_packet = self._Response(more=more, sequence=packet_index, nitems=len(peers), monitor_data=peers)
            response.append(resp_packet.to_data())
            packet_index += 1

        return response


class NTPServer(socketserver.BaseRequestHandler):
    # default logger
    logger = logging.getLogger(LOGGER_NAME)

    def log_packet(
            self, msg, addr, port,
            mode, mode_name, timestamp, incoming_pkt,
            req_size, outgoing_pkt, resp_size, last=False):
        data = {}
        data['time'] = str(timestamp)
        data['src_ip'] = addr
        data['src_port'] = port
        data['mode'] = mode_name
        data['req_size'] = req_size
        data['resp_size'] = resp_size
        if self.server.log_req_packets:
            data['req_pkt'] = incoming_pkt.decode('ascii')
        if self.server.log_resp_packets:
            data['resp_pkt'] = outgoing_pkt.decode('ascii')

        raw_json = json.dumps(data)

        self.logger.info('%s - %s' % (msg, raw_json))

        if not last:
            db_params = {
                        'ip': utils.addr_to_int(addr),
                        'port': port,
                        'time': timestamp,
                        'mode': mode,
                        'request_pkt': incoming_pkt,
                        'response_pkt': outgoing_pkt,
                        'input_size': req_size,
                        'output_size': resp_size,
                        }
            self.server.log_queue.put({'type': 'insert', 'db_params': db_params})

        # if last packet, send to hpfeeds and notifier/alerter
        if last:
            if self.server.hpfeeds_client:
                self.server.hpfeeds_client.publish('ntpot.events', raw_json)

            # send notification if alerter is enabled
            # THIS OPERATION CAN BE SLOW!
            if self.server.alerter:
                self.server.alerter.alert(addr, int(port))


    def _ntp_packet(self, data):
        """Factory that creates NTP request/response depending on the mode."""
        #mode = struct.unpack('B', data[0])[0] & 0x7
        mode = data[0] & 0x7
        if mode == 3:
            return NTPMode3Packet(data)
        elif mode == 6:
            return NTPMode6Packet(data)
        elif mode == 7:
            return NTPMode7Packet(data)
        else:
            raise NTPException(
                    'Unknown/unsupported NTP packet (mode %d) - %s' % (mode, base64.b64encode(data)))

    def handle(self):
        try:
            data = self.request[0]
            sock = self.request[1]
            addr = self.client_address[0]
            port = self.client_address[1]
            first = False
            last = False

            # ignore empty packets
            if not len(data):
                self.logger.error('%s:%d - %s' % (addr, port, 'Empty packet received'))
                return

            try:
                packet = self._ntp_packet(data)
            except NTPException as msg:
                self.logger.error('%s:%d - %s' % (addr, port, msg))
                return

            # IP addresses in transaction log and database will be stored as integers/long
            addr_int = utils.addr_to_int(addr)

            mode = packet.get_mode()
            now = datetime.datetime.now()
            log_msg = 'New NTP packet received'

            # check if this type of packet was already received - ENTERING CRITICAL SECTION HERE!
            with self.server.tx_log_lock:
                if addr_int in self.server.transaction_log:
                    addr_log = self.server.transaction_log[addr_int]
                    # take mode into account
                    if addr_log['mode'] == mode:
                        # check if this is an already existing attack or a new attack
                        # attack is classified as NEW if more than new_attack_duration_interval
                        # minutes have passed since the last seen packet
                        if addr_log['last_seen'] + self.server.new_attack_interval < now:
                            # consider this as a new attack, reset cache data
                            first = True
                            addr_log['count'] = 1
                            addr_log['last_seen'] = now
                            log_msg = 'New attack detected'
                        else:
                            # update transaction log and database last-seen time and packet count and do not respond to the packet
                            addr_log['last_seen'] = now
                            addr_log['count'] += 1

                            # add the address to ip set - this set will be frequently flushed to DB
                            self.server.ip_log.add(addr_int)

                            # if count >= threshold, ignore the packet, never respond
                            if addr_log['count'] > self.server.threshold:
                                return
                            # log reaching of threshold and mark packet as last that will be accepted
                            elif addr_log['count'] == self.server.threshold:
                                last = True
                                self.logger.info(
                                        'Threshold reached for host %s and mode %d - will not respond to this host/mode pair' % (addr, mode))
                                log_msg = 'Last packet - threshold reached'
                else:
                    # add host to transaction log
                    first = True
                    self.server.transaction_log[addr_int] = {}
                    self.server.transaction_log[addr_int]['mode'] = mode
                    self.server.transaction_log[addr_int]['last_seen'] = now
                    self.server.transaction_log[addr_int]['count'] = 1

            # handle the received packets (list of response packets) and send the appropriate NTP responses (or exit if no responses should be returned)
            try:
                responses = packet.handle()
            except Exception as msg:
                self.logger.error('Error while parsing NTP packet from %s:%d or unable to create proper response: %s' % (addr, port, msg))
                return

            if not len(responses):
                return

            b64_resp = b''
            output_size = 0
            for response in responses:
                sock.sendto(response, self.client_address)
                b64_resp += base64.b64encode(response)
                output_size += len(response)

            # log packet to file and database
            if first or last:
                b64_req = base64.b64encode(data)
                input_size = len(data)
                self.log_packet(
                        log_msg,
                        addr,
                        port,
                        mode,
                        packet.get_mode_name(),
                        now,
                        b64_req,
                        input_size,
                        b64_resp,
                        output_size,
                        last)
        except Exception:
            t = traceback.format_exc()
            self.logger.error('Unknown error during communication with %s:%d - %s' % (addr, port, base64.b64encode(data)))
            self.logger.error('Stacktrace: %s' % t)


class ThreadedNTPServer(genpot.ThreadedUDPServer):
    def _flush_ip_info(self, ip):
        addr_log = self.transaction_log[ip]
        db_params = {
                    'ip': ip,
                    'mode': addr_log['mode'],
                    'last_seen': addr_log['last_seen'],
                    'count': addr_log['count']
                    }
        self.log_queue.put({'type': 'update', 'db_params': db_params})


def _get_monlist_peer_lists(conf):
    logger = logging.getLogger(LOGGER_NAME)
    try:
        generate_random = conf.getboolean('monlist', 'generate_random')
        num_peers = conf.getint('monlist', 'peers_num')
        if num_peers < 0:
            logger.error('Invalid peers_num value, must be greater than zero!')
            return

        peers = []

        # get 'daddr' (i.e. local_address) from the config file
        # this value is the same for all the peers
        daddr = utils.addr_to_int(conf.get('monlist', 'local_address'))

        for i in range(1, num_peers + 1):
            peer = None
            if generate_random:
                # while generating data, make it look "realistic"
                # avg_int and count should not differ much between peers!
                # use values generated for the first peer as a baseline
                first_avg_int = 10
                first_count = 50
                if i > 1:
                    first_avg_int = peers[0].avg_int
                    first_count = peers[0].count
                avg_int = random.randint(first_avg_int - 5, first_avg_int + 5)
                last_int = random.randint(0, 100)
                restr = 0
                count = random.randint(first_count - 10, first_count + 10)
                addr = (random.randint(0, 255) << 24) | (random.randint(0, 255) << 16) | \
                        (random.randint(0, 255) << 8) | random.randint(0, 255)

                peer = NTPMode7Packet.MonlistPeer(avg_int, last_int, restr, count, addr, daddr)
                peers.append(peer)
            else:
                try:
                    section = 'peer-' + str(i)
                    avg_int = conf.getint(section, 'avg_int')
                    last_int = conf.getint(section, 'last_int')
                    restr = conf.getint(section, 'restr')
                    count = conf.getint(section, 'count')
                    addr = utils.addr_to_int(conf.get(section, 'addr'))
                    flags = conf.getint(section, 'flags')
                    port = conf.getint(section, 'port')
                    mode = conf.getint(section, 'mode')
                    version = conf.getint(section, 'version')
                    v6_flag = conf.getint(section, 'v6_flag')

                    peer = NTPMode7Packet.MonlistPeer(
                            avg_int,
                            last_int,
                            restr,
                            count,
                            addr,
                            daddr,
                            flags,
                            port,
                            mode,
                            version,
                            v6_flag)
                    peers.append(peer)
                except configparser.NoSectionError:
                    logger.warn('No section %s, ignoring peer...' % section)
                    continue
                except configparser.NoOptionError as msg:
                    logger.warn('Option error: %s. Ignoring peer...' % msg)
                    continue

        peer_lists = [peers[i:i + 6] for i in range(0, len(peers), 6)]
        return peer_lists
    except configparser.Error as msg:
        logger.error('Error occurred while parsing monlist section in configuration file: %s' % msg)


def create_server(conf, logger_name, log_queue, output_queue, hpf_client=None, alerter=None):
    global LOGGER_NAME
    LOGGER_NAME = logger_name

    server, ip, port = genpot.create_base_server(
                                                ThreadedNTPServer,
                                                NTPServer,
                                                conf,
                                                logger_name,
                                                log_queue,
                                                output_queue,
                                                hpf_client,
                                                alerter
                                                )

    # parse NTP configuration and apply default settings for mode 3 and mode 7 responses
    # this is done during start-up because these settings are static during server lifetime
    leap = conf.getint('NTP', 'leap')
    precision = conf.getint('NTP', 'precision')
    root_delay = int(conf.get('NTP', 'root_delay'), 16)
    dispersion = int(conf.get('NTP', 'dispersion'), 16)
    ref_id = utils.addr_to_int(conf.get('NTP', 'reference_id'))
    offset = conf.getfloat('NTP', 'timestamp_offset')

    NTPMode3Packet.set_response_defaults(
            leap=leap,
            precision=precision,
            root_delay=root_delay,
            dispersion=dispersion,
            ref_id=ref_id,
            ref_timestamp_offset=offset)

    peer_lists = _get_monlist_peer_lists(conf)
    NTPMode7Packet.set_response_defaults(peer_lists=peer_lists)

    msg = "NTPot started at %s:%d" % (ip, port)
    logging.getLogger(LOGGER_NAME).info(msg)
    print(msg)

    return server
