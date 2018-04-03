"""Implementation for Cisco's NetFlow Version 9 flow-record format.

NetFlow is an exchange protocol between a server (Exporter in Cisco parlance)
and a client (Collector in Cisco parlance). A stream of packets is sent from
the Exporter to the Collector. Each packet can represent several IP flows. A
diagram of a single packet is shown below::

    +--------+------------------+--------------+--------------+-----+------------------+--------------+
    | Header | Template FlowSet | Data FlowSet | Data FlowSet | ... | Template FlowSet | Data FlowSet |
    +--------+------------------+--------------+--------------+-----+------------------+--------------+

This implementation can serialize and deserialize a packet, but the stream is a
read-only representation of serialized packets.

The full documentation of this protocol is `NetflowV9`_.

.. _NetflowV9:
   https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.pdf
"""

import functools
import struct
import time

import attr
import enum

from .utils import byte_stream, read_and_unpack


s_header = struct.Struct("!HHIIII")
s_flowset = struct.Struct("!H")
s_type_length = struct.Struct("!HH")


class Field(enum.Enum):
    IN_BYTES = 1
    IN_PKTS = 2
    FLOWS = 3
    PROTOCOL = 4
    SRC_TOS = 5
    TCP_FLAGS = 6
    L4_SRC_PORT = 7
    IPV4_SRC_ADDR = 8
    SRC_MASK = 9
    INPUT_SNMP = 10
    L4_DST_PORT = 11
    IPV4_DST_ADDR = 12
    DST_MASK = 13
    OUTPUT_SNMP = 14
    IPV4_NEXT_HOP = 15
    SRC_AS = 16
    DST_AS = 17
    BGP_IPV4_NEXT_HOP = 18
    MUL_DST_PKTS = 19
    MUL_DST_BYTES = 20
    LAST_SWITCHED = 21
    FIRST_SWITCHED = 22
    OUT_BYTES = 23
    OUT_PKTS = 24
    MIN_PKT_LNGTH = 25
    MAX_PKT_LNGTH = 26
    IPV6_SRC_ADDR = 27
    IPV6_DST_ADDR = 28
    IPV6_SRC_MASK = 29
    IPV6_DST_MASK = 30
    IPV6_FLOW_LABEL = 31
    ICMP_TYPE = 32
    MUL_IGMP_TYPE = 33
    SAMPLING_INTERVAL = 34
    SAMPLING_ALGORITHM = 35
    FLOW_ACTIVE_TIMEOUT = 36
    FLOW_INACTIVE_TIMEOUT = 37
    ENGINE_TYPE = 38
    ENGINE_ID = 39
    TOTAL_BYTES_EXP = 40
    TOTAL_PKTS_EXP = 41
    TOTAL_FLOWS_EXP = 42
    IPV4_SRC_PREFIX = 44
    IPV4_DST_PREFIX = 45
    MPLS_TOP_LABEL_TYPE = 46
    MPLS_TOP_LABEL_IP_ADDR = 47
    FLOW_SAMPLER_ID = 48
    FLOW_SAMPLER_MODE = 49
    FLOW_SAMPLER_RANDOM_INTERVAL = 50
    MIN_TTL = 52
    MAX_TTL = 53
    IPV4_IDENT = 54
    DST_TOS = 55
    IN_SRC_MAC = 56
    OUT_DST_MAC = 57
    SRC_VLAN = 58
    DST_VLAN = 59
    IP_PROTOCOL_VERSION = 60
    DIRECTION = 61
    IPV6_NEXT_HOP = 62
    BPG_IPV6_NEXT_HOP = 63
    IPV6_OPTION_HEADERS = 64
    MPLS_LABEL_1 = 70
    MPLS_LABEL_2 = 71
    MPLS_LABEL_3 = 72
    MPLS_LABEL_4 = 73
    MPLS_LABEL_5 = 74
    MPLS_LABEL_6 = 75
    MPLS_LABEL_7 = 76
    MPLS_LABEL_8 = 77
    MPLS_LABEL_9 = 78
    MPLS_LABEL_10 = 79
    IN_DST_MAC = 80
    OUT_SRC_MAC = 81
    IF_NAME = 82
    IF_DESC = 83
    SAMPLER_NAME = 84
    IN_PERMANENT_BYTES = 85
    IN_PERMANENT_PKTS = 86
    FRAGMENT_OFFSET = 88
    FORWARDING_STATUS = 89
    MPLS_PAL_RD = 90
    MPLS_PREFIX_LEN = 91
    SRC_TRAFFIC_INDEX = 92
    DST_TRAFFIC_INDEX = 93
    APPLICATION_DESCRIPTION = 94
    APPLICATION_TAG = 95
    APPLICATION_NAME = 96
    POST_IP_DIFF_SERV_CODE_POINT = 98
    REPLICATION_FACTOR = 99
    LAYER2_PACKET_SECTION_OFFSET = 102
    LAYER2_PACKET_SECTION_SIZE = 103
    LAYER2_PACKET_SECTION_DATA = 104


class FieldDataType(enum.Enum):
    IN_BYTES = int
    IN_PKTS = int
    FLOWS = int
    PROTOCOL = int
    SRC_TOS = int
    TCP_FLAGS = int
    L4_SRC_PORT = int
    IPV4_SRC_ADDR = int
    SRC_MASK = int
    INPUT_SNMP = int
    L4_DST_PORT = int
    IPV4_DST_ADDR = int
    DST_MASK = int
    OUTPUT_SNMP = int
    IPV4_NEXT_HOP = int
    SRC_AS = int
    DST_AS = int
    BGP_IPV4_NEXT_HOP = int
    MUL_DST_PKTS = int
    MUL_DST_BYTES = int
    LAST_SWITCHED = int
    FIRST_SWITCHED = int
    OUT_BYTES = int
    OUT_PKTS = int
    MIN_PKT_LNGTH = int
    MAX_PKT_LNGTH = int
    IPV6_SRC_ADDR = bytes
    IPV6_DST_ADDR = bytes
    IPV6_SRC_MASK = int
    IPV6_DST_MASK = int
    IPV6_FLOW_LABEL = bytes
    ICMP_TYPE = int
    MUL_IGMP_TYPE = int
    SAMPLING_INTERVAL = int
    SAMPLING_ALGORITHM = int
    FLOW_ACTIVE_TIMEOUT = int
    FLOW_INACTIVE_TIMEOUT = int
    ENGINE_TYPE = int
    ENGINE_ID = int
    TOTAL_BYTES_EXP = int
    TOTAL_PKTS_EXP = int
    TOTAL_FLOWS_EXP = int
    IPV4_SRC_PREFIX = int
    IPV4_DST_PREFIX = int
    MPLS_TOP_LABEL_TYPE = int
    MPLS_TOP_LABEL_IP_ADDR = int
    FLOW_SAMPLER_ID = int
    FLOW_SAMPLER_MODE = int
    FLOW_SAMPLER_RANDOM_INTERVAL = int
    MIN_TTL = int
    MAX_TTL = int
    IPV4_IDENT = int
    DST_TOS = int
    IN_SRC_MAC = bytes
    OUT_DST_MAC = bytes
    SRC_VLAN = int
    DST_VLAN = int
    IP_PROTOCOL_VERSION = int
    DIRECTION = int
    IPV6_NEXT_HOP = bytes
    BPG_IPV6_NEXT_HOP = bytes
    IPV6_OPTION_HEADERS = int
    MPLS_LABEL_1 = bytes
    MPLS_LABEL_2 = bytes
    MPLS_LABEL_3 = bytes
    MPLS_LABEL_4 = bytes
    MPLS_LABEL_5 = bytes
    MPLS_LABEL_6 = bytes
    MPLS_LABEL_7 = bytes
    MPLS_LABEL_8 = bytes
    MPLS_LABEL_9 = bytes
    MPLS_LABEL_10 = bytes
    IN_DST_MAC = bytes
    OUT_SRC_MAC = bytes
    IF_NAME = str
    IF_DESC = str
    SAMPLER_NAME = str
    IN_PERMANENT_BYTES = int
    IN_PERMANENT_PKTS = int
    FRAGMENT_OFFSET = int
    FORWARDING_STATUS = int
    MPLS_PAL_RD = bytes
    MPLS_PREFIX_LEN = int
    SRC_TRAFFIC_INDEX = int
    DST_TRAFFIC_INDEX = int
    APPLICATION_DESCRIPTION = str
    APPLICATION_TAG = bytes
    APPLICATION_NAME = str
    POST_IP_DIFF_SERV_CODE_POINT = int
    REPLICATION_FACTOR = int
    LAYER2_PACKET_SECTION_OFFSET = int
    LAYER2_PACKET_SECTION_SIZE = int
    LAYER2_PACKET_SECTION_DATA = bytes


@attr.s
class Header(object):
    version = attr.ib(type=int, default=9)
    count = attr.ib(type=int, default=0)
    uptime = attr.ib(type=int, default=0)
    datetime = attr.ib(type=int)
    sequence = attr.ib(type=int, default=0)
    source_id = attr.ib(type=int, default=0)

    @datetime.default
    def current_unix_seconds(self):
        return int(time.time())

    @staticmethod
    def decode(source):
        return Header(*read_and_unpack(source, s_header))

    def encode(self):
        return s_header.pack(self.version,
                             self.count,
                             self.uptime,
                             self.datetime,
                             self.sequence,
                             self.source_id)


def create_struct(dtype, length):
    if dtype is int:
        if length == 1:
            code = 'B'
        elif length == 2:
            code = 'H'
        elif length == 4:
            code = 'I'
        elif length == 8:
            code = 'Q'
        else:
            raise ValueError("invalid integer length: {}".format(length))
    elif dtype is bytes:
        code = "{}B".format(length)
    elif dtype is str:
        code = "{}s".format(length)
    else:
        raise ValueError("invalid datatype: {}".format(dtype))
    return struct.Struct('!' + code)


@attr.s
class TemplateField(object):
    type = attr.ib(type=Field)
    length = attr.ib(type=int)

    @property
    def struct(self):
        if not hasattr(self, '_struct'):
            dtype = FieldDataType[Field(self.type.value).name].value
            self._struct = create_struct(dtype, self.length)
        return self._struct

    @staticmethod
    def decode(source):
        type, length = read_and_unpack(source, s_type_length)
        return TemplateField(Field(type), length)

    def encode(self):
        return s_type_length.pack(self.type.value, self.length)


class TemplateRecord(object):
    def __init__(self, id, fields=None):
        self.id = id
        self.fields = fields if fields else []

    def __eq__(self, other):
        return self.id == other.id and sorted(self.fields) == sorted(other.fields)

    def __len__(self):
        return s_type_length.size + sum(field.length for field in self.fields)

    def __iter__(self):
        return iter(self.fields)

    @staticmethod
    def decode(source):
        template_id, nfields = read_and_unpack(source, s_type_length)

        template = TemplateRecord(template_id)
        for _ in range(nfields):
            template.fields.append(TemplateField.decode(source))

        return template

    def encode(self):
        raw = s_type_length.pack(self.id, len(self.fields))
        for field in self.fields:
            raw += field.encode()
        return raw


class TemplateFlowSet(object):
    def __init__(self, templates=None):
        self.id = 0
        self.templates = {template.id: template for template in templates} if templates else {}

    def __eq__(self, other):
        return self.id == other.id and self.templates == other.templates

    def __len__(self):
        nbytes = s_type_length.size
        for template in self.templates.values():
            nbytes += len(template)
        return nbytes

    def __getitem__(self, key):
        return self.templates[key]

    def __iter__(self):
        return iter(self.templates)

    @staticmethod
    def decode(source):
        fs = TemplateFlowSet()
        _, length = read_and_unpack(source, s_type_length)
        offset = s_type_length.size

        while offset < length:
            template = TemplateRecord.decode(source)
            fs.templates[template.id] = template
            offset += len(template)

        return fs

    def encode(self):
        raw = s_type_length.pack(self.id, len(self))
        for template in self.templates.values():
            raw += template.encode()
        return raw


class DataFlowSet(object):
    def __init__(self, id, payload, templates):
        self.template = templates[id]
        self.records = []
        self.record_length = len(self.template) - s_type_length.size

        if isinstance(payload, bytes):
            source = byte_stream(payload)
            remaining = len(payload)
            while remaining >= self.record_length:
                self.records.append([read_and_unpack(source, field.struct)[0] for field in self.template])
                remaining -= self.record_length
        elif isinstance(payload, list):
            self.records = payload

    def __len__(self):
        return s_type_length.size + len(self.records) * self.record_length

    def __iter__(self):
        return iter(self.records)

    @staticmethod
    def decode(source):
        id, length = read_and_unpack(source, s_type_length)
        payload = source.read(length - s_type_length.size)
        return functools.partial(DataFlowSet, id, payload)

    def encode(self):
        raw = s_type_length.pack(self.template.id, len(self))
        for record in self.records:
            for field, value in zip(self.template.fields, record):
                raw += field.struct.pack(value)
        return raw


def decode_flowset(source):
    raw = source.peek(s_flowset.size)[:s_flowset.size]
    flowset_id = s_flowset.unpack(raw)[0]
    if flowset_id == 0:
        return TemplateFlowSet.decode(source)
    if flowset_id > 255:
        return DataFlowSet.decode(source)
    raise Exception("unknown flowset id '{}'".format(flowset_id))


class ExportPacket(object):
    def __init__(self, flowsets, header=None):
        self.header = header if header else Header(count=len(flowsets))
        self.flowsets = flowsets

    def update_cache(self, cache):
        """Update cache of template records."""
        for flowset in self.flowsets:
            if not isinstance(flowset, TemplateFlowSet):
                continue
            for id, record in flowset.templates.items():
                cache[id] = record

    def apply(self, templates):
        """Deserialize partially-decoded data flowsets.

        Deserialization of a data flowset is a two-step process because we
        cannot assume the needed template is available when we encounter the
        data flowset. Thus, we place the deserialization process on hold into
        a packet is fully read. Then we re-scan the partially-decoded data
        flowsets and finish deserialization.
        """
        for i, flowset in enumerate(self.flowsets):
            if isinstance(flowset, functools.partial):
                self.flowsets[i] = flowset(templates)

    @staticmethod
    def decode(source):
        header = Header.decode(source)
        flowsets = [decode_flowset(source) for _ in range(header.count)]
        return ExportPacket(flowsets, header=header)

    def encode(self):
        raw = self.header.encode()
        for flowset in self.flowsets:
            if isinstance(flowset, functools.partial):
                continue
            raw += flowset.encode()
        return raw


class PacketStream(object):
    def __init__(self, source):
        """A read-only representation of serialized packets.

        Parameters:
            source : io.BufferedReader
                Read-only input for packets.
        """
        self._source = source
        self._cache = {}

    def next(self):
        if self._source.peek() == b'':
            raise StopIteration

        # Packet deserialization is a two-step process.
        #
        # A data flowset requires a defined template to complete the
        # deserialization process, Since template and data flowsets can be
        # out-of-order within a packet, then we must temporarily wait to
        # finish deserializing a data flowset and the respective records.

        packet = ExportPacket.decode(self._source)

        # Add templates to cache
        packet.update_cache(self._cache)

        # Finish deserialization
        packet.apply(self._cache)

        return packet

    def __next__(self):
        return self.next()

    def __iter__(self):
        return self

    def close(self):
        return self._source.close()


class RecordStream(PacketStream):
    def __init__(self, source):
        """A read-only representation of serialized data records.

        Parameters:
            source : io.BufferedReader
                Read-only input for data records.
        """
        super(RecordStream, self).__init__(source)
        self._queue = []

    def next(self):
        while len(self._queue) == 0:
            packet = super(RecordStream, self).next()
            for flowset in packet.flowsets:
                if not isinstance(flowset, DataFlowSet):
                    continue
                keys = [field.type.name.lower() for field in flowset.template.fields]
                for record in flowset.records:
                    self._queue.append(dict(zip(keys, record)))

        record, self._queue = self._queue[0], self._queue[1:]
        return record

    def close(self):
        self._queue = []
        return super(RecordStream, self).close()
