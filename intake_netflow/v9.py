from datetime import datetime
import struct

import attr
import enum

from .utils import read_and_unpack


s_header = struct.Struct("!HHIIII")
s_flowset = struct.Struct("!H")
s_type_length = struct.Struct("!HH")


class FieldType(enum.Enum):
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
        return int(datetime.utcnow().strftime("%s"))

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


class FlowSet(object):
    @staticmethod
    def decode(source):
        raw = source.peek(s_flowset.size)[:s_flowset.size]
        flowset_id = s_flowset.unpack(raw)[0]
        if flowset_id == 0:
            return TemplateFlowSet.decode(source)
        if flowset_id > 255:
            return DataFlowSet.decode(source)
        raise Exception("unknown flowset id '{}'".format(flowset_id))


@attr.s
class TemplateField(object):
    type = attr.ib(type=FieldType)
    length = attr.ib(type=int)

    @staticmethod
    def decode(source):
        return TemplateField(*read_and_unpack(source, s_type_length))

    def encode(self):
        return s_type_length.pack(self.type, self.length)


class TemplateRecord(object):
    def __init__(self, id, fields=None):
        self.id = id
        self.fields = []

    def __eq__(self, other):
        return self.id == other.id and sorted(self.fields) == sorted(other.fields)

    @property
    def length(self):
        return s_type_length.size + len(self.fields) * s_type_length.size

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

    @property
    def length(self):
        nbytes = s_type_length.size
        for template in self.templates.values():
            nbytes += template.length
        return nbytes

    @staticmethod
    def decode(source):
        fs = TemplateFlowSet()
        _, length = read_and_unpack(source, s_type_length)
        offset = s_type_length.size

        while offset < length:
            template = TemplateRecord.decode(source)
            fs.templates[template.id] = template
            offset += template.length

        return fs

    def encode(self):
        raw = s_type_length.pack(self.id, self.length)
        for template in self.templates.values():
            raw += template.encode()
        return raw


class DataFlowSet(object):
    def __init__(self, id, length=s_type_length.size):
        self.id = id
        self.length = length

    @staticmethod
    def decode(source):
        fs = DataFlowSet(*read_and_unpack(source, s_type_length))
        source.seek(fs.length - s_type_length.size, 1)
        return fs

    def encode(self):
        return s_type_length.pack(self.id, self.length)


class ExportPacket(object):
    def __init__(self, flowsets, header=None):
        self.header = header if header else Header(count=len(flowsets))
        self.flowsets = flowsets

    @staticmethod
    def decode(source):
        header = Header.decode(source)
        flowsets = [FlowSet.decode(source) for _ in range(header.count)]
        return ExportPacket(flowsets, header=header)

    def encode(self):
        raw = self.header.encode()
        for flowset in self.flowsets:
            raw += flowset.encode()
        return raw


class Stream(object):
    def __init__(self, source):
        self._source = source

    def next(self):
        if self._source.peek() == b'':
            raise StopIteration
        return ExportPacket.decode(self._source)

    def __next__(self):
        return self.next()

    def __iter__(self):
        return self

    def close(self):
        return self._source.close()
