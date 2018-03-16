import pytest

import intake_netflow.v9 as nf

from .utils import byte_stream


@pytest.fixture
def stream1():
    flowsets = [nf.TemplateFlowSet()]
    packet = nf.ExportPacket(flowsets)
    return byte_stream(packet.encode())


@pytest.fixture
def stream2():
    template = [nf.TemplateFlowSet()]
    data = [nf.DataFlowSet(256 + i) for i in range(32)]
    packet = nf.ExportPacket(template + data)
    return byte_stream(packet.encode())


@pytest.fixture
def stream3():
    # template
    raw = nf.ExportPacket([nf.TemplateFlowSet()]).encode()

    # data
    for i in range(32):
        packet = nf.ExportPacket([nf.DataFlowSet(256 + i)])
        raw += packet.encode()

    return byte_stream(raw)


def test_stream_with_only_template(stream1):
    s = nf.Stream(stream1)
    packet = s.next()

    assert packet.header.version == 9
    assert packet.header.count == 1
    assert len(packet.flowsets) == 1


def test_stream_with_template_and_data(stream2):
    s = nf.Stream(stream2)
    packet = s.next()

    assert packet.header.version == 9
    assert packet.header.count == 33
    assert len(packet.flowsets) == 33


def test_stream_multiple_packets(stream3):
    s = nf.Stream(stream3)
    packets = list(s)

    assert len(packets) == 33

    assert packets[0].header.version == 9
    assert len(packets[0].flowsets) == 1
