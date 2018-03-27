import pytest

from intake_netflow.utils import byte_stream
import intake_netflow.v9 as nf


@pytest.fixture
def stream1(ipv4_template):
    tfs = nf.TemplateFlowSet([ipv4_template])
    packet = nf.ExportPacket([tfs])
    return byte_stream(packet.encode())


@pytest.fixture
def stream2(ipv4_template):
    tfs = nf.TemplateFlowSet([ipv4_template])
    data = [nf.DataFlowSet(ipv4_template.id, [], tfs.templates) for i in range(32)]
    packet = nf.ExportPacket([tfs] + data)
    return byte_stream(packet.encode())


@pytest.fixture
def stream3(ipv4_template):
    tfs = nf.TemplateFlowSet([ipv4_template])

    # template
    raw = nf.ExportPacket([tfs]).encode()

    # data
    for i in range(32):
        data = [nf.DataFlowSet(ipv4_template.id, [], tfs.templates)]
        packet = nf.ExportPacket(data)
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
