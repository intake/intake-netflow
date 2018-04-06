import io

import pytest

import intake_netflow.v9 as nf


@pytest.fixture
def ipv4_flows():
    return [
        [17, 3232235781, 21, 3232235782, 5000, 1024, 16, 512, 8],
        [17, 3232235781, 5000, 3232235782, 21, 512, 8, 1024, 16]]


def test_flowset_nonempty_roundtrip(ipv4_template, ipv4_flows):
    tfs = nf.TemplateFlowSet([ipv4_template])
    expected = nf.DataFlowSet(ipv4_template.id, ipv4_flows, tfs.templates)

    templates = {ipv4_template.id: ipv4_template}
    given = nf.DataFlowSet.decode(io.BytesIO(expected.encode()))
    given = given(templates)

    assert expected.records == given.records
