import pytest

import intake_netflow.v9 as nf


@pytest.fixture
def ipv4_template():
    fields = [
        nf.TemplateField(nf.Field.PROTOCOL, 1),
        nf.TemplateField(nf.Field.IPV4_SRC_ADDR, 4),
        nf.TemplateField(nf.Field.L4_SRC_PORT, 2),
        nf.TemplateField(nf.Field.IPV4_DST_ADDR, 4),
        nf.TemplateField(nf.Field.L4_DST_PORT, 2),
        nf.TemplateField(nf.Field.IN_BYTES, 4),
        nf.TemplateField(nf.Field.IN_PKTS, 4),
        nf.TemplateField(nf.Field.OUT_BYTES, 4),
        nf.TemplateField(nf.Field.OUT_PKTS, 4)]
    return nf.TemplateRecord(1024, fields)
