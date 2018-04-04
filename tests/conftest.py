import pytest

import intake_netflow.v9 as nf


@pytest.fixture
def ipv4_template():
    fields = [
        nf.TemplateField(nf.FieldType.PROTOCOL, 1),
        nf.TemplateField(nf.FieldType.IPV4_SRC_ADDR, 4),
        nf.TemplateField(nf.FieldType.L4_SRC_PORT, 2),
        nf.TemplateField(nf.FieldType.IPV4_DST_ADDR, 4),
        nf.TemplateField(nf.FieldType.L4_DST_PORT, 2),
        nf.TemplateField(nf.FieldType.IN_BYTES, 4),
        nf.TemplateField(nf.FieldType.IN_PKTS, 4),
        nf.TemplateField(nf.FieldType.OUT_BYTES, 4),
        nf.TemplateField(nf.FieldType.OUT_PKTS, 4)]
    return nf.TemplateRecord(1024, fields)
