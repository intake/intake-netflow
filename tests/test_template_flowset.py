from intake_netflow.utils import byte_stream
from intake_netflow.v9 import Field, TemplateField, TemplateFlowSet, TemplateRecord


def test_field_roundtrip():
    expected = TemplateField(Field.PROTOCOL, 4)

    given = TemplateField.decode(byte_stream(expected.encode()))

    assert expected == given


def test_record_empty_roundtrip():
    expected = TemplateRecord(id=256)

    given = TemplateRecord.decode(byte_stream(expected.encode()))

    assert expected == given


def test_record_nonempty_roundtrip():
    tf = TemplateField(Field.PROTOCOL, 4)

    expected = TemplateRecord(id=256, fields=[tf])

    given = TemplateRecord.decode(byte_stream(expected.encode()))

    assert expected == given


def test_flowset_empty_roundtrip():
    expected = TemplateFlowSet()

    given = TemplateFlowSet.decode(byte_stream(expected.encode()))

    assert expected == given


def test_flowset_nonempty_roundtrip():
    tf = TemplateField(Field.PROTOCOL, 4)
    templates = [TemplateRecord(id=256, fields=[tf])]
    expected = TemplateFlowSet(templates)

    given = TemplateFlowSet.decode(byte_stream(expected.encode()))

    assert expected == given
