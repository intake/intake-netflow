from intake_netflow.v9 import TemplateField, TemplateFlowSet, TemplateRecord

from .utils import byte_stream


def test_field_roundtrip():
    expected = TemplateField(type=1, length=4)

    given = TemplateField.decode(byte_stream(expected.encode()))

    assert expected == given


def test_record_empty_roundtrip():
    expected = TemplateRecord(id=256)

    given = TemplateRecord.decode(byte_stream(expected.encode()))

    assert expected == given


def test_record_nonempty_roundtrip():
    expected = TemplateRecord(id=256, fields=[TemplateField(type=1, length=4)])

    given = TemplateRecord.decode(byte_stream(expected.encode()))

    assert expected == given


def test_flowset_empty_roundtrip():
    expected = TemplateFlowSet()

    given = TemplateFlowSet.decode(byte_stream(expected.encode()))

    assert expected == given


def test_flowset_nonempty_roundtrip():
    templates = [TemplateRecord(id=256, fields=[TemplateField(type=1, length=4)])]
    expected = TemplateFlowSet(templates)

    given = TemplateFlowSet.decode(byte_stream(expected.encode()))

    assert expected == given
