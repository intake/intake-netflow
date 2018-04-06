import io

from intake_netflow.v9 import FieldType, TemplateField, TemplateFlowSet, TemplateRecord


def test_field_roundtrip():
    expected = TemplateField(FieldType.PROTOCOL, 4)

    given = TemplateField.decode(io.BytesIO(expected.encode()))

    assert expected == given


def test_record_empty_roundtrip():
    expected = TemplateRecord(id=256)

    given = TemplateRecord.decode(io.BytesIO(expected.encode()))

    assert expected == given


def test_record_nonempty_roundtrip():
    tf = TemplateField(FieldType.PROTOCOL, 4)

    expected = TemplateRecord(id=256, fields=[tf])

    given = TemplateRecord.decode(io.BytesIO(expected.encode()))

    assert expected == given


def test_flowset_empty_roundtrip():
    expected = TemplateFlowSet()

    given = TemplateFlowSet.decode(io.BytesIO(expected.encode()))

    assert expected == given


def test_flowset_nonempty_roundtrip():
    tf = TemplateField(FieldType.PROTOCOL, 4)
    templates = [TemplateRecord(id=256, fields=[tf])]
    expected = TemplateFlowSet(templates)

    given = TemplateFlowSet.decode(io.BytesIO(expected.encode()))

    assert expected == given
