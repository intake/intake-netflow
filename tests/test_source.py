import os

from intake_netflow.source import NetflowSource


basedir = os.path.dirname(__file__)
single = os.path.join(basedir, '2.netflow')
multiple = os.path.join(basedir, '*.netflow')


def test_single():
    src = NetflowSource(urlpath=single)

    metadata = src.discover()
    assert metadata['npartitions'] == 1

    data = src.read()
    assert len(data) == 2

    src.close()


def test_multiple():
    src = NetflowSource(urlpath=multiple)

    metadata = src.discover()
    assert metadata['npartitions'] == 2

    data = src.read()
    assert len(data) == 102

    src.close()
