from dask.bytes import open_files

from intake.source import base
from . import __version__


class NetflowSource(base.DataSource):
    name = 'netflow'
    version = __version__
    container = 'python'
    partition_access = True

    def __init__(self, urlpath, metadata=None):
        """Source to load Cisco Netflow packets as sequence of Python dicts.

        Parameters:
            urlpath : str
                Location of the data files; can include protocol and glob 
                characters.
        """
        self._urlpath = urlpath
        super(NetflowSource, self).__init__(metadata=metadata)

    def _get_schema(self):
        self._streams = open_files(self._urlpath, mode='rb')
        self.npartitions = len(self._streams)
        return base.Schema(datashape=None,
                           dtype=None,
                           shape=None,
                           npartitions=len(self._streams),
                           extra_metadata={})

    def _get_partition(self, i):
        return read_stream(self._streams[i])

    def read(self):
        return self.to_dask().compute()

    def to_dask(self):
        import dask.delayed
        import dask.bag as db
        dpart = dask.delayed(read_stream)
        parts = [dpart(stream) for stream in self._streams]
        return db.from_delayed(parts)

    def _close(self):
        self._streams = None


def read_stream(stream):
    from .v9 import RecordStream
    with stream as f:
        return list(RecordStream(f))
