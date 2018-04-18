from dask.bytes import open_files

from intake.source import base

from .v9 import RecordStream


class NetflowSource(base.DataSource):
    def __init__(self, urlpath, metadata=None):
        """Source to load Cisco Netflow packets as sequence of Python dicts.

        Parameters:
            urlpath : str
                Location of the data files; can include protocol and glob characters.
        """
        self._urlpath = urlpath
        self._streams = open_files(urlpath, mode='rb')

        super(NetflowSource, self).__init__(container='python', metadata=metadata)

    def _get_schema(self):
        return base.Schema(datashape=None,
                           dtype=None,
                           shape=None,
                           npartitions=len(self._streams),
                           extra_metadata={})

    def _get_partition(self, i):
        with self._streams[i] as f:
            return list(RecordStream(f))

    def _close(self):
        for stream in self._streams:
            stream.close()

        self._streams = None
