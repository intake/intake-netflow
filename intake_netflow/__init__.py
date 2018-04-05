from dask.bytes import open_files

from intake.source import base

from .v9 import RecordStream


class Plugin(base.Plugin):
    def __init__(self):
        super(Plugin, self).__init__(name='netflow', version='0.1', container='python', partition_access=False)

    def open(self, urlpath, **kwargs):
        """
        Parameters:
            urlpath : str
                Location of the data files; can include protocol and glob characters.
            kwargs : dict
                Additional parameters to pass to ``intake_netflow.v9.RecordStream``.
        """
        base_kwargs, source_kwargs = self.separate_base_kwargs(kwargs)
        return NetflowSource(urlpath=urlpath, netflow_kwargs=source_kwargs, metadata=base_kwargs['metadata'])


class NetflowSource(base.DataSource):
    def __init__(self, urlpath, netflow_kwargs, metadata):
        self._init_args = dict(netflow_kwargs=netflow_kwargs, metadata=metadata)

        self._urlpath = urlpath
        self._netflow_kwargs = netflow_kwargs
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
