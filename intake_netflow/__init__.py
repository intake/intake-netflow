from glob import glob

from intake.source import base

from .v9 import Stream


class Plugin(base.Plugin):
    def __init__(self):
        super(Plugin, self).__init__(name='netflow', version='0.1', container='python', partition_access=False)

    def open(self, urlpath, **kwargs):
        """
        Parameters:
            urlpath : str
                Absolute or relative path to source files that can contain shell-style wildcards.
            kwargs : dict
                Additional parameters to pass to ``intake_netflow.v9.Stream``.
        """
        base_kwargs, source_kwargs = self.separate_base_kwargs(kwargs)
        return NetflowSource(urlpath=urlpath, netflow_kwargs=source_kwargs, metadata=base_kwargs['metadata'])


class NetflowSource(base.DataSource):
    def __init__(self, urlpath, netflow_kwargs, metadata):
        self._init_args = dict(netflow_kwargs=netflow_kwargs, metadata=metadata)

        self._urlpath = urlpath
        self._netflow_kwargs = netflow_kwargs
        self._streams = None
        self._stream_sources = None

        super(NetflowSource, self).__init__(container='python', metadata=metadata)

    def _create_stream(self, src):
        return Stream(open(src, "rb"))

    def _get_schema(self):
        if self._streams is None:
            self._stream_sources = sorted(glob(self._urlpath))
            self._streams = [self._create_stream(src) for src in self._stream_sources]

        return base.Schema(datashape=None,
                           dtype=None,
                           shape=None,
                           npartitions=len(self._streams),
                           extra_metadata={})

    def _get_partition(self, i):
        self._streams[i] = self._create_stream(self._stream_sources[i])

        return self._streams[i]

    def _close(self):
        for stream in self._streams:
            stream.close()

        self._streams = None
        self._stream_sources = None
