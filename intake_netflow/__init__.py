from intake.source import base

from ._version import get_versions

__version__ = get_versions()['version']
del get_versions


class Plugin(base.Plugin):
    """Cisco Netflow packets to sequence of Python dicts reader"""

    def __init__(self):
        super(Plugin, self).__init__(name='netflow', version='0.1', container='python', partition_access=False)

    def open(self, urlpath, **kwargs):
        """
        Parameters:
            urlpath : str
                Location of the data files; can include protocol and glob characters.
        """
        from .source import NetflowSource
        base_kwargs, source_kwargs = self.separate_base_kwargs(kwargs)
        return NetflowSource(urlpath=urlpath, metadata=base_kwargs['metadata'])
