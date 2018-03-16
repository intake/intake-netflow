def read_and_unpack(source, obj):
    """Read and deserialize structure from stream."""
    return obj.unpack(source.read(obj.size))
