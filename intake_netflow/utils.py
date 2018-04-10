def read_and_unpack(source, obj):
    """Read and deserialize structure from stream.

    Parameters:
        source : file-like object
            Read-only input stream.
        obj : struct.Struct
            Deserialization struct.
    """
    return obj.unpack(source.read(obj.size))
