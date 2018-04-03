import io


def read_and_unpack(source, obj):
    """Read and deserialize structure from stream.

    Parameters:
        source : io.BufferedReader
            Read-only input stream.
        obj : struct.Struct
            Deserialization struct.
    """
    return obj.unpack(source.read(obj.size))


def byte_stream(raw):
    return io.BufferedReader(io.BytesIO(raw))
