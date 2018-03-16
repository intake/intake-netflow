import io


def byte_stream(raw):
    return io.BufferedReader(io.BytesIO(raw))
