def read_and_unpack(source, obj):
    return obj.unpack(source.read(obj.size))
