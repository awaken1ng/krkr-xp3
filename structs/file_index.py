import os
import zlib
import struct
from .file_entry import XP3FileEntry
from io import BytesIO
from .constants import XP3Signature, XP3FileIndexContinue, XP3FileIndexCompressed, Xp3FileIndexUncompressed


class peek:
    """
        Context manager, goes to position in the buffer and goes back
        Usage example::
            buffer.tell() # 0
            with peek(buffer, position) as peek_buffer:
                peek_buffer.read(4)
            buffer.tell() # 0
    """

    def __init__(self, input_buffer, position):
        self.input_buffer = input_buffer
        self.position = position

    def __enter__(self):
        self.initial_position = self.input_buffer.tell()
        self.input_buffer.seek(self.position)
        return self.input_buffer

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.input_buffer.seek(self.initial_position)


class XP3FileIndex:
    def __init__(self, entries: list, buffer=None):
        self.entries = entries
        self.path_index = {entry.file_path: index for index, entry in enumerate(entries)}
        self.buffer = buffer

    @classmethod
    def from_entries(cls, entries: list, buffer=None):
        return cls(entries, buffer)

    @classmethod
    def read_from(cls, buffer):
        """Constructor to instantiate class from buffer"""
        index = cls.read_index(buffer)
        entries = []
        with BytesIO(index) as index_buffer:
            while index_buffer.tell() < len(index):
                entries.append(XP3FileEntry.read_from(index_buffer))

        return cls.from_entries(entries, buffer)

    def extract(self, to=''):
        """Dump file index from buffer"""

        with peek(self.buffer, len(XP3Signature)):
            index = self.read_index(self.buffer)

        dirname = os.path.dirname(to)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        with open(to, 'wb') as out:
            out.write(index)

        return self

    @staticmethod
    def read_index(buffer):
        """Reads file index from buffer"""
        offset, = struct.unpack('<1Q', buffer.read(8))
        if not offset:
            raise AssertionError('File index offset is missing')
        buffer.seek(offset, 0)

        flag, = struct.unpack('<B', buffer.read(1))
        if flag == XP3FileIndexContinue:  # Index is in another castle
            offset, = struct.unpack('<8x1Q', buffer.read(16))
            buffer.seek(offset, 0)
            flag, = struct.unpack('<B', buffer.read(1))

        if flag == XP3FileIndexCompressed:
            compressed_size, uncompressed_size = struct.unpack('<2Q', buffer.read(16))
            index = buffer.read(compressed_size)
            index = zlib.decompress(index)
            if len(index) != uncompressed_size:
                raise AssertionError('Index size mismatch')
        elif flag == Xp3FileIndexUncompressed:
            uncompressed_size, = struct.unpack('<Q', buffer.read(8))
            index = buffer.read(uncompressed_size)
        else:
            raise AssertionError('Unexpected index flag {}'.format(flag))

        return index

    def to_bytes(self):
        uncompressed_index = b''.join([entry.to_bytes() for entry in self.entries])
        compressed_index = zlib.compress(uncompressed_index, level=9)
        uncompressed_size = len(uncompressed_index)
        compressed_size = len(compressed_index)
        if compressed_size + 1 + 8 + 8 < uncompressed_size + 1 + 8:  # Account for header overhead
            return struct.pack('<BQQ', XP3FileIndexCompressed, compressed_size, uncompressed_size) + compressed_index
        else:
            return struct.pack('<BQ', Xp3FileIndexUncompressed, uncompressed_size) + uncompressed_index

    def __iter__(self):
        yield from self.entries

    def __getitem__(self, item):
        """Access file entries by index position or their file path"""
        if isinstance(item, int):
            return self.entries[item]
        elif isinstance(item, str):
            return self.entries[self.path_index[item]]
        else:
            raise TypeError

    def __repr__(self):
        return "<XP3FileIndex, {} entry(ies)>".format(len(self.entries))
