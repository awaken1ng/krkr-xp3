import zlib
import struct
from io import BufferedReader
from collections import namedtuple
from datetime import datetime
from .constants import XP3FileIsEncrypted


class XP3FileEncryption:
    encryption_chunk = struct.Struct('<QIH')

    def __init__(self, adler32: int, file_path: str, name: bytes = b'eliF'):
        """
        :param adler32: Adler-32 checksum of a file
        :param file_path: Internal file path
        :param name: Chunk header
        """
        self.name = name
        self.adler32 = adler32
        self.file_path = file_path

    @classmethod
    def read_from(cls, buffer: BufferedReader, name: bytes = b'eliF'):
        start = buffer.tell() + 8
        size, adler32, file_path_length = cls.encryption_chunk.unpack(buffer.read(14))
        file_path, = struct.unpack('<' + (str(file_path_length * 2) + 's') + 'xx',
                                   buffer.read(2 + file_path_length * 2))
        file_path = file_path.decode('utf-16le')

        if buffer.tell() != start + size:  # chunk size doesn't include the size itself
            raise AssertionError('Buffer position {}, expected {}'.format(buffer.tell(),
                                                                          start + size))
        return cls(adler32, file_path, name)

    def to_bytes(self):
        size = 4 + 2 + (len(self.file_path) * 2) + 2
        data = struct.pack('<QIH', size, self.adler32, len(self.file_path))
        file_path = self.file_path.encode('utf-16le') + b'\x00\x00'
        return self.name + data + file_path

    def __repr__(self):
        return "<XP3FileEncryption adler32={}, file_path='{}'>".format(self.adler32, self.file_path)


class XP3FileTime:
    time_chunk = struct.Struct('<QQ')

    def __init__(self, timestamp: int = 0):
        self.timestamp = timestamp


    @classmethod
    def read_from(cls, buffer: BufferedReader):
        size, timestamp = cls.time_chunk.unpack(buffer.read(16))
        if size != 8:
            raise AssertionError
        return cls(timestamp // 1000)

    def to_bytes(self):
        return b'time' + self.time_chunk.pack(8, self.timestamp)


class XP3FileSegments:
    segment = namedtuple('Segment', 'is_compressed, offset, uncompressed_size, compressed_size')
    _header = struct.Struct('<Q')
    _segment = struct.Struct('<?xxxQQQ')

    def __init__(self, segments: list):
        self.segments = segments

    @classmethod
    def read_from(cls, buffer: BufferedReader):
        size, = cls._header.unpack(buffer.read(8))
        number_of_segments = size // 28  # 28 bytes per segment
        segments = [cls.segment(*cls._segment.unpack(buffer.read(28)))
                    for _ in range(number_of_segments)]

        return cls(segments)

    @property
    def uncompressed_size(self):
        return sum([segment.uncompressed_size for segment in self.segments])

    @property
    def compressed_size(self):
        return sum([segment.compressed_size for segment in self.segments])

    def to_bytes(self):
        size = len(self.segments) * 28
        header = b'segm' + self._header.pack(size)
        segments = [self._segment.pack(*segment) for segment in self.segments]
        return header + b''.join(segments)

    def __iter__(self):
        yield from self.segments

    def __getitem__(self, item):
        return self.segments[item]

    def __repr__(self):
        return '<XP3FileSegments {} segment(s)>'\
            .format(len(self.segments))


class XP3FileInfo:
    info_chunk = struct.Struct('<QIQQH')

    def __init__(self, is_encrypted: bool, uncompressed_size: int, compressed_size: int, file_path: str):
        self.is_encrypted = is_encrypted
        self.uncompressed_size = uncompressed_size
        self.compressed_size = compressed_size
        self.file_path = file_path

    @classmethod
    def read_from(cls, buffer: BufferedReader):
        start = buffer.tell() + 8
        size, flags, uncompressed_size, compressed_size, file_path_length \
            = cls.info_chunk.unpack(buffer.read(30))
        encrypted = bool(flags & XP3FileIsEncrypted)

        # 2 bytes per character and 2 bytes null-terminator
        file_path, = struct.unpack('<' + (str(file_path_length * 2) + 's') + 'xx',
                                   buffer.read(2 + file_path_length * 2))
        file_path = file_path.decode('utf-16le')

        if buffer.tell() != start + size:
            raise AssertionError('Buffer position {}, expected {}'.format(buffer.tell(),
                                                                          start + size))
        return cls(encrypted, uncompressed_size, compressed_size, file_path)

    def to_bytes(self):
        size = 4 + 8 + 8 + 2 + (len(self.file_path) * 2) + 2
        flags = XP3FileIsEncrypted if self.is_encrypted else 0

        return b'info' \
               + self.info_chunk.pack(size, flags, self.uncompressed_size, self.compressed_size, len(self.file_path)) \
               + self.file_path.encode('utf-16le') + b'\x00\x00'

    def __repr__(self):
        return "<XP3FileInfo encrypted={}, uncompressed_size={}, compressed_size={}, file_path='{}'"\
            .format(self.is_encrypted, self.uncompressed_size, self.compressed_size, self.file_path)


class XP3FileAdler:
    adler32_chunk = struct.Struct('<QI')

    def __init__(self, adler32: int):
        self.value = adler32

    @classmethod
    def read_from(cls, buffer: BufferedReader):
        size, adler32, = cls.adler32_chunk.unpack(buffer.read(12))
        if size != 4:  # adler value size should always be 4 bytes
            raise AssertionError
        return cls(adler32)

    @classmethod
    def from_data(cls, data: bytes):
        return cls(zlib.adler32(data))

    def to_bytes(self):
        return b'adlr' + self.adler32_chunk.pack(4, self.value)

    def __repr__(self):
        return "<XP3FileAdler adler32={}>".format(self.value)


class XP3FileEntry:
    file_chunk = struct.Struct('<Q')

    def __init__(self, time: XP3FileTime, adlr: XP3FileAdler, segm: XP3FileSegments, info: XP3FileInfo,
                 encryption: XP3FileEncryption = None):
        self.encryption = encryption
        self.time = time
        self.adlr = adlr
        self.segm = segm
        self.info = info

        if encryption:
            if adlr.value != encryption.adler32:
                raise AssertionError('Checksum values in adlr chunk and encryption chunk do not match')

    @classmethod
    def read_from(cls, buffer: BufferedReader):
        encryption = None
        time = None
        adlr = None
        segm = None
        info = None

        name = buffer.read(4)
        if name != b'File':  # first chunk should be 'File', if not most likely an encryption chunk
            encryption = XP3FileEncryption.read_from(buffer, name)
            if buffer.read(4) != b'File':
                raise AssertionError
        start = buffer.tell()
        size, = cls.file_chunk.unpack(buffer.read(8))
        end = start + size
        while buffer.tell() < end:
            name = buffer.read(4)
            if name == b'time':
                time = XP3FileTime.read_from(buffer)
            elif name == b'adlr':
                adlr = XP3FileAdler.read_from(buffer)
            elif name == b'segm':
                segm = XP3FileSegments.read_from(buffer)
            elif name == b'info':
                info = XP3FileInfo.read_from(buffer)

        if not adlr or not segm or not info:
            raise AssertionError
        elif not time:  # time chunk is not always present
            time = XP3FileTime()  # create an empty placeholder

        return cls(adlr=adlr, segm=segm, info=info, time=time, encryption=encryption)

    @property
    def adler32(self):
        return self.adlr.value

    @property
    def is_encrypted(self):
        return bool(self.encryption)

    @property
    def file_path(self):
        if self.is_encrypted and self.encryption:
            return self.encryption.file_path
        else:
            return self.info.file_path

    def to_bytes(self):
        entry = self.time.to_bytes() \
            + self.adlr.to_bytes() \
            + self.segm.to_bytes() \
            + self.info.to_bytes()
        header = struct.pack('<4sQ', b'File', len(entry))
        encryption = self.encryption.to_bytes() if self.is_encrypted else b''

        return encryption + header + entry

    def __repr__(self):
        return "<XP3FileEntry file_path='{}', size={}, encrypted={}, timestamp={}>"\
            .format(self.file_path, self.info.uncompressed_size, self.is_encrypted, datetime.utcfromtimestamp(self.time.timestamp))
