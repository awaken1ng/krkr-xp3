import zlib
import struct
import hashlib
from io import BytesIO
from structs import XP3FileIndex, XP3FileEncryption, XP3FileTime, XP3FileAdler, XP3FileSegments, XP3FileInfo, XP3File, \
    XP3FileEntry, XP3Signature, encryption_parameters


class XP3Writer:
    def __init__(self, buffer: BytesIO = None, silent: bool = False, use_numpy: bool = True):
        """
        :param buffer: Buffer object to write data to
        :param silent: Supress prints
        :param use_numpy: Use Numpy for XORing if available
        """
        if not buffer:
            buffer = BytesIO()
        self.buffer = buffer
        self.file_entries = []
        self.silent = silent
        self.use_numpy = use_numpy
        buffer.seek(0)
        buffer.write(XP3Signature)
        buffer.write(struct.pack('<Q', 0))  # File index offset placeholder
        self.packed_up = False
        self._filenames = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.packed_up:
            self.pack_up()
        self.buffer.close()

    def add(self, internal_filepath: str, file: bytes, encryption_type: str = None, timestamp: int = 0):
        """
        Add a file to the archive
        :param internal_filepath: Internal file path
        :param file: File to add
        :param encryption_type: Encryption type to encrypt with
        :param timestamp: Timestamp (in milliseconds) to save
        """
        if self.packed_up:
            raise Exception('Archive is already packed up')
        if internal_filepath in self._filenames:
            raise FileExistsError

        self._filenames.append(internal_filepath)
        file_entry, file = self._create_file_entry(
            internal_filepath=internal_filepath,
            uncompressed_data=file,
            offset=self.buffer.tell(),
            encryption_type=encryption_type,
            timestamp=timestamp)
        self.file_entries.append(file_entry)
        if not self.silent:
            print('| Packing {} ({} -> {} bytes)'.format(internal_filepath,
                                                         file_entry.segm.uncompressed_size,
                                                         file_entry.segm.compressed_size))
        self.buffer.write(file)

    def pack_up(self) -> bytes:
        """
        Write the file index to the archive, returns the resulting archive if it can
        (if already packed, just returns the archive)
        """
        if self.packed_up:
            if hasattr(self.buffer, 'getvalue'):
                return self.buffer.getvalue()

        # Write the file index
        file_index = XP3FileIndex.from_entries(self.file_entries).to_bytes()
        file_index_offset = self.buffer.tell()
        self.buffer.write(file_index)

        # Go back to the header and write the offset
        self.buffer.seek(len(XP3Signature))
        self.buffer.write(struct.pack('<Q', file_index_offset))

        # Mark as packed up and return the resulting archive
        self.packed_up = True
        # Flush the buffer explicitly, had a test fail because index was missing
        self.buffer.flush()
        if hasattr(self.buffer, 'getvalue'):
            return self.buffer.getvalue()

    def _create_file_entry(self, internal_filepath, uncompressed_data, offset, encryption_type: str = None,
                           timestamp: int = 0) -> (XP3FileEntry, bytes):
        """
        Create a file entry for a file
        :param internal_filepath: Internal file path
        :param uncompressed_data: File to create entry for
        :param offset: Position in the buffer to put into the segment data
        :param encryption_type: Encryption type to use
        :param timestamp Timestamp (in milliseconds)
        :return XP3FileEntry object and compressed or uncompressed file (to write into buffer)
        """

        uncompressed_size = len(uncompressed_data)
        compressed_data = zlib.compress(uncompressed_data, level=9)
        compressed_size = len(compressed_data)

        if compressed_size >= uncompressed_size:
            data = uncompressed_data
            compressed_size = uncompressed_size
            is_compressed = False
        else:
            data = compressed_data
            is_compressed = True

        adlr = XP3FileAdler.from_data(uncompressed_data)
        time = XP3FileTime(timestamp)

        is_encrypted = False if encryption_type in ('none', None) else True
        if is_encrypted:
            data = self.xor(data, adlr.value, encryption_type, self.use_numpy)
            _, _, _, name = encryption_parameters[encryption_type]
            encryption = XP3FileEncryption(adlr.value, internal_filepath, name)
            path_hash = hashlib.md5(internal_filepath.lower().encode('utf-16le')).hexdigest()
        else:
            encryption = path_hash = None

        info = XP3FileInfo(is_encrypted=is_encrypted,
                           uncompressed_size=uncompressed_size,
                           compressed_size=compressed_size,
                           file_path=internal_filepath if not is_encrypted else path_hash
                           )

        segment = XP3FileSegments.segment(
            compressed=is_compressed,
            offset=offset,
            uncompressed_size=uncompressed_size,
            compressed_size=compressed_size
        )
        segm = XP3FileSegments([segment])

        file_entry = XP3FileEntry(encryption=encryption, time=time, adlr=adlr, segm=segm, info=info)

        return file_entry, data

    @staticmethod
    def xor(data, adler32, encryption_type, use_numpy):
        with BytesIO() as buffer:
            buffer.write(data)
            XP3File.xor(buffer, adler32, encryption_type, use_numpy)
            return buffer.getvalue()
