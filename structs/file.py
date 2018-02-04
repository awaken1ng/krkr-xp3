import os
from io import BytesIO
from array import array
import zlib
from .encryption_parameters import encryption_parameters
from .file_entry import XP3FileEntry
try:
    from numpy import frombuffer, uint8, bitwise_and, bitwise_xor, right_shift, concatenate
    numpy = True
except ModuleNotFoundError:
    numpy = False


class XP3DecryptionError(Exception):
    pass


class XP3File(XP3FileEntry):
    """Wrapper around file entry with buffer access to be able to read the file"""

    def __init__(self, index_entry: XP3FileEntry, buffer, use_numpy):
        super(XP3File, self).__init__(
            encryption=index_entry.encryption,
            time=index_entry.time,
            adlr=index_entry.adlr,
            segm=index_entry.segm,
            info=index_entry.info
        )
        self.buffer = buffer
        self.use_numpy = use_numpy

    def read(self, encryption_type='none', raw=False):
        """Reads the file from buffer and return it's data"""
        with BytesIO() as file_buffer:
            # Read the data
            for segment in self.segm:
                self.buffer.seek(segment.offset)
                data = self.buffer.read(segment.compressed_size)
                if segment.compressed:
                    data = zlib.decompress(data)
                if len(data) != segment.uncompressed_size:
                    raise AssertionError(len(data), segment.uncompressed_size)
                file_buffer.write(data)

            if self.is_encrypted:
                if encryption_type in ('none', None) and not raw:
                    raise XP3DecryptionError('File is encrypted and no encryption type was specified')
                self.xor(file_buffer, self.adler32, encryption_type, self.use_numpy)

            return file_buffer.getvalue()

    def extract(self, to='', name=None, encryption_type='none', raw=False):
        """
        Reads the data and saves the file to specified folder,
        if no location is specified, unpacks into folder with archive name (data.xp3, unpacks into data folder)
        """
        file = self.read(encryption_type=encryption_type, raw=raw)
        if zlib.adler32(file) != self.adler32:
            print('! Checksum error')

        if not to:
            # Use archive name as output folder if it's not explicitly specified
            basename = os.path.basename(self.buffer.name)
            to = os.path.splitext(basename)[0]
        if not name:
            name = self.file_path
        to = os.path.join(to, name)
        dirname = os.path.dirname(to)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        with open(to, 'wb') as output:
            output.write(file)

    @staticmethod
    def xor(output_buffer, adler32: int, encryption_type: str, use_numpy: bool = True):
        """XOR the data, uses numpy if available"""
        master_key, secondary_key, xor_the_first_byte, _ = encryption_parameters[encryption_type]
        # Read the encrypted data from buffer
        output_buffer.seek(0)
        data = output_buffer.read()

        # Use numpy if available
        if numpy and use_numpy:
            # Calculate the XOR key
            adler_key = bitwise_xor(adler32, master_key)
            xor_key = bitwise_and(bitwise_xor(bitwise_xor(bitwise_xor(right_shift(adler_key, 24), right_shift(adler_key, 16)), right_shift(adler_key, 8)), adler_key), 0xFF)
            if not xor_key:
                xor_key = secondary_key

            data = frombuffer(data, dtype=uint8)

            if xor_the_first_byte:
                first_byte_key = bitwise_and(adler_key, 0xFF)
                if not first_byte_key:
                    first_byte_key = bitwise_and(master_key, 0xFF)
                # Split the first byte into separate array
                first = frombuffer(data[:1], dtype=uint8)
                rest = frombuffer(data[1:], dtype=uint8)
                # XOR the first byte
                first = bitwise_xor(first, first_byte_key)
                # Concatenate the array back
                data = concatenate((first, rest))

            data = bitwise_xor(data, xor_key)
        else:
            adler_key = adler32 ^ master_key
            xor_key = (adler_key >> 24 ^ adler_key >> 16 ^ adler_key >> 8 ^ adler_key) & 0xFF
            if not xor_key:
                xor_key = secondary_key

            data = array('B', data)

            if xor_the_first_byte:
                first_byte_key = adler_key & 0xFF
                if not first_byte_key:
                    first_byte_key = master_key & 0xFF
                data[0] ^= first_byte_key

            # XOR the data
            for index in range(len(data)):
                data[index] ^= xor_key

        # Overwrite the buffer with decrypted/encrypted data
        output_buffer.seek(0)
        output_buffer.write(data.tobytes())
