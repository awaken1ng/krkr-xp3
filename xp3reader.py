from io import BytesIO
from structs import XP3Signature, XP3FileIndex, XP3File


class XP3Reader:
    def __init__(self, buffer, silent: bool = False, use_numpy: bool = True):
        if isinstance(buffer, bytes):
            buffer = BytesIO(buffer)

        self.buffer = buffer
        self.silent = silent
        self.use_numpy = use_numpy

        if XP3Signature != self.buffer.read(len(XP3Signature)):
            raise AssertionError('Is not an XP3 file')

        if not silent:
            print('Reading the file index', end='')
        self.file_index = XP3FileIndex.read_from(self.buffer)
        if not silent:
            print(', found {} file(s)'.format(len(self.file_index.entries)))

    def close(self):
        self.buffer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def is_encrypted(self):
        for file in self:
            if file.is_encrypted:
                return True
        return False

    # File access

    def __getitem__(self, item):
        """Access a file by it's internal file path or position in file index"""
        return XP3File(self.file_index[item], self.buffer, self.use_numpy)

    def open(self, item):
        return self.__getitem__(item)
