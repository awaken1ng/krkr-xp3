#!/usr/bin/env python

# KiriKiri .XP3 archive repacking and extraction tool
#
# Extracts an .XP3 archive to a directory of files, and
# packs a directory of files into an .XP3 archive, including any
# subdirectory structure.
#
# Uses Numpy (if available) to speed up decryption/encryption.
#
# Original script by Edward Keyes, ed-at-insani-dot-org, 2006-07-08, http://www.insani.org/tools/
# and SmilingWolf, https://bitbucket.org/SmilingWolf/xp3tools-updated
# Python 3 rewrite, Awakening


import os
from xp3reader import XP3Reader
from xp3writer import XP3Writer


class XP3(XP3Reader, XP3Writer):
    def __init__(self, target, mode='r', silent=False):
        self.mode = mode

        if self._is_readmode:
            if isinstance(target, str):
                if not os.path.isfile(target):
                    raise FileNotFoundError
                with open(target, 'rb') as buffer:
                    target = buffer.read()
            XP3Reader.__init__(self, target, silent)
        elif self._is_writemode:
            if isinstance(target, str):
                if not os.path.exists(os.path.dirname(target)):
                    os.makedirs(os.path.dirname(target))
                target = open(target, 'wb')
            XP3Writer.__init__(self, target, silent)
        else:
            raise ValueError('Invalid operation mode')

    @property
    def _is_readmode(self):
        return True if self.mode == 'r' else False

    @property
    def _is_writemode(self):
        return True if self.mode == 'w' else False

    def extract(self, to='', encryption_type='none'):
        """Extract all files in the archive to specified folder"""
        if not self._is_readmode:
            raise Exception('Archive is not open in reading mode')

        for file in self:
            try:
                if not self.silent:
                    print('| Extracting {} ({} -> {} bytes)'.format(file.file_path,
                                                                    file.info.compressed_size,
                                                                    file.info.uncompressed_size))
                file.extract(to=to, encryption_type=encryption_type)
            except OSError:  # Usually because of long file names
                if not self.silent:
                    print('! Problem writing {}'.format(file.file_path))
        return self

    def add_folder(self, path, flatten: bool = False, encryption_type: str = None, save_timestamps: bool = False):
        if not self._is_writemode:
            raise Exception('Archive is not open in writing mode')
        if not self.silent:
            print('Packing {}'.format(path))
        for dirpath, dirs, filenames in os.walk(path):
            # Strip off the base directory and possible slash
            internal_root = dirpath[len(path) + 1:]
            # and make sure we're using forward slash as a separator
            internal_root = internal_root.split(os.sep)
            internal_root = '/'.join(internal_root)

            for filename in filenames:
                internal_filepath = internal_root + '/' + filename \
                                    if internal_root and not flatten \
                                    else filename
                self.add_file(os.path.join(dirpath, filename), internal_filepath, encryption_type, save_timestamps)

    def add_file(self, path, internal_filepath: str = None, encryption_type: str = None, save_timestamps: bool = False):
        """
        :param path: Path to file
        :param internal_filepath: Internal archive path to save file under (if not specified, file name is used)
        :param encryption_type: Encryption type to use
        :param save_timestamps: Save the file creating time into archive or not
        """
        if not self._is_writemode:
            raise Exception('Archive is not open in writing mode')

        if not os.path.exists(path):
            raise FileNotFoundError

        with open(path, 'rb') as buffer:
            data = buffer.read()
            if not internal_filepath:
                internal_filepath = os.path.basename(buffer.name)

        timestamp = 0 if not save_timestamps else round(os.path.getctime(path) * 1000)
        super().add(internal_filepath, data, encryption_type, timestamp)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Write the file index in the archive as we leave the context manager"""
        if self._is_writemode:
            if not self.packed_up:
                self.pack_up()
            self.buffer.close()


if __name__ == '__main__':
    import argparse
    from structs.encryption_parameters import encryption_parameters

    def input_filepath(path: str) -> str:
        if not os.path.exists(os.path.realpath(path)):
            raise argparse.ArgumentError
        return path


    parser = argparse.ArgumentParser(description='KiriKiri .XP3 archive repacking and extraction tool')
    parser.add_argument('-mode', '-m', choices=['e', 'r', 'extract', 'repack'], default='e', help='Operation mode')
    parser.add_argument('-silent', '-s', action='store_true', default=False)
    parser.add_argument('-flatten', '-f', action='store_true', default=False,
                        help='Ignore the subdirectories and pack the archive as if all files are in the root folder')
    parser.add_argument('--dump-index', '-i', action='store_true', help='Dump the file index of an archive')
    parser.add_argument('-encryption', '-e', choices=encryption_parameters.keys(), default='none',
                        help='Specify the encryption method')
    parser.add_argument('input', type=input_filepath, help='File to unpack or folder to pack')
    parser.add_argument('output', help='Output folder to unpack into or output file to pack into')
    args = parser.parse_args()

    if args.mode in ('e', 'extract'):
        with XP3(args.input, 'r', args.silent) as xp3:
            if args.dump_index:
                xp3.file_index.extract(args.output)
            else:
                xp3.extract(args.output, args.encryption)
    elif args.mode in ('r', 'repack'):
        with XP3(args.output, 'w', args.silent) as xp3:
            xp3.add_folder(args.input, args.flatten, args.encryption)
