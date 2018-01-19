#!/usr/bin/env python

# KiriKiri .XP3 archive repacking and extraction tool
#
# Extracts an .XP3 archive to a directory of files, and
# packs a directory of files into an .XP3 archive, including any
# subdirectory structure.
#
# Original script by Edward Keyes, ed-at-insani-dot-org, 2006-07-08, http://www.insani.org/tools/
# Updated by SmilingWolf, https://bitbucket.org/SmilingWolf/xp3tools-updated
# Python 3 port, Awakening

import os
import zlib
import struct
import hashlib
from array import array
from io import BytesIO


xp3_signature = b'XP3\x0D\x0A\x20\x0A\x1A\x8B\x67\x01'
encryption_parameters = {
    # Master key, secondary key, XOR the first byte
    'none':            (0x00000000, 0x00, False),
    'neko_vol1':       (0x1548E29C, 0xD7, False),
    'neko_vol1_steam': (0x44528B87, 0x23, False),
    'neko_vol0':       (0x1548E29C, 0xD7, True),
    'neko_vol0_steam': (0x44528B87, 0x23, True),
}


def read_i16le(input_buffer): return struct.unpack('<h', input_buffer.read(2))[0]
def read_i64le(input_buffer): return struct.unpack('<q', input_buffer.read(8))[0]
def read_u8le(input_buffer):  return struct.unpack('<B', input_buffer.read(1))[0]
def read_u16le(input_buffer): return struct.unpack('<H', input_buffer.read(2))[0]
def read_u32le(input_buffer): return struct.unpack('<I', input_buffer.read(4))[0]
def read_u64le(input_buffer): return struct.unpack('<Q', input_buffer.read(8))[0]
def write_u16le(output_buffer, value): output_buffer.write(struct.pack('<H', value))
def write_u32le(output_buffer, value): output_buffer.write(struct.pack('<I', value))
def write_u64le(output_buffer, value): output_buffer.write(struct.pack('<Q', value))
def write_string(output_buffer, value): output_buffer.write(value + b'\0')


def define_encryption_parameters(encryption):
    if encryption not in encryption_parameters.keys():
        print('Check that you\'re spelling the encryption type correctly')
        print('Defaulting to no encryption')
        encryption = 'none'
    return encryption_parameters[encryption]


def xor(output_buffer, master_key, secondary_key, xor_the_first_byte, adler32):
    # Calculate the XOR key
    xor_key = adler32 ^ master_key
    xor_key = (xor_key >> 24 ^ xor_key >> 16 ^ xor_key >> 8 ^ xor_key) & 0xFF
    if not xor_key:
        xor_key = secondary_key

    # Read the encrypted data from buffer
    output_buffer.seek(0)
    data = array('B', output_buffer.read())

    if xor_the_first_byte:
        first_byte_key = (adler32 ^ master_key) & 0xFF
        if not first_byte_key:
            first_byte_key = master_key & 0xFF
        data[0] ^= first_byte_key

    # XOR the data
    for index in range(len(data)):
        data[index] ^= xor_key

    # Overwrite the buffer with decrypted data
    output_buffer.seek(0)
    output_buffer.write(data.tobytes())


def pack_folder(input_directory, output_archive, encryption='none', silent=False, flatten=False):
    # Flatten - ignore the subdirectories and write as if all files are in the root folder
    def write_file_entry(output_buffer, entry):
        if entry['encrypted']:
            output_buffer.write(entry['encryption segment name'])
            # Write the actual file path here instead of info segment
            write_u64le(output_buffer, 4 + 2 + len(entry['internal file path']))
            write_u32le(output_buffer, entry['adler-32'])
            write_u16le(output_buffer, int(len(entry['internal file path']) / 2))
            output_buffer.write(entry['internal file path'])
            write_u16le(output_buffer, 0)
            # Put file path hash in info instead
            entry['internal file path'] = entry['file path hash']
        output_buffer.write(b'File')
        write_u64le(output_buffer, len(entry['internal file path']) + 20 + len(entry['segments']) * 28 + 62)
        output_buffer.write(b'time')
        write_u64le(output_buffer, 8)
        write_u64le(output_buffer, 0)
        output_buffer.write(b'adlr')
        write_u64le(output_buffer, 4)
        write_u32le(output_buffer, entry['adler-32'])
        output_buffer.write(b'segm')
        write_u64le(output_buffer, len(entry['segments']) * 28)
        for segment in entry['segments']:
            write_u32le(output_buffer, segment['compressed'])
            write_u64le(output_buffer, segment['offset'])
            write_u64le(output_buffer, segment['decompressed size'])
            write_u64le(output_buffer, segment['compressed size'])
        output_buffer.write(b'info')
        write_u64le(output_buffer, len(entry['internal file path']) + 22)
        write_u32le(output_buffer, entry['encrypted'])
        write_u64le(output_buffer, entry['decompressed size'])
        write_u64le(output_buffer, entry['compressed size'])
        write_u16le(output_buffer, int(len(entry['internal file path']) / 2))
        output_buffer.write(entry['internal file path'])

    def lower(string):
        for i in range(0, len(string), 2):
            if string[i] >= 0x41 and string[i] <= 0x5A and string[i + 1] == 0x00:
                string = string[:i] + bytes(string[i] + 0x20) + string[i + 1:]
        return string

    # Check for name collisions
    if flatten:
        filenames = []
        for root, dirs, files in os.walk(input_directory):
            for file in files:
                filenames.append(file)
        if len(filenames) != len(set(filenames)):
            raise Exception('Duplicate file names found')

    with open(output_archive, 'wb') as archive:
        master_key, secondary_key, xor_the_first_byte = define_encryption_parameters(encryption)

        # Write header
        write_string(archive, xp3_signature)
        write_u64le(archive, 0)

        # Scan for files, write them and collect the index as we go
        with BytesIO() as index_buffer:
            for root, dirs, filenames in os.walk(input_directory):
                assert root.startswith(input_directory)
                # Strip off the base directory and possible slash
                # and make sure we're using forward slash as a separator
                internal_root_path = root[len(input_directory) + 1:]
                internal_root_path = internal_root_path.split(os.sep)
                internal_root_path = '/'.join(internal_root_path)

                for filename in filenames:
                    file_entry = {}
                    segment = {}

                    if internal_root_path and not flatten:
                        internal_file_path = internal_root_path + '/' + filename
                    else:
                        internal_file_path = filename
                    file_entry['internal file path'] = internal_file_path.encode('utf-16le')

                    with open(os.path.join(root, filename), 'rb') as infile:
                        data = infile.read()

                        file_entry['adler-32'] = zlib.adler32(data)
                        file_entry['decompressed size'] = segment['decompressed size'] = len(data)

                        if encryption != 'none':
                            if encryption in ['neko_vol0', 'neko_vol0_steam']:
                                file_entry['encryption segment name'] = b'neko'
                            else:
                                file_entry['encryption segment name'] = b'eliF'
                            file_entry['encrypted'] = 0x0080000000

                            # Calculate the hash of an internal file path
                            file_path_hash = hashlib.md5()
                            file_path_hash.update(lower(file_entry['internal file path']))
                            file_path_hash = file_path_hash.hexdigest()
                            file_path_hash = file_path_hash.encode('utf-16le')
                            file_entry['file path hash'] = file_path_hash

                            # Encrypt the data
                            with BytesIO() as encrypted_data:
                                encrypted_data.write(data)
                                xor(encrypted_data, master_key, secondary_key, xor_the_first_byte, file_entry['adler-32'])
                                data = encrypted_data.getvalue()
                        else:
                            file_entry['encrypted'] = 0

                        compressed_data = zlib.compress(data, 9)
                        # Don't store compressed data if it barely changes the data size
                        if len(compressed_data) < 0.95 * len(data):
                            segment['compressed'] = 1
                            data = compressed_data
                        else:
                            segment['compressed'] = 0
                        file_entry['compressed size'] = segment['compressed size'] = len(data)
                        segment['offset'] = archive.tell()
                        file_entry['segments'] = [segment]  # Always using a list of one segment
                        write_file_entry(index_buffer, file_entry)
                        if not silent:
                            if internal_root_path and not flatten:
                                internal_file_path = internal_root_path + '/' + filename
                            else:
                                internal_file_path = filename
                            print('Packing {} ({} -> {} bytes)'.format(internal_file_path,
                                                                       file_entry['decompressed size'],
                                                                       file_entry['compressed size']))
                        archive.write(data)

            # Now write the index and go back and put its offset in the header
            index_offset = archive.tell()
            index = index_buffer.getvalue()
            compressed_index = zlib.compress(index, 9)
            archive.write(b'\x01')
            write_u64le(archive, len(compressed_index))
            write_u64le(archive, len(index))
            archive.write(compressed_index)
            archive.seek(11)  # Length of header
            write_u64le(archive, index_offset)


def extract(input_archive, output_directory, encryption='none', silent=False, dump_index=False, skip_long_names=True):
    # Skip long names - do not extract files with long names, usually a copyright infringement notice.
    # Dump index - dump the archive index

    def read_file_entry(archive, header_offset):
        file_entry = {
            'adler-32': False,
            'internal file path': '',
            'segments': []
        }
        initial_position = archive.tell()
        entry_size = read_u64le(archive)
        while archive.tell() < initial_position + entry_size:
            entry_name = archive.read(4)
            if entry_name == b'time':
                # Skip the segment
                archive.seek(16, 1)
            elif entry_name == b'adlr':
                assert read_u64le(archive) == 4
                file_entry['adler-32'] = read_u32le(archive)
            elif entry_name == b'segm':
                number_of_segments = read_u64le(archive) // 28  # 28 bytes per segment
                for _ in range(number_of_segments):
                    segment = {
                        'compressed': bool(read_u32le(archive)),
                        'offset': read_u64le(archive) + header_offset,
                        'decompressed size': read_u64le(archive),
                        'compressed size': read_u64le(archive)
                    }
                    file_entry['segments'].append(segment)
            elif entry_name == b'info':
                info_size = read_u64le(archive)
                cursor_position = archive.tell()
                file_entry['encrypted'] = bool(read_u32le(archive))
                file_entry['decompressed size'] = read_u64le(archive)
                file_entry['compressed size'] = read_u64le(archive)
                filename_length = read_i16le(archive)
                for _ in range(filename_length):
                    file_entry['internal file path'] += chr(read_u8le(archive))
                    archive.seek(1, 1)
                archive.seek(cursor_position + info_size, 0)


        # Make sure the adler, segment and info segments were processed
        assert file_entry['adler-32'] and file_entry['segments'] and file_entry['compressed size']
        return file_entry

    with open(input_archive, 'rb') as archive:
        archive_size = os.stat(input_archive).st_size
        master_key, secondary_key, xor_the_first_byte = define_encryption_parameters(encryption)

        # Find the header offset of an XP3 archive
        # TODO add support for archives bundled into executables
        header_offset = archive.read(4096).rfind(xp3_signature)
        archive.seek(header_offset, 0)

        # Assert the archive signature and read the index offset
        assert xp3_signature == archive.read(len(xp3_signature))
        index_offset = read_i64le(archive)

        # Seek to index
        archive.seek(header_offset + index_offset, 0)
        index_first_byte = archive.read(1)
        if index_first_byte == b'\x80':
            # To keep compatibility with legacy xp3 files we check if the current byte is 0x80
            # This is a constant defined inside KiriKiriZ itself
            if not silent:
                print('! Legacy XP3 archive')
            archive.seek(8, 1)
            index_offset = header_offset + read_i64le(archive)
            archive.seek(index_offset, 0)
            index_first_byte = archive.read(1)
        if index_first_byte != b'\x01':
            if not silent:
                raise AssertionError('Unknown first byte of the index')

        # Read the index size
        index_compressed_size = read_u64le(archive)
        index_decompressed_size = read_u64le(archive)
        assert index_offset + index_compressed_size + 17 == archive_size

        # Read the index
        index = archive.read(index_compressed_size)
        index = zlib.decompress(index)
        assert len(index) == index_decompressed_size
        if dump_index:
            index_path = os.path.join(os.path.dirname(input_archive), os.path.basename(input_archive)) + '.index'
            if not silent:
                print('Dumping the index at {}'.format(index_path))
            with open(index_path, 'wb') as output_buffer:
                output_buffer.write(index)
            return

        if not silent:
            print('Reading the archive index', end='')
        # Read file entries from the index
        with BytesIO(index) as index:
            file_entries = []
            while index.tell() < index_decompressed_size:
                encrypted = False
                entry_name = index.read(4)
                if entry_name in [b'neko', b'eliF']:
                    encrypted = True
                    entry_size = read_u64le(index)
                    adler32 = read_u32le(index)
                    filename_length = read_u16le(index)
                    internal_file_path = array('B')
                    for _ in range(filename_length * 2):
                        internal_file_path.append(read_u8le(index))
                    internal_file_path = internal_file_path.tobytes().decode('utf-16le')
                    index.read(2)  # String terminator
                    entry_name = index.read(4)  # Read the next entry name to process the rest
                if entry_name == b'File':
                    file_entry = read_file_entry(index, header_offset)
                    if encrypted:
                        assert adler32 == file_entry['adler-32']
                        # If file is encrypted the file path in file entry will be hashed
                        file_entry['file path hash'] = file_entry['internal file path']
                        file_entry['internal file path'] = internal_file_path
                    file_entries.append(file_entry)
        if not silent:
            print(', found {} files.'.format(len(file_entries)))


        # Starting the extraction
        for file_entry in file_entries:
            if file_entry['encrypted'] and 'file path hash' not in file_entry:
                # If for some reason the file was marked as encrypted, but the file path hash is missing.
                # Unmark and dump raw instead.
                file_entry['encrypted'] = False

            if len(file_entry['internal file path']) > 256:
                if skip_long_names:
                    if not silent:
                        print('Skipping {} ({} -> {} bytes)'.format(file_entry['internal file path'],
                                                                    file_entry['compressed size'],
                                                                    file_entry['decompressed size']))
                    continue
                # If the name is too long use file path hash as a name instead
                file_entry['internal file path'] = file_entry['file path hash']

            if not silent:
                print('Extracting {} ({} -> {} bytes)'.format(file_entry['internal file path'],
                                                              file_entry['compressed size'],
                                                              file_entry['decompressed size']))

            # Paths inside the XP3 use forward slashes as separators
            path_components = file_entry['internal file path'].split('/')
            output_file_path = output_directory
            for path_component in path_components:
                # Create directory if it doesn't exist
                if not os.path.isdir(output_file_path):
                    os.mkdir(output_file_path)
                output_file_path = os.path.join(output_file_path, path_component)

            # Start reading data from archive and writing it
            with BytesIO() as output_buffer:
                # Reading the data
                for segment in file_entry['segments']:
                    archive.seek(segment['offset'])
                    if segment['compressed']:
                        data = zlib.decompress(archive.read(segment['compressed size']))
                    else:
                        data = archive.read(segment['compressed size'])
                    assert len(data) == segment['decompressed size']
                    output_buffer.write(data)

                if file_entry['encrypted']:
                    if encryption != 'none':
                        # Decrypt the file
                        xor(output_buffer, master_key, secondary_key, xor_the_first_byte, file_entry['adler-32'])
                    else:
                        if not silent:
                            print('| The file is encrypted, but no encryption type was specified. Dumping it raw...')

                # Compare the checksums
                adler32 = zlib.adler32(output_buffer.getvalue())
                if adler32 != file_entry['adler-32']:
                    if not silent:
                        print(f"| Checksum error ({adler32} != {file_entry['adler-32']}), but continuing...")
                # Writing the file
                try:
                    with open(output_file_path, 'wb') as output_file:
                        output_file.write(output_buffer.getvalue())
                except IOError:
                    if not silent:
                        print('| Problem writing {}, but continuing...'.format(file_entry['internal file path']))


if __name__ == "__main__":
    import argparse

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
        extract(input_archive=args.input, output_directory=args.output,
                encryption=args.encryption, silent=args.silent, dump_index=args.dump_index)
    elif args.mode in ('r', 'repack'):
        pack_folder(input_directory=args.input, output_archive=args.output,
                    encryption=args.encryption, silent=args.silent, flatten=args.flatten)
