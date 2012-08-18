#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Parse tcpdump file into format that can be used by dumpy

The parsing that is done is currently by each character byte. Although
we do know the number of bytes to read, this routine is currently not
struct.pack or struct.unpacking those bytes.

Instead, this is completely driven on a byte-by-byte read. Additional
routines that are equivalent to converting network byte order into
integers (for example) are done in a non-efficient way.  Additionally,
we only parse ethernet linked-level data.

However, with that said, this has done a reasonable job of making
tcpdump data accessible for immediate use.
"""

import sys

from network import Ethernet, DLT_EN10MB


def parse_bytes(bytes, is_byte_swapped=False):
    # Take read characters and parse bytes
    bytes = [ord(m) for m in bytes]
    if is_byte_swapped:
        bytes.reverse()

    return bytes


def convert_to_number(bytes):
    reverse_bytes = bytes
    reverse_bytes.reverse()
    return sum([(b * (256 ** a)) for a, b in enumerate(reverse_bytes)])


def read_preamble(f):
    """Read preamble of input file

    Read the preamble of an input tcpdump file. When finished, the
    file position will be immediately after the preamble. Additionally,
    the following values are returned:
       0: A boolean if the file is byte swapped (True is byte swapped)
       1: The file magic number (4-tuple)
       2: The maximum length of a capture
       3: The linked layer type of this input file.
    """

    # We are reading the preamble from the begining of the file.
    assert f.tell() == 0

    byte_swap = False

    # File pre-amble contains...
    # ... a 32-bit "magic number"
    magic_number = f.read(4)
    if ord(magic_number[0]) == 0xd4:
        byte_swap = True

    magic_number = parse_bytes(magic_number, is_byte_swapped=byte_swap)

    # ... a 16-bit major version number;
    major_version = convert_to_number(parse_bytes(f.read(2),
                                                  is_byte_swapped=byte_swap))

    # ... a 16-bit minor version number;
    minor_version = convert_to_number(parse_bytes(f.read(2),
                                                  is_byte_swapped=byte_swap))

    # ... an unused 32-bit time zone offset field;
    timezone_offset = convert_to_number(parse_bytes(f.read(4),
                                                    is_byte_swapped=byte_swap))
    if timezone_offset != 0:
        raise ValueError("We are not considering timezone offset!")

    # ... an unused 32-bit time stamp accuracy field;
    time_accuracy = convert_to_number(parse_bytes(f.read(4),
                                                  is_byte_swapped=byte_swap))
    if time_accuracy != 0:
        raise ValueError("We are not considering time accuracy!")

    # ... a 32-bit field giving the maximum length of the saved data in
    # packets
    snapshot_length = convert_to_number(parse_bytes(f.read(4),
                                                    is_byte_swapped=byte_swap))

    # ... a 32-bit field giving the link-layer type of the packets in the
    # capture.
    linked_layer_type = convert_to_number(parse_bytes(
        f.read(4),
        is_byte_swapped=byte_swap))

    version = "{0}.{1}".format(major_version, minor_version)

    return (byte_swap, magic_number, version, snapshot_length,
            linked_layer_type)


def parse_file(filename):
    results = []
    with open(filename, "rb") as f:

        preamble = read_preamble(f)
        byte_swap = preamble[0]
        version = preamble[2]
        linked_layer_type = preamble[4]

        if linked_layer_type != DLT_EN10MB:
            raise ValueError("We currently can't handle anything but ethernet")

        if version != "2.4":
            # We currently may not be able to handle any file that isn't
            # version 2.4. If you have another version, send it to me.
            sys.stderr.write("Warning: This file is not version 2.4")

        keep_parsing = True
        while keep_parsing:
            start_of_frame = f.read(4)
            if len(start_of_frame) == 0:
                keep_parsing = False
                continue
            elif len(start_of_frame) != 4:
                keep_parsing = False
                sys.stderr.write(
                    "Warning: We stopped parsing file at pos:{0}".format(
                        f.tell()))
                continue

            # The data about this header is actually missing. We don't
            # really understand this 16-byte header.
            sof = parse_bytes(start_of_frame, is_byte_swapped=byte_swap)

            # We have no idea why, because we don't understand this header.
            # But, this seems to be true.
            assert sof == [0x50, 0x2e, 0xcd, 0xd0]
            unknown = parse_bytes(f.read(4), is_byte_swapped=byte_swap)

            # We don't actually understand the difference between these
            # two sizes. They seem to have the value from the data we
            # reviewed. But, we don't know the specification.
            size1 = convert_to_number(parse_bytes(f.read(4),
                                      is_byte_swapped=byte_swap))
            size2 = convert_to_number(parse_bytes(f.read(4),
                                                  is_byte_swapped=byte_swap))

            packet = [ord(m) for m in f.read(size1)]
            if len(packet) != size1:
                keep_parsing = False

            if linked_layer_type == DLT_EN10MB:
                results.append(Ethernet(packet))

    return results
