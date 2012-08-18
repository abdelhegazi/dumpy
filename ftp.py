#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Demonstration of network parsing tool

This is for lab exercise 03 - ftp
"""

import os
from optparse import OptionParser
import sys

from parse_tcpdump import parse_file

parser = OptionParser()
parser.add_option("-f", "--file", dest="filename",
                  help="input file to read", metavar="FILE")


def process_file():
    results = parse_file(options.filename)

    for line in [(r.source, r.destination, r.contents) for r in results]:
        print line


if __name__ == "__main__":
    (options, args) = parser.parse_args()

    if not options.filename:
        sys.stderr.write("usage: \n")
        sys.stderr.write("tcpdump <options> -w <dumpfilename>\n")
        sys.stderr.write("./ftp.py --file=<dumpfilename>\n")
        sys.exit(1)


    if os.path.exists(options.filename):
        process_file()
    else:
        sys.stderr.write("File does not exist\n")
        sys.exit(1)
