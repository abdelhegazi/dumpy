#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Represent raw network data as Python Objects

Although several tools exist to parse network data and let you manipulate that
data, no tool let's you easily programmatically review that data without
a deep knowledge of the Network protocols.

Instead, we represent that data as easily accessible objects. This will
never be the most performant tool. It should, however, be the easiest tool
to create a quick program for quick analysis of a dataset.
"""


TYPE_IPv4 = 0x0800
TYPE_TCP = 0x0600

types = {
    TYPE_IPv4: 'IP Version 4',
    TYPE_TCP: 'TCP',
}

# From different header files
ETHERTYPE = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_PPPOE_SESSION = 0x8864

DLT_NULL = 0         # no link-layer encapsulation
DLT_EN10MB = 1       # Ethernet (10Mb)
DLT_EN3MB = 2        # Experimental Ethernet (3Mb)
DLT_AX25 = 3         # Amateur Radio AX.25
DLT_PRONET = 4       # Proteon ProNET Token Ring
DLT_CHAOS = 5        # Chaos
DLT_IEEE802 = 6      # IEEE 802 Networks
DLT_ARCNET = 7       # ARCNET
DLT_SLIP = 8         # Serial Line IP
DLT_PPP = 9          # Point-to-point Protocol
DLT_FDDI = 10        # FDDI
DLT_ATM_RFC1483 = 11 # LLC/SNAP encapsulated atm
DLT_RAW = 12         # raw IP
DLT_SLIP_BSDOS = 15  # BSD/OS Serial Line IP
DLT_PPP_BSDOS = 16   # BSD/OS Point-to-point Protocol
DLT_ATM_CLIP = 19    # Linux Classical-IP over ATM
DLT_PPP_SERIAL = 50  # PPP over serial with HDLC encapsulation
DLT_C_HDLC = 104     # Cisco HDLC
DLT_IEEE802_11 = 105 # IEEE 802.11 wireless
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_APPLE_IP_OVER_IEEE1394 = 138
DLT_CHDLC = DLT_C_HDLC


def make_hex(address):
    return "".join(["{0:0>2x}".format(n) for n in address])

def make_hex_long(address):
    return int(make_hex(address), 16)

class Ethernet(object):
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.destination  = self._hex(self.raw_data[:6])
        self.source = self._hex(self.raw_data[6:12])
        self.contents = None
        self.type = make_hex_long(self.raw_data[12:14])
        if self.type == TYPE_IPv4:
            self.contents = IPv4(self.raw_data[14:])

    def _hex(self, address):
        return ":".join([hex(x).replace('0x', '') for x in address])

    def __unicode__(self):
        return "{0} {1}->{2}".format(types(self.type),
                                     self.source, self.destination)


class IPv4(object):
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.version = raw_data[0]
        self.differentiated_services_field = raw_data[1]
        self.total_length = make_hex_long(raw_data[2:4])
        self.identification = make_hex_long(raw_data[4:6])
        self.flags = raw_data[6]
        self.fragment_offset = raw_data[7]
        self.time_to_live = raw_data[8]
        self.protocol = raw_data[9]
        self.header_checksum = make_hex_long(raw_data[10:12])
        self.source = raw_data[12:16]
        self.destination = raw_data[16:20]
        self.contents = TCP(raw_data[20:], ip_packet=self)

    def summary(self):
        print "Version:", self.version
        print "Differentiated_services: ", self.differentiated_services_field
        print "Total Length: ", self.total_length
        print "Identification: ", self.identification
        print "Flags: ", hex(self.flags)
        print "Fragment offset: ", self.fragment_offset
        print "Time to live: ", self.time_to_live
        print "Protocol: ", types[self.protocol]
        print "header_checksum: ", hex(self.header_checksum)
        print "source: ", self.source
        print "destination: ", self.destination
        print "contents: ", self.contents

    def get_dotted_address(self, octet):
        return ".".join([str(o) for o in octet])

    @property
    def source_address(self):
        return self.get_dotted_address(self.source)

    @property
    def destination_address(self):
        return self.get_dotted_address(self.destination)

    def __unicode__(self):
        return "{0}: {1}->{2}".format(self.version, self.source, self.destination)

class TCP(object):
    def __init__(self, raw_data, ip_packet=None):
        self._raw_data = raw_data
        self.ip_packet = ip_packet

        self.source_port = make_hex_long(raw_data[0:2])
        self.destination_port = make_hex_long(raw_data[2:4])
        self.sequence_number = make_hex_long(raw_data[4:8])
        self.acknowledgement_number = make_hex_long(raw_data[8:12])
        self.header_length = raw_data[12]
        self._flags = raw_data[13]
        self._window_size = make_hex_long(raw_data[14:16])
        self._checksum = make_hex_long(raw_data[16:18])
        self._options_NOP1 = raw_data[20]
        self._options_NOP2 = raw_data[21]
        self.timestamp_TSval = make_hex_long(raw_data[22:27])
        self.timestamp_TSecr = make_hex_long(raw_data[27:32])
        self.contents = "".join([chr(c) for c in raw_data[32:]])

    def summary(self):
        print self.__unicode__()
        #print "Source port: ", self.source_port
        #print "Destination port: ", self.destination_port
        #print "sequence number: ", self.sequence_number
        #print "ack number: ", self.acknowledgement_number
        #print "header_length: ", hex(self.header_length)
        #print "flags: ", hex(self.flags)
        #print "window_size: ", self.window_size
        #print "checksum: ", self.checksum
        #print "options NOP1: ", hex(self.options_NOP1)
        #print "options NOP2: ", hex(self.options_NOP2)
        #print "timestamp_TSval: ", self.timestamp_TSval
        #print "timestamp_TSecr: ", self.timestamp_TSecr
        #print "contents: ", self.contents

    @property
    def source_address_and_port(self):
        if self.ip_packet is not None:
            return "{0}:{1}".format(self.ip_packet.source_address,
                                    self.source_port)
    @property
    def destination_address_and_port(self):
        if self.ip_packet is not None:
            return "{0}:{1}".format(self.ip_packet.destination_address,
                                    self.destination_port)

    @property
    def flags(self):
        results = []
        possible_flags = {
            0x80: 'CWR',  # Congestion Window Reduced (CWR)
            0x40: 'ECN',  # ECN-Echo
            0x20: 'URG',  # Urgent
            0x10: 'ACK',  # Acknowledgement
            0x08: 'PSH',  # Push
            0x04: 'RES',  # Reset
            0x02: 'SYN',  # SYN
            0x01: 'FIN'   # FIN
        }
        for flag in possible_flags:
            if flag & self._flags:
                results.append(possible_flags[flag])
        return '[{0}]'.format(",".join(results))

    def __unicode__(self):
        return "{0}".format(1)

