from ftp_c import stream

TYPE_IPv4 = 0x0800
TYPE_TCP = 0x0600

types = {
    TYPE_IPv4: 'IP Version 4',
    TYPE_TCP: 'TCP',
}


def make_hex(address):
    #return "".join([hex(x).replace('0x', '',1) for x in address])
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


CONTROL_PORT = 21
PORTS = [20, 21, 58129, 58130, 68128]
results = []
for s in stream:
    packet = Ethernet(s)
    if packet.contents is not None:
        results.append(packet)
        ip = packet.contents
        tcp = ip.contents
        if tcp.source_port in PORTS or tcp.destination_port in PORTS:
            if tcp.source_port != CONTROL_PORT and tcp.destination_port != CONTROL_PORT:
                print "="*40, "====>",
            print tcp.timestamp_TSval, tcp.source_address_and_port, "->", tcp.destination_address_and_port, tcp.flags, tcp.contents
            #print tcp.sequence_number, tcp.source_address_and_port, "->", tcp.destination_address_and_port, tcp.flags, tcp.contents

