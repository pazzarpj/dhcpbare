from abc import abstractmethod

# DHCP constants
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8


class DHCPType:
    """
    A type used for encoding and decoding data to be using with DHCP Packet
    MSB of value translates to LSB in packet
    """
    length = None
    start_addr = None
    value = None

    def __init__(self, start_addr=None, length=None, value=None):
        if start_addr is not None:
            self.start_addr = start_addr
        if length is not None:
            self.length = length
        if value is not None:
            self.value = value

    def encode(self):
        self._ensure_adequate_data()
        return self._encode()

    @abstractmethod
    def _encode(self):
        """
        Override this method
        :return: bytearray of encoded data from length and value parameters on the object
        """

    def _ensure_adequate_data(self):
        if any((self.start_addr is None, self.length is None, self.value is None)):
            raise ValueError("Insufficient data in order to encode for {}".format(self.__class__.__name__))

    def decode(self, data):
        """
        Validates the decoded data against existing value set for the object and raises exceptions where they don't match
        and populates the value where the existing value is None
        :return:
        """
        value = self._decode(data)
        if self.value is None:
            self.value = value
        else:
            if self.value != value:
                try:
                    err_msg = "Invalid {} Decode error: Expecting 0x{:X}, Received 0x{:X}".format(
                        self.__class__.__name__, self.value, value)
                except:
                    err_msg = "Invalid {} Decode error: Expecting {}, Received {}".format(
                        self.__class__.__name__, self.value, value)
                raise IOError(err_msg)

    @abstractmethod
    def _decode(self, data):
        """
        Override this method
        If self.value is None then load the decoded data in self.value
        If self.value is not None then check that the decoded data matches self.value and raise an exception if not
        :return: decoded data
        """

    def __repr__(self):
        try:
            return "{}: 0x{:X}".format(self.__class__.__name__, self.value)
        except:
            return "{}: {}".format(self.__class__.__name__, self.value)


class Hex(DHCPType):
    """
    MSB of value translates to LSB in packet
    """

    def _encode(self):
        data = bytearray()
        value_shift = self.value
        while value_shift != 0:
            data.append(value_shift & 0xff)
            value_shift >>= 8
        data.extend(bytearray(self.length - len(data)))
        return data[::-1]

    def _decode(self, data):
        return int(data.hex(), 16)


class Str(DHCPType):
    """
    MSB of value translates to LSB in packet
    """

    def _encode(self):
        data = bytearray(self.value.encode('utf-8'))
        if len(data) > self.length:
            raise ValueError(
                "Invalid {} Encode error: Expecting Length {}, Received {}".format(
                    self.__class__.__name__, self.length, len(data)))
        data.extend(bytearray(self.length - len(data)))
        return data

    def _decode(self, data):
        return data.decode('utf-8')


class Ipv4(DHCPType):
    """
    MSB of value translates to LSB in packet
    """
    length = 4

    def _encode(self):
        data = bytearray(self.length)
        data[0:self.length + 1] = [int(x, 10) for x in self.value.split('.')]
        return data

    def _decode(self, data):
        return ".".join("{}".format(x) for x in data[0:self.length + 1])


class Mac(DHCPType):
    """
    MSB of value translates to LSB in packet
    """
    length = 6

    def _encode(self):
        data = bytearray(self.length)
        data[0:self.length + 1] = [int(x, 16) for x in self.value.split(':')]
        return data

    def _decode(self, data):
        return ":".join("{:X}".format(x) for x in data[:6])


class OptSubnet(Ipv4):
    start_addr = 1


class OptRouter(Ipv4):
    start_addr = 3


class OptDNS(Hex):
    start_addr = 6


class OptLogServer(Hex):
    start_addr = 7


class OptHostName(Str):
    start_addr = 12


class OptDomainName(Str):
    start_addr = 15


class OptBroadcastAddr(Ipv4):
    start_addr = 28


class OptNTPServers(Hex):
    start_addr = 42


class OptReqIpAddr(Ipv4):
    start_addr = 50


class OptIPAddrLease(Hex):
    start_addr = 51
    length = 4


class OptDHCPMessageType(Hex):
    start_addr = 53
    length = 1


class OptDHCPServerID(Ipv4):
    start_addr = 54


class OptParameterReqList(Hex):
    start_addr = 55


class OptMaxDHCPMsgSize(Hex):
    start_addr = 57
    length = 2


class OptRenewalTime(Hex):
    start_addr = 58
    length = 4


class OptRebindTime(Hex):
    start_addr = 59
    length = 4


class OptVendorClassID(Str):
    start_addr = 60


class OptClientID(Hex):
    start_addr = 61


class OptTFTPServerName(Str):
    start_addr = 66


DHCP_OPTIONS = {
    1: OptSubnet,
    3: OptRouter,
    6: OptDNS,
    7: OptLogServer,
    12: OptHostName,
    15: OptDomainName,
    28: OptBroadcastAddr,
    42: OptNTPServers,
    50: OptReqIpAddr,
    51: OptIPAddrLease,
    53: OptDHCPMessageType,
    54: OptDHCPServerID,
    55: OptParameterReqList,
    57: OptMaxDHCPMsgSize,
    58: OptRenewalTime,
    59: OptRebindTime,
    60: OptVendorClassID,
    61: OptClientID,
    66: OptTFTPServerName
}


class DHCPOptions:
    """
    Encodes and decodes options using the appropriate DHCPType as a data object
    A DHCP option should be passed the equivalent DHCPType, where
    start_addr is option number
    """

    def __init__(self):
        self.options = []

    def encode(self):
        data = bytearray()
        for opt in self.options:
            data.append(opt.start_addr)
            data.append(opt.length)
            data.extend(opt.encode())
        data.append(255)  # End Byte
        return data

    def decode(self, data):
        index = 0
        while index <= len(data):
            # Start option decode
            byt = data[index]
            if byt == 255:
                break  # End byte
            option = DHCP_OPTIONS[byt]()
            index += 1
            if option.length != data[index] and option.length is not None:
                raise IOError("Invalid {} Decode error: Expecting length {}, Received {}".format(
                    option.__class__.__name__, option.length, data[index]))
            option.length = data[index]
            index += 1
            option.decode(data[index:index + option.length])
            index += option.length
            self.options.append(option)

    def __repr__(self):
        return "{}".format(self.options)


class Op(Hex):
    start_addr = 0
    length = 1


class HType(Hex):
    start_addr = 1
    length = 1
    value = 0x01


class HLen(Hex):
    start_addr = 2
    length = 1
    value = 0x06


class Hops(Hex):
    start_addr = 3
    length = 1
    value = 0x00


class XID(Hex):
    start_addr = 4
    length = 4


class Secs(Hex):
    start_addr = 8
    length = 2


class Flags(Hex):
    start_addr = 10
    length = 2
    value = 0x0000


class CIAddr(Ipv4):
    start_addr = 12


class YIAddr(Ipv4):
    start_addr = 16


class SIAddr(Ipv4):
    start_addr = 20


class GIAddr(Ipv4):
    start_addr = 24


class CHAddr(Mac):
    start_addr = 28


class BootpLegacy(Hex):
    start_addr = 34
    length = 198
    value = 0x00


class MagicCookie(Hex):
    start_addr = 236
    length = 4
    value = 0x63825363


class DHCPPacket:
    options_start_addr = 240

    def __init__(self):
        self.frame = [Op(), HType(), HLen(), Hops(), XID(), Secs(), Flags(), CIAddr(), YIAddr(), SIAddr(), GIAddr(),
                      CHAddr(), BootpLegacy(), MagicCookie()]
        self._frame_lookup = {x.__class__.__name__: x for x in self.frame}
        self.options = DHCPOptions()
        self.payload_size = 0
        self.init()

    def init(self):
        """
        Optionally override this for initial conditions
        :return:
        """

    def encode(self):
        packet = bytearray(self.payload_size)
        for field in self.frame:
            packet[field.start_addr:field.start_addr + field.length] = field.encode()
        options = self.options.encode()
        packet[self.options_start_addr:self.options_start_addr + len(options)] = options
        return packet

    def decode(self, packet):
        """
        If this is called, it will validate against values that are stored in each of the parameters and will raise an
        Exception if they do not match
        If the value is None, it will instead store that value.
        :param packet:
        :return:
        """
        self.payload_size = len(packet)
        for field in self.frame:
            field.decode(packet[field.start_addr:field.start_addr + field.length])
        self.options.decode(packet[self.options_start_addr:])
        return self

    def __getattr__(self, item):
        try:
            return self._frame_lookup[item]
        except KeyError:
            raise AttributeError("'{}' object has no attribute {}".format(__class__.__name__, item))

    def __repr__(self):
        return "Frame: {} Options: {}".format(self.frame, self.options)


class DHCPDiscover(DHCPPacket):
    def init(self):
        self.payload_size = 300
        self.Op.value = 0x01
        self.HType.value = 0x01
        self.HLen.value = 0x06


class DHCPOffer(DHCPPacket):
    def init(self):
        self.payload_size = 296


if __name__ == "__main__":
    import packet_examples

    discover = DHCPPacket().decode(packet_examples.discover_packet)
    assert (discover.encode() == packet_examples.discover_packet)
    offer = DHCPPacket().decode(packet_examples.offer_packet)
    assert (offer.encode() == packet_examples.offer_packet)
    request = DHCPPacket().decode(packet_examples.request_packet)
    assert (request.encode() == packet_examples.request_packet)
    ack = DHCPPacket().decode(packet_examples.ack_packet)
    assert (ack.encode() == packet_examples.ack_packet)
