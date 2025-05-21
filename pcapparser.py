import struct


ECAT_DATAGRAM_HEADER_LENGTH = 10
ENET_HEADER_LENGTH = 14
ECAT_HEADER_LENGTH = 2
ECAT_COE_HEADER_LENGTH = 6
ETHERCAT = 0x88A4


class CoEData:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.header = raw_data[:6]
        self.length = struct.unpack("<H", raw_data[:2])[0]
        self.protocol_type = raw_data[5] & 0xF
        self.SDO_type = struct.unpack("<H", raw_data[6:8])[0]
        self.index = struct.unpack("<H", raw_data[9:11])[0]
        self.subindex = raw_data[11]

    def _get_address(self):
        return struct.unpack("<H", self.raw_data[2:4])[0]

    def _get_priority(self):
        return self.raw_data[4]

    def _get_counter(self):
        return self.raw_data[5] >> 4

    def _get_sdo_info(self):
        return self.raw_data[8]

    def _get_data(self):
        return struct.unpack("<I", self.raw_data[12:16])[0]
        # return self.raw_data[12:16]

    address = property(_get_address)
    priority = property(_get_priority)
    counter = property(_get_counter)
    sdo_info = property(_get_sdo_info)
    data = property(_get_data)

    def __str__(self):
        return f"CoEData(index: {hex(self.index)}, subindex: {self.subindex}, data: {self.data}, SDO type: {hex(self.SDO_type)}, protocol type: {self.protocol_type}, raw_data: {' '.join([f'{b:02x}' for b in self.raw_data])})"


class EcatDatagram:
    def __init__(self, raw_datagram, length):
        self.raw_datagram = raw_datagram
        self.length = length

    def _get_cmd(self):
        return self.raw_datagram[0]

    def _get_idx(self):
        return self.raw_datagram[1]

    def _get_address(self):
        return struct.unpack("<I", self.raw_datagram[2:6])[0]

    def _get_wkc(self):
        return struct.unpack("<H", self.raw_datagram[-2:])[0]

    def _get_logaddr(self):
        if not self.cmd in [10, 11, 12]:
            return None
        return self.address

    def _get_ado(self):
        if self.cmd in [0, 10, 11, 12]:
            return None
        return self.address >> 16

    def _get_adp(self):
        if self.cmd in [0, 10, 11, 12]:
            return None
        return self.address & 0xFFFF

    def _get_data(self):
        return self.raw_datagram[
            ECAT_DATAGRAM_HEADER_LENGTH : ECAT_DATAGRAM_HEADER_LENGTH + self.length
        ]

    def _get_coe_data(self) -> CoEData | None:
        if (
            self.cmd in [4, 5, 6] and self.length >= 16 and self.ado >= 0x1000
        ):  # CoE commands have at least a 6 byte header and 10 bytes of data and the ado is >= 0x1000
            return CoEData(
                self.raw_datagram[
                    ECAT_DATAGRAM_HEADER_LENGTH : ECAT_DATAGRAM_HEADER_LENGTH
                    + self.length
                ]
            )
        return None

    cmd = property(_get_cmd)
    idx = property(_get_idx)
    address = property(_get_address)
    wkc = property(_get_wkc)
    log_addr = property(_get_logaddr)
    ado = property(_get_ado)
    adp = property(_get_adp)
    data = property(_get_data)
    coe_data: CoEData | None = property(_get_coe_data)

    def __str__(self):
        return f"EcatDatagram(cmd: {self.cmd}, idx: {self.idx}, address: {self.address:08x}, length: {self.length}, raw_datagram: {' '.join([f'{b:02x}' for b in self.raw_datagram])}, wkc: {self.wkc})"

    def __repr__(self):
        return str(self)


class Packet:
    def __init__(self, number, timestamp, content_length, raw_data):
        self.packet_number = number
        self.timestamp = timestamp
        self.packet_length = content_length
        self.raw_data = raw_data

    def _get_ethertype(self):
        ethertype = struct.unpack(">H", self.raw_data[12:14])[0]
        return (
            ethertype if ethertype >= 0x600 else None
        )  # NOTE: Ethertype is only defined for Ethernet II and should be >= 0x600

    def _get_datagrams(self) -> list[EcatDatagram]:
        pointer = ENET_HEADER_LENGTH + ECAT_HEADER_LENGTH
        length = self.packet_length
        datagrams = []
        while pointer + ECAT_DATAGRAM_HEADER_LENGTH <= length:
            data_length = (
                struct.unpack("<H", self.raw_data[pointer + 6 : pointer + 8])[0] & 0x7FF
            )
            pointer += ECAT_DATAGRAM_HEADER_LENGTH + data_length + 2
            datagrams.append(
                EcatDatagram(
                    self.raw_data[
                        pointer
                        - data_length
                        - ECAT_DATAGRAM_HEADER_LENGTH
                        - 2 : pointer
                    ],
                    data_length,
                )
            )
        return datagrams

    ethertype = property(_get_ethertype)
    datagrams: list[EcatDatagram] = property(_get_datagrams)

    def __str__(self):
        return f"Packet(packet_number: {self.packet_number}, packet_length: {self.packet_length}, timestamp: {self.timestamp}, raw_data: {' '.join([f'{b:02x}' for b in self.raw_data])})"


class PcapParser:
    def __init__(self, filename):
        self.filename = filename
        try:
            self.file = open(self.filename, "rb")
        except FileNotFoundError:
            self.file = None
        self.packet_counter = 0

    def _get_next(self):
        while True:
            block_header = self.file.read(8)

            # Reached end of file
            if len(block_header) < 8:
                return None
            block_type, block_length = struct.unpack("<II", block_header)

            # Enhanced packet block, used to store packets
            if block_type == 0x6:
                self.file.seek(4, 1)  # Skip Interface ID
                timestamp_high = self.file.read(4)
                timestamp_low = self.file.read(4)
                timestamp = struct.unpack("<Q", timestamp_low + timestamp_high)[0]
                captured_len, _ = struct.unpack("<II", self.file.read(8))
                raw_data = self.file.read(captured_len)
                padding = (4 - captured_len % 4) % 4
                self.file.seek(
                    padding + 4, 1
                )  # Skip the trailing packetlength bytes and padding
                self.packet_counter += 1
                return Packet(self.packet_counter, timestamp, captured_len, raw_data)
            else:
                self.file.seek(block_length - 8, 1)

    def get_packet(self, packet_number):
        packet = self._get_next()
        while packet.packet_number != packet_number:
            packet = self._get_next()
            if packet is None:
                return None
        return packet

    def close(self):
        """Close the file safely."""
        if self.file:
            self.file.close()
            self.file = None

    def __iter__(self):
        return self

    def __next__(self):
        packet = self._get_next()
        if packet is None:
            raise StopIteration
        return packet

    def __del__(self):
        """Ensure the file is closed when the object is deleted."""
        self.close()


def main():
    # Example usage
    pcapng_file = "path/to/your/pcapng"
    parser = PcapParser(pcapng_file)
    with open("path/to/output/file", 'w') as file:
        for packet in parser:
            if packet.ethertype == ETHERCAT:
                for datagram in packet.datagrams:
                    coe_data = datagram.coe_data
                    if coe_data and coe_data.sdo_info & 0xF0 == 0x20:  # Get SDO upload requests and responses
                        file.write(
                            f"{packet.packet_number},{datagram.adp},{coe_data.index:04x},{coe_data.subindex},{coe_data.data},{hex(coe_data.data)},{hex(coe_data.sdo_info)}\n"
                        )


if __name__ == "__main__":
    main()
