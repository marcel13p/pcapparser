import struct


ECAT_DATAGRAM_HEADER_LENGTH = 10
ENET_HEADER_LENGTH = 14
ECAT_HEADER_LENGTH = 2
ETHERCAT = 0x88a4


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
        return self.raw_datagram[ECAT_DATAGRAM_HEADER_LENGTH:ECAT_DATAGRAM_HEADER_LENGTH + self.length]
    
    cmd = property(_get_cmd)
    idx = property(_get_idx)
    address = property(_get_address)
    wkc = property(_get_wkc)
    log_addr = property(_get_logaddr)
    ado = property(_get_ado)
    adp = property(_get_adp)
    data = property(_get_data)

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
        return ethertype if ethertype >= 0x600 else None # NOTE: Ethertype is only defined for Ethernet II and should be >= 0x600
        
    def _get_datagrams(self) -> list[EcatDatagram]:
        pointer = ENET_HEADER_LENGTH + ECAT_HEADER_LENGTH
        length = self.packet_length
        datagrams = []
        while pointer + ECAT_DATAGRAM_HEADER_LENGTH <= length:
            data_length = struct.unpack("<H", self.raw_data[pointer+6:pointer+8])[0] & 0x7FF
            pointer += ECAT_DATAGRAM_HEADER_LENGTH + data_length + 2
            datagrams.append(EcatDatagram(self.raw_data[pointer - data_length - ECAT_DATAGRAM_HEADER_LENGTH - 2:pointer], data_length))
        return datagrams
    
    ethertype = property(_get_ethertype)
    datagrams: list[EcatDatagram] = property(_get_datagrams)
        
    def __str__(self):
        return f"Packet(packet_number: {self.packet_number}, packet_length: {self.packet_length}, timestamp: {self.timestamp}, raw_data: {' '.join([f'{b:02x}' for b in self.raw_data])})"


class PcapParser:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(self.filename, "rb")
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
                timestamp = struct.unpack("<Q", timestamp_low+timestamp_high)[0]
                captured_len, _ = struct.unpack("<II", self.file.read(8))
                raw_data = self.file.read(captured_len)
                padding = (4 - captured_len % 4) % 4
                self.file.seek(padding + 4, 1) # Skip the trailing packetlength bytes and padding
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
    pcapng_file = "desktest.pcapng"
    parser = PcapParser(pcapng_file)
    packet = parser.get_packet(14158)
    for datagram in packet.datagrams:
        print(dir(datagram))

if __name__ == "__main__":
    main()