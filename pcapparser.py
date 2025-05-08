import struct


ECAT_DATAGRAM_HEADER_LENGTH = 10
ENET_HEADER_LENGTH = 14
ECAT_HEADER_LENGTH = 2


class EcatDatagram:
    def __init__(self, cmd, idx, address, length, data, wkc):
        self.cmd = cmd
        self.idx = idx
        self.address = address
        self.length = length
        self.data = data
        self.wkc = wkc

    def __str__(self):
        return f"EcatDatagram(cmd: {self.cmd}, idx: {self.idx}, address: {self.address:08x}, length: {self.length}, data: {' '.join([f'{b:02x}' for b in self.data])}, wkc: {self.wkc})"

    def __repr__(self):
        return str(self)


class Packet:
    def __init__(self, number, timestamp, content_length, raw_data):
        self.packet_number = number
        self.timestamp = timestamp
        self.packet_length = content_length
        self.raw_data = raw_data
        
    def get_datagrams(self):
        pointer = ENET_HEADER_LENGTH + ECAT_HEADER_LENGTH
        length = self.packet_length
        datagrams = []
        while pointer + ECAT_DATAGRAM_HEADER_LENGTH <= length:
            header = self.raw_data[pointer:pointer + ECAT_DATAGRAM_HEADER_LENGTH]
            cmd, idx, address, data_length, _ = struct.unpack("<BBIHH", header)
            data_length = data_length & 0x7FF
            pointer += ECAT_DATAGRAM_HEADER_LENGTH + data_length + 2
            wkc = struct.unpack("<H", self.raw_data[pointer-2:pointer])[0]
            datagrams.append(EcatDatagram(cmd, idx, address, data_length, self.raw_data[pointer - data_length - 2:pointer - 2], wkc))
        return datagrams
        
    def __str__(self):
        return f"Packet(packet_number: {self.packet_number}, packet_length: {self.packet_length}, timestamp: {self.timestamp}, raw_data: {' '.join([f'{b:02x}' for b in self.raw_data])})"


class PcapParser:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(self.filename, "rb")
        self.packet_counter = 0
        
    # def read_shb(self):
    #     block_header = self.file.read(8)  # Read 8 bytes (Block Type + Block Length)
    #     if len(block_header) < 8:
    #         raise ValueError("File too short to contain a valid pcapng header")

    #     block_type, block_length = struct.unpack("<II", block_header)
    #     if block_type != 0x0A0D0D0A:
    #         raise ValueError("Invalid pcapng file: Missing Section Header Block")

    #     self.file.seek(block_length - 8, 1) # Skip the rest of the SHB
                
    def get_next(self):
        while True:
            block_header = self.file.read(8)
            if len(block_header) < 8:
                # Reached end of file
                return None
            block_type, block_length = struct.unpack("<II", block_header)
            if block_type == 0x6:
                # Enhanced packet block, used to store packets                
                self.file.seek(4, 1)  # Skip Interface ID
                timestamp_high = self.file.read(4)
                timestamp_low = self.file.read(4)
                timestamp = struct.unpack("<Q", timestamp_low+timestamp_high)[0]
                captured_len, _ = struct.unpack("<II", self.file.read(8))
                raw_data = self.file.read(captured_len)
                padding = (4 - captured_len % 4) % 4
                self.file.seek(padding + 4, 1) # Skip the trailing length and padding
                self.packet_counter += 1
                return Packet(self.packet_counter, timestamp, captured_len, raw_data)
            else:
                self.file.seek(block_length - 8, 1)
                
    def get_packet(self, packet_number):
        packet = self.get_next()
        while packet.packet_number != packet_number:
            packet = self.get_next()
            if packet is None:
                return None
        return packet
        
    def close(self):
        """Close the file safely."""
        if self.file:
            self.file.close()
            self.file = None

    def __del__(self):
        """Ensure the file is closed when the object is deleted."""
        self.close()
        

def main():
    pcapng_file = "desktest.pcapng"
    parser = PcapParser(pcapng_file)
    packet = parser.get_packet(793)
    print(packet.get_datagrams())

if __name__ == "__main__":
    main()