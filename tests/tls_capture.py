"""Wrap exact TLS endpoint bytes in deterministic Ethernet/TCP test records."""
import struct


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return value ^ 65535


def write_capture(path, flights):
    packets = []
    sequence = [100, 500]

    def packet(side, payload, flags=0x18):
        source, destination = (b'\xc0\x00\x02\x01', b'\xc0\x00\x02\x02')
        if side:
            source, destination = destination, source
        tcp = struct.pack('!HHIIBBHHH', 443 if side else 50000, 50000 if side else 443,
                          sequence[side], sequence[1 - side], 0x50, flags, 65535, 0, 0) + payload
        pseudo = source + destination + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(tcp) + 20, len(packets), 0, 64, 6, 0, source, destination)
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
        packets.append(bytes.fromhex('0200000000020200000000010800') + ip + tcp)
        sequence[side] += len(payload) + bool(flags & 3)

    packet(0, b'', 2)
    packet(1, b'', 18)
    packet(0, b'', 16)
    for side, flight in flights:
        # Split TLS records over arbitrary TCP boundaries, retaining exact bytes.
        for offset in range(0, len(flight), 317):
            packet(side, flight[offset:offset + 317])
    packet(0, b'', 17)
    packet(1, b'', 17)
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
        for index, data in enumerate(packets):
            stream.write(struct.pack('<IIII', 1700000000, index * 1000000, len(data), len(data)))
            stream.write(data)
    return len(packets)


