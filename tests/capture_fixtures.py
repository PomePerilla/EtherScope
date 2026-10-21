"""Independent PCAPNG fixtures shared by interoperability and fuzz checks."""
from pathlib import Path
import struct


def block(kind, body, endian):
    body += bytes(-len(body) % 4)
    length = len(body) + 12
    return struct.pack(endian + 'II', kind, length) + body + struct.pack(endian + 'I', length)


def section(endian):
    return block(0x0A0D0D0A, struct.pack(endian + 'IHHq', 0x1A2B3C4D, 1, 0, -1), endian)


def interface(endian, link, resolution, offset):
    return block(1, struct.pack(endian + 'HHIHHB3xHHq', link, 0, 65535, 9, 1,
                                resolution, 14, 8, offset), endian)


def enhanced(endian, index, ticks, content):
    return block(6, struct.pack(endian + 'IIIII', index, ticks >> 32, ticks & 0xFFFFFFFF,
                               len(content), len(content)) + content, endian)


def packet_bytes():
    sample = (Path(__file__).resolve().parent.parent / 'samples/synthetic-protocols.pcap').read_bytes()
    length = struct.unpack_from('<I', sample, 32)[0]
    return sample[40:40 + length]


def captures():
    ethernet = packet_bytes()
    raw_ip = ethernet[14:]
    simple = block(3, struct.pack('<I', len(ethernet)) + ethernet, '<')
    sections = (section('<') + interface('<', 1, 9, 2) + interface('<', 101, 0x8A, -2) +
                enhanced('<', 0, 1234567891, ethernet) + block(0xBEEF, bytes(256), '<') +
                enhanced('<', 1, 2560, raw_ip) + simple +
                section('>') + interface('>', 1, 6, 0) + enhanced('>', 0, 1234567, ethernet))
    old = block(2, struct.pack('>HHIIII', 0, 0, 0, 1234567, len(ethernet), len(ethernet)) + ethernet, '>')
    return {'sections.pcapng': sections,
            'untimed.pcapng': section('<') + interface('<', 1, 6, 0) + simple,
            'legacy-block.pcapng': section('>') + interface('>', 1, 6, 0) + old,
            'truncated.pcapng': sections[:-1]}


if __name__ == '__main__':
    import sys
    target = Path(sys.argv[1])
    target.mkdir(parents=True, exist_ok=True)
    for name, data in captures().items():
        (target / name).write_bytes(data)
