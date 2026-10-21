import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
seeds = [
    b'\x00' + bytes.fromhex('123401000001000000000000076578616d706c6503636f6d0000010001'),
    b'\x01GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
    b'\x01HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc',
    b'\x02PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + bytes.fromhex('000000040000000000000003010500000001828684'),
    b'\x03' + bytes.fromhex('160303000401000000'),
    b'\x04tcp.port == 443 and not tls.sni contains "example"',
    b'\x04ip.addr in {192.0.2.0/24,198.51.100.1}',
]
for index, seed in enumerate(seeds):
    (destination / str(index)).write_bytes(seed)
