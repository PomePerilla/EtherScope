"""Compare section, interface, timestamp and byte preservation with fixed records."""
import argparse
from decimal import Decimal
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
from capture_fixtures import captures, packet_bytes


def inspect(executable, capture, output=None):
    args = [str(executable), str(capture)] + ([str(output)] if output else [])
    rows = subprocess.check_output(args, text=True, encoding='utf-8').splitlines()
    return [[int(value) for value in row.split('\t')[:4]] + [row.split('\t')[4]] for row in rows]


parser = argparse.ArgumentParser()
parser.add_argument('inspector', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--tshark', type=Path)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
ethernet = packet_bytes()
raw_ip = ethernet[14:]
data = captures()['sections.pcapng']
capture = args.output / 'sections.pcapng'
converted = args.output / 'exported.pcapng'
capture.write_bytes(data)
expected = [[0, 1, 1, 3234567891, ethernet.hex()], [1, 101, 1, 500000000, raw_ip.hex()],
            [0, 1, 0, 0, ethernet.hex()], [2, 1, 1, 1234567000, ethernet.hex()]]
assert inspect(args.inspector, capture, converted) == expected
assert inspect(args.inspector, converted) == expected
if args.tshark:
    for path in (capture, converted):
        raw = subprocess.check_output([str(args.tshark), '-n', '-r', str(path), '-T', 'json', '-x'],
                                      text=True, encoding='utf-8')
        reference = json.loads(raw)
        assert len(reference) == len(expected)
        timestamps = subprocess.check_output([str(args.tshark), '-n', '-r', str(path), '-T',
                                               'fields', '-e', 'frame.time_epoch'],
                                              text=True, encoding='utf-8').splitlines()
        for item, wanted, timestamp in zip(reference, expected, timestamps):
            layers = item['_source']['layers']
            assert layers['frame_raw'][0] == wanted[4]
            if wanted[2]:
                nanos = int(Decimal(timestamp) * 1_000_000_000)
                assert nanos == wanted[3], (path, nanos, wanted[3])
        (args.output / (path.stem + '.tshark.json')).write_text(raw, encoding='utf-8')
report = {'records': 4, 'sections': 2, 'interfaces': 3, 'timestamp_and_bytes': True,
          'export_roundtrip': True, 'tshark': bool(args.tshark)}
(args.output / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report))
