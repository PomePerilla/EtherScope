"""Compare project-decoded fields to an independent tshark executable; no live capture."""
import argparse
import csv
import io
import ipaddress
import json
import re
import subprocess
from pathlib import Path

FIELDS = [
    'frame.number', 'frame.len', 'frame.cap_len', 'eth.src', 'eth.dst', 'eth.type', 'vlan.id',
    'ip.version', 'ip.hdr_len', 'ip.dscp', 'ip.ecn', 'ip.len', 'ip.id', 'ip.flags',
    'ip.frag_offset', 'ip.ttl', 'ip.proto', 'ip.checksum', 'ip.src', 'ip.dst',
    'icmp.type', 'icmp.code', 'icmp.checksum', 'icmp.ident', 'icmp.seq',
    'arp.opcode', 'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.hw_mac', 'arp.dst.proto_ipv4',
    'tcp.srcport', 'tcp.dstport', 'tcp.seq_raw', 'tcp.ack_raw', 'tcp.hdr_len',
    'tcp.flags', 'tcp.window', 'tcp.checksum', 'tcp.urgent',
    'udp.srcport', 'udp.dstport', 'udp.length', 'udp.checksum',
    'ipv6.version', 'ipv6.tclass', 'ipv6.tclass.dscp', 'ipv6.tclass.ecn', 'ipv6.flow', 'ipv6.plen',
    'ipv6.nxt', 'ipv6.hlim', 'ipv6.src', 'ipv6.dst', 'icmpv6.type', 'icmpv6.code', 'icmpv6.checksum',
    'icmpv6.echo.identifier', 'icmpv6.echo.sequence_number', 'icmpv6.nd.ns.target_address',
    'icmpv6.nd.na.target_address', 'icmpv6.mtu', 'ipv6.fraghdr.nxt', 'ipv6.fraghdr.offset',
    'ipv6.fraghdr.more', 'ipv6.fraghdr.ident', 'ah.spi', 'ah.sequence',
    'ip.checksum.status', 'icmp.checksum.status', 'ip.opt.type', 'ip.opt.len', 'ip.opt.ptr',
    'ip.rec_rt', 'ip.opt.flag', 'ip.opt.overflow', 'ip.opt.time_stamp', 'ip.opt.time_stamp_addr',
]
ALIASES = {'ip.dscp': 'ip.dsfield.dscp', 'ip.ecn': 'ip.dsfield.ecn', 'tcp.window': 'tcp.window_size_value', 'tcp.urgent': 'tcp.urgent_pointer'}


def numeric(value):
    match = re.match(r'(?:0x[0-9a-fA-F]+|\d+)', value)
    if not match:
        raise ValueError(f'No numeric prefix in {value!r}')
    token = match[0]
    return int(token, 16 if token.startswith('0x') else 10)


def normalized(field, value, project=False):
    value = value.strip()
    if field in ('ipv6.src', 'ipv6.dst', 'icmpv6.nd.ns.target_address', 'icmpv6.nd.na.target_address'):
        return ipaddress.IPv6Address(value)
    if field == 'ipv6.fraghdr.more' and value.lower() in ('true', 'false'):
        return int(value.lower() == 'true')
    if field in ('eth.src', 'eth.dst', 'ip.src', 'ip.dst', 'ip.rec_rt', 'ip.opt.time_stamp_addr') or '.hw_mac' in field or '.proto_ipv4' in field:
        return value.lower()
    if project and field == 'ip.flags':
        values = re.search(r'保留=(\d) DF=(\d) MF=(\d)', value)
        return (int(values[1]) << 2) | (int(values[2]) << 1) | int(values[3])
    return numeric(value)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--tshark', required=True)
    p.add_argument('--inspector', default='build/msvc-release/inspect_pcap.exe')
    p.add_argument('--pcap', default='samples/synthetic-protocols.pcap')
    p.add_argument('--output', default='output/evidence/wireshark-comparison.json')
    p.add_argument('--capture-kind', choices=('synthetic', 'live'), default='synthetic')
    args = p.parse_args()
    ours = subprocess.check_output([args.inspector, args.pcap], encoding='utf-8')
    # Match this analyzer's per-packet semantics instead of TShark's default fragment reassembly.
    command = [args.tshark, '-n', '-r', args.pcap, '-o', 'ipv6.defragment:FALSE', '-o', 'ip.defragment:FALSE', '-o', 'ip.check_checksum:TRUE',
               '-T', 'fields', '-E', 'header=y', '-E', 'separator=/t', '-E', 'occurrence=f']
    for name in FIELDS:
        command += ['-e', ALIASES.get(name, name)]
    reference = subprocess.check_output(command, encoding='utf-8')
    own_rows = list(csv.DictReader(io.StringIO(ours), delimiter='\t'))
    ref_rows = list(csv.DictReader(io.StringIO(reference), delimiter='\t'))
    mismatches = []
    compared = 0
    if len(own_rows) != len(ref_rows):
        mismatches.append({'record_count': [len(own_rows), len(ref_rows)]})
    for number, (own, ref) in enumerate(zip(own_rows, ref_rows), 1):
        for name in FIELDS:
            if not own[name]:
                continue  # Deliberately unsupported/truncated structures are not compared as decoded fields.
            a, b = own[name], ref.get(ALIASES.get(name, name), '')
            compared += 1
            if not b or normalized(name, a, True) != normalized(name, b):
                mismatches.append({'packet': number, 'field': name, 'project': a, 'tshark': b})
    version = subprocess.check_output([args.tshark, '--version'], encoding='utf-8').splitlines()[0]
    report = {'kind': args.capture_kind + '_pcap_independent_field_comparison', 'reference': version,
              'records': len(own_rows), 'compared_field_values': compared, 'reference_ip_reassembly': False,
              'passed': not mismatches, 'mismatches': mismatches,
              'limits': 'Only decoded fields are compared; capture source is ' + args.capture_kind +
                        '. Field comparison alone does not validate driver performance or another machine.'}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
