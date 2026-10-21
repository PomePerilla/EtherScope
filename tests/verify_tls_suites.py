"""Crosscheck every supported AEAD suite using independent socket TLS endpoints."""
import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading

sys.dont_write_bytecode = True
from tls_capture import write_capture

REQUEST = b'GET /suite HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'
RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc'
SUITES = ['AES128-GCM-SHA256', 'AES256-GCM-SHA384',
          'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-GCM-SHA384',
          'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-GCM-SHA384',
          'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',
          'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-CHACHA20-POLY1305',
          'DHE-RSA-CHACHA20-POLY1305', 'TLS_AES_128_GCM_SHA256',
          'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']


def run_case(suite, args):
    modern = suite.startswith('TLS_')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3 if modern else ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['http/1.1'])
    certificates = Path(__file__).resolve().parent.parent / '.tools/dependencies/openssl-3.5.9/test/certs'
    cert, key = ('p256-server-cert.pem', 'p256-server-key.pem') if 'ECDSA' in suite else ('servercert.pem', 'serverkey.pem')
    context.load_cert_chain(certificates / cert, certificates / key)
    context.load_dh_params(str(certificates / 'dhp2048.pem'))
    if not modern:
        context.set_ciphers(suite)
    flights, errors, negotiated = [], [], []

    def listen():
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(10)
        return listener

    server, proxy = listen(), listen()

    def serve():
        try:
            with server.accept()[0] as raw, context.wrap_socket(raw, server_side=True) as connection:
                connection.settimeout(10)
                negotiated.append(connection.cipher()[0])
                request = b''
                while b'\r\n\r\n' not in request:
                    part = connection.recv(4096)
                    if not part:
                        raise EOFError('Request ended early')
                    request += part
                assert request == REQUEST
                connection.sendall(RESPONSE)
                connection.unwrap().close()
        except Exception as error:
            errors.append(str(error))

    def forward(source, target, direction):
        try:
            while True:
                content = source.recv(16384)
                if not content:
                    break
                flights.append((direction, content))
                target.sendall(content)
        except OSError:
            pass
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def relay():
        try:
            with proxy.accept()[0] as client, socket.create_connection(server.getsockname(), timeout=10) as peer:
                client.settimeout(10)
                reverse = threading.Thread(target=forward, args=(peer, client, 1), daemon=True)
                reverse.start()
                forward(client, peer, 0)
                reverse.join(10)
        except Exception as error:
            errors.append(str(error))

    workers = [threading.Thread(target=serve, daemon=True), threading.Thread(target=relay, daemon=True)]
    for worker in workers:
        worker.start()
    keylog = args.output / (suite + '.keys')
    command = [str(args.openssl), 's_client', '-quiet', '-ign_eof', '-connect',
               '127.0.0.1:' + str(proxy.getsockname()[1]), '-servername', 'example.com',
               '-alpn', 'http/1.1', '-keylogfile', str(keylog),
               '-tls1_3' if modern else '-tls1_2', '-ciphersuites' if modern else '-cipher', suite]
    try:
        client = subprocess.run(command, input=REQUEST, capture_output=True, timeout=15)
    finally:
        for worker in workers:
            worker.join(12)
        server.close()
        proxy.close()
    assert not errors and not any(worker.is_alive() for worker in workers), (suite, errors)
    assert client.returncode == 0 and client.stdout == RESPONSE, (suite, client.stderr)
    assert negotiated == [suite], (suite, negotiated)
    capture = args.output / (suite + '.pcap')
    records = write_capture(capture, flights)
    analysis = subprocess.check_output([str(args.inspector), str(capture), str(keylog), '--plaintext'], text=True, encoding='utf-8')
    plaintext = ['', '']
    for line in analysis.splitlines():
        fields = line.split('\t')
        if fields[0] == 'plaintext':
            plaintext[int(fields[1])] += fields[2]
        elif fields[0] == 'status':
            assert fields[1] == '1', (suite, line)
    assert plaintext == [REQUEST.hex(), RESPONSE.hex()], suite
    incremental = subprocess.check_output([str(args.inspector), str(capture), str(keylog),
                                          '--plaintext', '--incremental'], text=True, encoding='utf-8')
    assert sorted(incremental.splitlines()) == sorted(analysis.splitlines()), suite
    if args.tshark:
        reference = subprocess.check_output([str(args.tshark), '-n', '-r', str(capture), '-o',
                                             'tls.keylog_file:' + str(keylog), '-T', 'fields',
                                             '-e', 'http.host', '-e', 'http.response.code'], text=True, encoding='utf-8')
        assert 'example.com' in reference and '200' in reference, (suite, reference)
    return {'suite': suite, 'records': records, 'exact_plaintext': True, 'incremental_equal': True, 'tshark': bool(args.tshark)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--openssl', type=Path, required=True)
    parser.add_argument('--inspector', type=Path, required=True)
    parser.add_argument('--tshark', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    options.output = options.output.resolve()
    options.output.mkdir(parents=True, exist_ok=True)
    report = []
    for name in SUITES:
        report.append(run_case(name, options))
        print('PASS:', name, flush=True)
    (options.output / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
