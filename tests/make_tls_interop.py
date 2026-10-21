"""Create offline captures from Python/OpenSSL TLS endpoints, without network I/O."""
import argparse
import json
import pathlib
import ssl
import sys
sys.dont_write_bytecode = True
from tls_capture import write_capture

parser = argparse.ArgumentParser()
parser.add_argument('output', type=pathlib.Path)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parent.parent
certificates = root / '.tools/dependencies/openssl-3.5.9/test/certs'
args.output.mkdir(parents=True, exist_ok=True)
sessions = {}


def create(name, version, cipher=None, protocol='http/1.1', resume=False):
    keylog = args.output / (name + '.keys')
    previous = sessions.get((version, cipher, protocol)) if resume else None
    if previous:
        client_context, server_context, session = previous
    else:
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certificates / 'p256-server-cert.pem', certificates / 'p256-server-key.pem')
        session = None
    for context in (client_context, server_context):
        context.minimum_version = context.maximum_version = version
        context.set_alpn_protocols([protocol])
        if cipher:
            context.set_ciphers(cipher)
    client_context.keylog_filename = str(keylog)
    incoming = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    outgoing = [ssl.MemoryBIO(), ssl.MemoryBIO()]
    endpoints = [client_context.wrap_bio(incoming[0], outgoing[0], server_hostname='example.com', session=session),
                 server_context.wrap_bio(incoming[1], outgoing[1], server_side=True)]
    flights = []

    def transfer():
        for side in (0, 1):
            data = outgoing[side].read()
            if data:
                flights.append((side, data))
                incoming[1 - side].write(data)

    done = [False, False]
    for _ in range(100):
        for side in (0, 1):
            if done[side]:
                continue
            try:
                endpoints[side].do_handshake()
                done[side] = True
            except ssl.SSLWantReadError:
                pass
        transfer()
        if all(done):
            break
    assert all(done)
    if protocol == 'h2':
        settings = bytes.fromhex('000000040000000000')
        headers = bytes.fromhex('828684410f7777772e6578616d706c652e636f6d')
        request = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + settings + len(headers).to_bytes(3, 'big') + bytes.fromhex('010500000001') + headers
        response = settings + bytes.fromhex('00000101050000000188')
    else:
        request = b'GET /index HTTP/1.1\r\nHost: example.com\r\n\r\n'
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc'
    endpoints[0].write(request)
    transfer()
    assert endpoints[1].read() == request
    endpoints[1].write(response)
    transfer()
    assert endpoints[0].read() == response
    sessions[(version, cipher, protocol)] = (client_context, server_context, endpoints[0].session)
    if resume:
        assert endpoints[0].session_reused
    path = args.output / (name + '.pcap')
    count = write_capture(path, flights)
    return {'name': name, 'capture': str(path), 'keylog': str(keylog), 'packets': count,
            'cipher': endpoints[0].cipher(), 'alpn': endpoints[0].selected_alpn_protocol(),
            'expected_request': request.hex(), 'expected_response': response.hex(), 'resumed': endpoints[0].session_reused}


cases = [create('tls12-aes128', ssl.TLSVersion.TLSv1_2, 'ECDHE-ECDSA-AES128-GCM-SHA256'),
         create('tls12-aes256', ssl.TLSVersion.TLSv1_2, 'ECDHE-ECDSA-AES256-GCM-SHA384'),
         create('tls12-chacha', ssl.TLSVersion.TLSv1_2, 'ECDHE-ECDSA-CHACHA20-POLY1305'),
         create('tls13-http1', ssl.TLSVersion.TLSv1_3),
         create('tls13-http2', ssl.TLSVersion.TLSv1_3, protocol='h2'),
         create('tls13-resumed', ssl.TLSVersion.TLSv1_3, resume=True)]
(args.output / 'manifest.json').write_text(json.dumps({'backend': ssl.OPENSSL_VERSION, 'cases': cases}, indent=2))
print(f'{len(cases)} independent TLS endpoint cases')
