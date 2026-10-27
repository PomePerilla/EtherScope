"""Exercise the native UI against a controlled local HTTP flow using bundled Qt libraries."""
from pathlib import Path
import argparse
import http.client
import http.server
import json
import os
import shutil
import subprocess
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve(); output.mkdir(parents=True, exist_ok=True)
    runtime = args.runtime_dir.resolve(strict=True)
    ready = output / 'http-ui-ready'; done = output / 'http-ui-done'
    for path in [ready, done]:
        if path.exists(): path.unlink()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def do_GET(self):
            body = b'EtherScope controlled loopback acceptance\n' * 256
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def log_message(self, *_): pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('QT_')}
    test_runtime = output / 'test-runtime'; test_runtime.mkdir(exist_ok=True)
    shutil.copy2(root / '.tools/Qt/bin/Qt6Test.dll', test_runtime / 'Qt6Test.dll')
    env['PATH'] = os.pathsep.join([str(test_runtime), str(runtime), str(Path(os.environ['WINDIR']) / 'System32'), os.environ['WINDIR']])
    env['QT_PLUGIN_PATH'] = str(runtime)
    env.update(ETHERSCOPE_HTTP_PORT=str(server.server_port), ETHERSCOPE_ACCEPTANCE_READY=str(ready),
               ETHERSCOPE_ACCEPTANCE_DONE=str(done), ETHERSCOPE_ACCEPTANCE_REPORT=str(output / 'native-http.json'),
               ETHERSCOPE_ACCEPTANCE_PCAPNG=str(output / 'controlled-loopback.pcapng'))
    startup = subprocess.STARTUPINFO(); startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW; startup.wShowWindow = 0
    log = (output / 'native-http-console.log').open('wb')
    process = subprocess.Popen([str(root / 'build/msvc-release/native_acceptance.exe'), '-platform', 'windows',
                                'realLoopbackCaptureAndAnalysis', '-o', os.path.relpath(output / 'native-http.xml', root) + ',junitxml'],
                               env=env, cwd=root, startupinfo=startup, stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline: time.sleep(.05)
        assert ready.exists(), 'Native capture did not become ready'
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
        try:
            for index in range(30):
                connection.request('GET', '/acceptance/' + str(index), headers={'Host': 'localhost'})
                response = connection.getresponse(); assert response.status == 200; response.read(); time.sleep(.04)
        finally: connection.close()
        done.write_text('30 requests completed', encoding='ascii')
        assert process.wait(timeout=40) == 0, 'Native UI acceptance failed'
        report = json.loads((output / 'native-http.json').read_text(encoding='utf-8'))
        assert report['passed']
        report.update(controlled_requests=30, ui_executable='native_acceptance.exe', runtime_directory=str(runtime))
        (output / 'native-http.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report))
    finally:
        if process.poll() is None: process.terminate(); process.wait(timeout=5)
        log.close(); server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == '__main__':
    main()
