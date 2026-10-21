"""Check decrypted bytes against an independent Python/OpenSSL endpoint."""
import argparse
import json
import pathlib
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('inspector')
parser.add_argument('output', type=pathlib.Path)
args = parser.parse_args()
subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('make_tls_interop.py')), str(args.output)], check=True)
manifest = json.loads((args.output / 'manifest.json').read_text())
reports = []
for case in manifest['cases']:
    result = subprocess.run([args.inspector, case['capture'], case['keylog'], '--plaintext'],
                            check=True, capture_output=True, text=True, encoding='utf-8')
    plaintext = ['', '']
    for line in result.stdout.splitlines():
        values = line.split('\t')
        if values[0] == 'plaintext':
            plaintext[int(values[1])] += values[2]
        elif values[0] == 'status':
            assert values[1] == '1', (case['name'], line)
    assert plaintext == [case['expected_request'], case['expected_response']], case['name']
    incremental = subprocess.check_output([args.inspector, case['capture'], case['keylog'],
                                          '--plaintext', '--incremental'], text=True, encoding='utf-8')
    assert sorted(incremental.splitlines()) == sorted(result.stdout.splitlines()), case['name']
    reports.append({'name': case['name'], 'exact_plaintext': True, 'incremental_equal': True, 'resumed': case['resumed']})
(args.output / 'verification.json').write_text(json.dumps(reports, indent=2))
print(f'PASS: {len(reports)} endpoint captures with exact decrypted bytes')
