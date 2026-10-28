"""Run offline specimen checks and screenshots with an explicit Chromium/Edge binary."""
import argparse
import html
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def verify(browser, generated, output):
    browser, generated, output = Path(browser).resolve(), Path(generated).resolve(), Path(output).resolve()
    if not browser.is_file() or not (generated / 'index.html').is_file():
        raise ValueError('Browser executable and generated index.html are required')
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads((generated / 'project-contract.json').read_text(encoding='utf-8'))
    startup = None
    if os.name == 'nt':
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
    def run(extra, profile):
        result = subprocess.run([str(browser), '--headless', '--disable-gpu', '--no-first-run',
            '--no-default-browser-check', '--hide-scrollbars', '--allow-file-access-from-files',
            '--user-data-dir=' + str(profile), *extra], capture_output=True, startupinfo=startup, timeout=40)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode('utf-8', errors='replace')[-2000:])
        return result.stdout.decode('utf-8', errors='replace')
    with tempfile.TemporaryDirectory(prefix='browser-', dir=output) as profile:
        dom = run(['--dump-dom', '--virtual-time-budget=1000', (generated / 'index.html').as_uri() + '?selftest=1'], profile)
        (output / 'selftest-dom.html').write_text(dom, encoding='utf-8')
        match = re.search(r'<script type="application/json" id="selftest-results">(.*?)</script>', dom, re.S)
        if not match:
            raise ValueError('Specimen did not return a self-test result')
        interaction = json.loads(html.unescape(match.group(1)))
        if not interaction['passed']:
            raise ValueError('Interaction check failed: ' + json.dumps(interaction))
        screenshots = []
        for width, height in config['verification']['sizes']:
            path = output / f'web-{width}.png'
            run(['--screenshot=' + str(path), f'--window-size={width},{height}', '--virtual-time-budget=1000',
                 (generated / 'index.html').as_uri()], profile)
            if not path.is_file() or path.stat().st_size < 1000:
                raise ValueError('Screenshot was not created')
            screenshots.append(str(path))
    report = {'passed': True, 'browser': str(browser), 'interaction': interaction,
              'screenshots': screenshots, 'scope': 'offline specimen; inspect screenshots and test target app separately'}
    (output / 'web-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', type=Path, required=True)
    parser.add_argument('--generated', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.browser, args.generated, args.output), ensure_ascii=False))
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')
