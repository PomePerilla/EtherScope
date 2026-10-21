"""Fetch pinned source archives into the build cache; verify before extraction."""
import argparse
import hashlib
import json
import pathlib
import tarfile
import urllib.request
import zipfile
import sys

sys.stdout.reconfigure(encoding='utf-8')

parser = argparse.ArgumentParser()
parser.add_argument('--perl', action='store_true')
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parent.parent
cache = root / '.tools' / 'dependencies'
cache.mkdir(parents=True, exist_ok=True)
manifest = json.loads((root / 'scripts' / 'dependencies.json').read_text())
for name in ['openssl', 'nghttp2'] + (['perl'] if args.perl else []):
    spec = manifest[name]
    archive = cache / spec['url'].rsplit('/', 1)[-1]
    if not archive.exists():
        with urllib.request.urlopen(spec['url'], timeout=60) as response, archive.open('wb') as out:
            while chunk := response.read(1024 * 1024):
                out.write(chunk)
    if hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() != spec['sha256']:
        raise RuntimeError(f'{name}: SHA256 mismatch: {archive}')
    destination = cache / spec['directory']
    marker = destination / '.etherscope-verified'
    if not marker.exists():
        if archive.suffix == '.zip':
            destination.mkdir(exist_ok=True)
            with zipfile.ZipFile(archive) as source:
                for member in source.infolist():
                    target = (destination / member.filename).resolve()
                    if not target.is_relative_to(destination.resolve()):
                        raise RuntimeError('Archive path escapes destination')
                source.extractall(destination)
        else:
            with tarfile.open(archive) as source:
                source.extractall(cache, filter='data')
        marker.write_text(spec['sha256'] + '\n')
    print(f'{name} {spec["version"]}: {destination}')
