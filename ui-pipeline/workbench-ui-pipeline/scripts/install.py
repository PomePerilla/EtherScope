"""Install this self-contained skill to a local skills directory without overwrite."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


def install(destination):
    root = Path(destination).expanduser().resolve()
    target = root / 'workbench-ui-pipeline'
    if target.exists():
        raise FileExistsError('Existing skill preserved: ' + str(target))
    if target == PACKAGE or PACKAGE in target.parents:
        raise ValueError('Destination must be outside the source skill')
    root.mkdir(parents=True, exist_ok=True)
    # copytree itself refuses an existing target, including a concurrent installation.
    shutil.copytree(PACKAGE, target, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    count = 0
    for source in PACKAGE.rglob('*'):
        if not source.is_file() or '__pycache__' in source.parts or source.suffix == '.pyc':
            continue
        relative = source.relative_to(PACKAGE)
        if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256((target / relative).read_bytes()).digest():
            raise ValueError('Installed file differs: ' + str(relative))
        count += 1
    return {'installed': str(target), 'files_verified': count, 'version': '1.0.0'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(install(args.destination), ensure_ascii=False))
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')
