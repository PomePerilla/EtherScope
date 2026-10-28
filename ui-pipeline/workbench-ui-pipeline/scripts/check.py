"""Validate project configuration and reproducible generated files."""
import argparse
import json
from pathlib import Path
from build import read_json, render, resolve, contrast_results


def check(config_path, generated=None):
    config = read_json(config_path)
    files = render(config)
    if generated:
        root = Path(generated).resolve()
        for name, content in files.items():
            path = root / name
            if not path.is_file() or path.read_bytes() != content.encode('utf-8'):
                raise ValueError('Generated asset differs: ' + name)
    return {'passed': True, 'project': config['project'], 'generated_files': len(files),
            'contrast_pairs': len(contrast_results(resolve(config))),
            'scope': 'configuration and generated assets; runtime UI requires separate checks'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--generated', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.config, args.generated), ensure_ascii=False))
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, str(error) + '\n')
