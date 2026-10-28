"""Generate portable workbench assets. Python 3 standard library only."""
import argparse
import copy
import hashlib
import html
import json
import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def merge(target, changes, path='token_overrides'):
    if not isinstance(changes, dict):
        raise ValueError(path + ' must be an object')
    for key, value in changes.items():
        if key not in target:
            raise ValueError('Unknown token: ' + path + '.' + key)
        if isinstance(target[key], dict):
            merge(target[key], value, path + '.' + key)
        else:
            target[key] = value


def contrast(a, b):
    def luminance(color):
        channels = [int(color[n:n + 2], 16) / 255 for n in (1, 3, 5)]
        channels = [x / 12.92 if x <= .04045 else ((x + .055) / 1.055) ** 2.4 for x in channels]
        return sum(x * weight for x, weight in zip(channels, (.2126, .7152, .0722)))
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + .05) / (low + .05)


def resolve(config):
    if not isinstance(config, dict):
        raise ValueError('Configuration must be an object')
    for field in ('project', 'primary_task'):
        if not isinstance(config.get(field), str) or not config[field].strip() or len(config[field]) > 300:
            raise ValueError(field + ' must contain 1-300 characters')
    if config.get('layout') not in ('list-inspector', 'navigation-content', 'monitor-analysis'):
        raise ValueError('Unsupported layout')
    if not isinstance(config.get('languages'), list) or not config['languages'] or any(not isinstance(v, str) for v in config['languages']):
        raise ValueError('languages must be a nonempty string array')
    # Sample supplies zh_CN/en. Other languages are contract requirements for the target app.
    def dimensions(value):
        return isinstance(value, list) and len(value) == 2 and all(type(v) is int and 240 <= v <= 10000 for v in value)
    if not dimensions(config.get('minimum_window')):
        raise ValueError('minimum_window must contain two positive logical dimensions')
    checks = config.get('verification', {})
    if not checks.get('sizes') or not all(dimensions(v) for v in checks['sizes']):
        raise ValueError('verification.sizes must contain valid dimensions')
    if not checks.get('themes') or any(v not in ('dark', 'light') for v in checks['themes']):
        raise ValueError('verification.themes must contain dark or light')
    if not checks.get('scales') or any(type(v) not in (float, int) or not .5 <= v <= 4 for v in checks['scales']):
        raise ValueError('verification.scales must be between 0.5 and 4')
    tokens = copy.deepcopy(read_json(PACKAGE / 'assets/tokens.json'))
    merge(tokens, config.get('token_overrides', {}))
    if tokens['version'] != '1.0.0':
        raise ValueError('Token schema version is fixed at 1.0.0')
    for theme, colors in tokens['colors'].items():
        for key, color in colors.items():
            if not isinstance(color, str) or not re.fullmatch(r'#[0-9a-fA-F]{6}', color):
                raise ValueError('Invalid color: ' + theme + '.' + key)
    for key, value in tokens['metrics'].items():
        if type(value) not in (int, float) or not 0 < value <= 128:
            raise ValueError('Invalid positive metric: ' + key)
        if key != 'icon_stroke' and type(value) is not int:
            raise ValueError('Pixel metric must be an integer: ' + key)
    if tokens['metrics']['control_height'] < tokens['metrics']['font_size'] + 8:
        raise ValueError('Control height must provide text clearance')
    if tokens['metrics']['row_height'] < tokens['metrics']['font_size'] + 4:
        raise ValueError('Row height must provide text clearance')
    for family in tokens['fonts'].values():
        if not isinstance(family, list) or not family or any(not isinstance(v, str) or not re.fullmatch(r'[\w -]+', v) for v in family):
            raise ValueError('Font families must be nonempty names')
    return tokens


def contrast_results(tokens):
    checks = []
    for theme, c in tokens['colors'].items():
        for fg, bg in [('text', 'surface'), ('muted', 'surface'), ('primary_text', 'primary'),
                       ('primary_text', 'primary_hover'), ('primary_text', 'primary_pressed'),
                       ('accent', 'surface'), ('text', 'selection'), ('error', 'surface'),
                       ('success', 'surface'), ('warning', 'surface')]:
            ratio = contrast(c[fg], c[bg])
            checks.append({'theme': theme, 'foreground': fg, 'background': bg,
                           'ratio': round(ratio, 3), 'passed': ratio >= 4.5})
    return checks


def render(config):
    tokens = resolve(config)
    checks = contrast_results(tokens)
    if not all(v['passed'] for v in checks):
        raise ValueError('Readable text contrast is below 4.5: ' + json.dumps([v for v in checks if not v['passed']]))
    blocks = []
    for theme, colors in tokens['colors'].items():
        selector = ':root, [data-theme="dark"]' if theme == 'dark' else '[data-theme="light"]'
        values = [f'  --wb-{key.replace("_", "-")}: {value};' for key, value in colors.items()]
        values += [f'  --wb-{key.replace("_", "-")}: {value}px;' for key, value in tokens['metrics'].items()]
        values += [f'  --wb-font-{key}: ' + ', '.join(json.dumps(v) for v in family) + ';' for key, family in tokens['fonts'].items()]
        blocks.append(selector + ' {\n' + '\n'.join(values) + '\n}')
    css = '\n'.join(blocks) + '\n'
    files = {'tokens.json': json.dumps(tokens, ensure_ascii=False, indent=2) + '\n',
             'project-contract.json': json.dumps(config, ensure_ascii=False, indent=2) + '\n',
             'tokens.css': css, 'components.css': (PACKAGE / 'assets/web/components.css').read_text(encoding='utf-8')}
    page = (PACKAGE / 'assets/web/index.html').read_text(encoding='utf-8')
    page = page.replace('@PROJECT@', html.escape(config['project'], quote=True))
    page = page.replace('@TASK@', html.escape(config['primary_task'], quote=True)).replace('@LAYOUT@', config['layout'])
    files['index.html'] = page
    for theme, colors in tokens['colors'].items():
        qss = (PACKAGE / 'assets/qt/theme.qss.in').read_text(encoding='utf-8')
        values = {**colors, **tokens['metrics'], 'ui_font': tokens['fonts']['ui'][0],
                  'control_inner': tokens['metrics']['control_height'] - 2}
        for key, value in values.items():
            qss = qss.replace('@' + key + '@', str(value))
        if re.search(r'@[a-z_]+@', qss):
            raise ValueError('Unresolved QSS token')
        files[f'qt/theme-{theme}.qss'] = qss
    header = (PACKAGE / 'assets/qt/workbench_style.h.in').read_text(encoding='utf-8')
    for theme, colors in tokens['colors'].items():
        for key, value in colors.items():
            header = header.replace('@' + theme + '_' + key + '@', value)
    for key, value in tokens['metrics'].items():
        header = header.replace('@' + key + '@', str(value))
    header = header.replace('@DATA_FONTS@', ', '.join(json.dumps(v, ensure_ascii=False) for v in tokens['fonts']['data']))
    if re.search(r'@[A-Za-z_]+@', header):
        raise ValueError('Unresolved header token')
    files['qt/workbench_style.h'] = header
    for path in (PACKAGE / 'assets/qt').iterdir():
        if path.suffix != '.in':
            files['qt/' + path.name] = path.read_text(encoding='utf-8')
    files['LICENSE'] = (PACKAGE / 'LICENSE').read_text(encoding='utf-8')
    files['contrast.json'] = json.dumps(checks, indent=2) + '\n'
    manifest = {'pipeline_version': '1.0.0', 'files': {name: hashlib.sha256(content.encode('utf-8')).hexdigest() for name, content in sorted(files.items())}}
    files['manifest.json'] = json.dumps(manifest, indent=2) + '\n'
    return files


def build(config_path, output):
    files = render(read_json(config_path))
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('Choose a new output directory: ' + str(output))
    output.mkdir(parents=True)
    for name, content in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8', newline='\n')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(str(build(args.config, args.output)))
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, str(error) + '\n')
