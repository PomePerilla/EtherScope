"""Check translation coverage, placeholders, and source archive language entries."""
import json
import re
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent.parent
    rows = json.loads((root / 'src/ui/i18n/messages.json').read_text(encoding='utf-8'))
    messages = {}
    for source, english, traditional in rows:
        assert source and english and traditional and source not in messages, source
        assert not re.search('[\u4e00-\u9fff]', english), source
        placeholders = sorted(re.findall(r'%[1-9][0-9]*', source))
        assert placeholders == sorted(re.findall(r'%[1-9][0-9]*', english)), source
        assert placeholders == sorted(re.findall(r'%[1-9][0-9]*', traditional)), source
        assert not any(s in english + traditional for s in ('·', '—', '–', '｜')), source
        messages[source] = (english, traditional)
    missing = set()
    for path in (root / 'src').rglob('*'):
        if path.suffix not in ('.cpp', '.inc'):
            continue
        for literal in re.findall(r'"(?:[^"\\]|\\.)*"', path.read_text(encoding='utf-8-sig')):
            try:
                value = json.loads(literal)
            except json.JSONDecodeError:
                continue
            if value in messages or value in ('简体中文', '繁體中文'):
                continue
            missing.update(run for run in re.findall('[\u4e00-\u9fff]+', value) if run not in messages)
    assert not missing, 'Untranslated phrases: ' + ', '.join(sorted(missing))
    for name in ('README.md', 'README.zh-CN.md', 'README.zh-TW.md'):
        content = (root / name).read_text(encoding='utf-8')
        for target in re.findall(r'\]\((README[^)]+)\)', content):
            assert (root / target).is_file(), target
    print(f'PASS: {len(messages)} translations, placeholders, source coverage, and README links')


if __name__ == '__main__':
    main()
