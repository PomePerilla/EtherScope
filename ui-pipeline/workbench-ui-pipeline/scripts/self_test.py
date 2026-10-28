"""Behavioral checks for the portable generator and installer; no GUI required."""
import copy
import tempfile
import unittest
from pathlib import Path
from build import PACKAGE, read_json, build, render
from check import check
from install import install
import json


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.config = read_json(PACKAGE / 'assets/project-contract.json')
        self.temp = tempfile.TemporaryDirectory(prefix='workbench-pipeline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write_config(self):
        path = self.root / '配置.json'
        path.write_text(json.dumps(self.config, ensure_ascii=False), encoding='utf-8')
        return path

    def test_config_generates_matching_adapters(self):
        self.config['token_overrides'] = {'metrics': {'row_height': 32}}
        path = self.write_config()
        target = build(path, self.root / 'generated')
        self.assertTrue(check(path, target)['passed'])
        self.assertIn('--wb-row-height: 32px', (target / 'tokens.css').read_text())
        self.assertIn('rowHeight = 32', (target / 'qt/workbench_style.h').read_text())

    def test_existing_output_preserved(self):
        target = self.root / 'existing'
        target.mkdir()
        (target / 'personal').write_text('keep')
        with self.assertRaises(FileExistsError):
            build(self.write_config(), target)
        self.assertEqual((target / 'personal').read_text(), 'keep')

    def test_invalid_config_writes_nothing(self):
        self.config['token_overrides'] = {'colors': {'dark': {'text': '#17191C'}}}
        target = self.root / 'invalid'
        with self.assertRaises(ValueError):
            build(self.write_config(), target)
        self.assertFalse(target.exists())

    def test_reject_unknown_or_injected_tokens(self):
        for override in ({'missing': 4}, {'metrics': {'row_height': -1}},
                         {'colors': {'dark': {'primary': 'red; background:black'}}},
                         {'fonts': {'ui': ['bad\"; color: red']}}):
            config = copy.deepcopy(self.config)
            config['token_overrides'] = override
            with self.assertRaises(ValueError):
                render(config)

    def test_escaped_project_and_determinism(self):
        self.config['project'] = '<script>alert("unsafe")</script>'
        files = render(self.config)
        self.assertNotIn(self.config['project'], files['index.html'])
        self.assertIn('&lt;script&gt;', files['index.html'])
        self.assertEqual(render(self.config), files)

    def test_tampered_asset_is_detected(self):
        path = self.write_config()
        target = build(path, self.root / 'generated')
        (target / 'tokens.css').write_text('changed')
        with self.assertRaises(ValueError):
            check(path, target)

    def test_install_preserves_existing_and_has_no_repo_dependency(self):
        target = Path(install(self.root / 'skills')['installed'])
        self.assertEqual((target / 'SKILL.md').read_bytes(), (PACKAGE / 'SKILL.md').read_bytes())
        with self.assertRaises(FileExistsError):
            install(self.root / 'skills')
        import subprocess
        import sys
        process = subprocess.run([sys.executable, str(target / 'scripts/build.py'), '--config',
            str(target / 'assets/project-contract.json'), '--output', str(self.root / 'from-installed')], capture_output=True)
        self.assertEqual(process.returncode, 0, process.stderr.decode('utf-8', errors='replace'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
