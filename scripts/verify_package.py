"""Install, upgrade, launch and remove the current release in an isolated directory."""
import ctypes
import argparse
from contextlib import contextmanager
from ctypes import wintypes
import json
import os
import struct
from pathlib import Path
import subprocess
import tempfile
import time
import winreg
import zipfile


USER32 = ctypes.WinDLL('user32', use_last_error=True)
CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
USER32.EnumWindows.argtypes = [CALLBACK, wintypes.LPARAM]
USER32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
USER32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
USER32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
UNINSTALL = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\{C3DDDFD6-1B8D-4D87-A5DF-F21F60246B70}_is1'


def registered():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except FileNotFoundError:
        return False


@contextmanager
def preserve_shortcut(path):
    previous = path.read_bytes() if path.exists() else None
    try:
        yield
    finally:
        if previous is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(previous)


class ShellProcess:
    def __init__(self, shortcut, arguments, env):
        class ExecuteInfo(ctypes.Structure):
            _fields_ = [('cbSize', wintypes.DWORD), ('fMask', wintypes.ULONG), ('hwnd', wintypes.HWND),
                        ('lpVerb', wintypes.LPCWSTR), ('lpFile', wintypes.LPCWSTR), ('lpParameters', wintypes.LPCWSTR),
                        ('lpDirectory', wintypes.LPCWSTR), ('nShow', ctypes.c_int), ('hInstApp', wintypes.HANDLE),
                        ('lpIDList', ctypes.c_void_p), ('lpClass', wintypes.LPCWSTR), ('hkeyClass', wintypes.HANDLE),
                        ('dwHotKey', wintypes.DWORD), ('hIcon', wintypes.HANDLE), ('hProcess', wintypes.HANDLE)]
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.GetProcessId.argtypes = [wintypes.HANDLE]
        self.kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        info = ExecuteInfo(); info.cbSize = ctypes.sizeof(info); info.fMask = 0x40
        info.lpVerb = 'open'; info.lpFile = str(shortcut); info.lpParameters = subprocess.list2cmdline(arguments); info.nShow = 1
        shell = ctypes.WinDLL('shell32', use_last_error=True)
        shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ExecuteInfo)]
        previous = os.environ.copy()
        try:
            os.environ.clear(); os.environ.update(env)
            assert shell.ShellExecuteExW(ctypes.byref(info)), ctypes.get_last_error()
        finally:
            os.environ.clear(); os.environ.update(previous)
        self.handle = info.hProcess; assert self.handle
        self.pid = self.kernel.GetProcessId(self.handle)

    def poll(self):
        code = wintypes.DWORD(); self.kernel.GetExitCodeProcess(self.handle, ctypes.byref(code))
        return None if code.value == 259 else code.value

    def wait(self, timeout):
        assert self.kernel.WaitForSingleObject(self.handle, int(timeout * 1000)) == 0, 'Close timed out'
        return self.poll()

    def terminate(self):
        self.kernel.TerminateProcess(self.handle, 1)

    def close(self):
        self.kernel.CloseHandle(self.handle)


def launch(application, settings, env, sample=None):
    args = [str(application), '--settings-file', str(settings)]
    if sample:
        args += ['--open', str(sample)]
    start = time.perf_counter()
    process = ShellProcess(application, args[1:], env) if application.suffix == ".lnk" else subprocess.Popen(args, cwd=application.parent, env=env)
    windows = []

    @CALLBACK
    def inspect(window, _):
        owner = wintypes.DWORD()
        USER32.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == process.pid:
            title = ctypes.create_unicode_buffer(512)
            USER32.GetWindowTextW(window, title, len(title))
            if title.value == 'EtherScope' or title.value.endswith(' — EtherScope'):
                windows.append(window)
        return True

    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and process.poll() is None and not windows:
            USER32.EnumWindows(inspect, 0)
            time.sleep(0.02)
        elapsed = time.perf_counter() - start
        assert windows and process.poll() is None, 'Window missing'
        time.sleep(0.25)
        for window in windows:
            USER32.PostMessageW(window, 0x0010, 0, 0)
        assert process.wait(timeout=5) == 0
        assert settings.is_file()
        return round(elapsed * 1000, 2)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        if isinstance(process, ShellProcess):
            process.close()


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument('--previous-installer', type=Path)
    args = arguments.parse_args()
    project = Path(__file__).resolve().parent.parent
    manifest = json.loads((project / 'output/program-package.json').read_text(encoding='utf-8-sig'))
    version = manifest['version']
    archive_path = Path(manifest['archive'])
    assert archive_path.name == f'EtherScope-{version}-windows-x64.zip', archive_path.name
    assert not registered(), 'An existing EtherScope installation must be preserved.'
    profile_files = [Path(os.environ[key]) / 'EtherScope Course Project/EtherScope/settings.ini'
                     for key in ('APPDATA', 'LOCALAPPDATA')]
    profiles = {str(path): path.read_bytes() if path.exists() else None for path in profile_files}
    report = {'version': version, 'passed': False}
    shortcut_path = Path(os.environ['APPDATA']) / 'Microsoft/Windows/Start Menu/Programs/EtherScope/EtherScope.lnk'
    shortcut_before = shortcut_path.read_bytes() if shortcut_path.exists() else None
    with preserve_shortcut(shortcut_path), tempfile.TemporaryDirectory(prefix='EtherScope-install-') as temporary:
        root = Path(temporary) / '安装测试 & 空格'
        root.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            assert archive.testzip() is None
            files = [name for name in archive.namelist() if not name.endswith('/')]
            expected = {f'EtherScope-{version}/EtherScope-Setup-{version}-x64.exe'}
            assert set(files) == expected, files
            archive.extractall(root)
        release = root / f'EtherScope-{version}'
        installer = release / f'EtherScope-Setup-{version}-x64.exe'
        assert manifest['driver_download_url'] == 'https://npcap.com/dist/npcap-1.89.exe'
        application_root = root / '应用程序'
        group = 'EtherScope'
        shortcut = Path(os.environ['APPDATA']) / 'Microsoft/Windows/Start Menu/Programs' / group / 'EtherScope.lnk'
        settings = root / '验收设置.ini'
        settings.write_text('[filter]\nip=2001:db8::1\nprotocol=ICMPv6\nmacDirection=0\nipDirection=0\n', encoding='utf-8')
        parameters = [str(installer), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/CURRENTUSER',
                      '/TASKS=', '/DIR=' + str(application_root), '/GROUP=' + group]
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith('QT_') and key.upper() not in ('QTDIR', 'QT6_DIR', 'CMAKE_PREFIX_PATH')}
        env['PATH'] = os.pathsep.join([str(application_root), str(Path(env['WINDIR']) / 'System32'), env['WINDIR']])
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        installed = False
        try:
            subprocess.run(parameters + ['/LOG=' + str(project / 'output/evidence/installer-install.log')], check=True, timeout=60, startupinfo=startup)
            installed = True
            assert registered()
            application = application_root / 'EtherScope.exe'
            assert application.read_bytes() == (project / 'build/msvc-release/EtherScope.exe').read_bytes()
            assert (application_root / 'licenses/EtherScope-MIT.txt').read_bytes() == (project / 'LICENSE').read_bytes()
            installed_files = [str(path.relative_to(application_root)) for path in application_root.rglob('*') if path.is_file()]
            assert not any(path.lower().endswith(('.ps1', '.cmd', '.pcap', '.md')) or 'npcap' in path.lower() for path in installed_files)
            shortcut = Path(os.environ['APPDATA']) / 'Microsoft/Windows/Start Menu/Programs' / group / 'EtherScope.lnk'
            assert shortcut.is_file(), str(shortcut) + '\n' + '\n'.join(str(p) for p in shortcut.parent.parent.rglob('*EtherScope*'))
            link = shortcut.read_bytes(); offset = 76
            if struct.unpack_from('<I', link, 20)[0] & 1:
                offset += 2 + struct.unpack_from('<H', link, offset)[0]
            unicode_offset = struct.unpack_from('<I', link, offset + 28)[0]
            target = link[offset + unicode_offset:].decode('utf-16-le', errors='ignore').split('\0')[0]
            assert os.path.samefile(target, application)
            startups = [launch(shortcut, settings, env, project / 'samples/synthetic-ipv6.pcap')]
            restored = settings.read_text(encoding='utf-8-sig')
            assert '2001:db8::1' in restored and 'ICMPv6' in restored and 'openDirectory=' in restored
            previous_checked = None
            if args.previous_installer:
                previous_installer = args.previous_installer.resolve(strict=True)
                subprocess.run([str(previous_installer)] + parameters[1:] + ['/LOG=' + str(root / 'previous.log')], check=True, timeout=60, startupinfo=startup)
                assert application.read_bytes() != (project / 'build/msvc-release/EtherScope.exe').read_bytes()
                launch(shortcut, settings, env)
                previous_checked = previous_installer.name
            before_upgrade = settings.read_bytes()
            subprocess.run(parameters + ['/LOG=' + str(root / 'upgrade.log')], check=True, timeout=60, startupinfo=startup)
            assert settings.read_bytes() == before_upgrade
            assert application.read_bytes() == (project / 'build/msvc-release/EtherScope.exe').read_bytes()
            startups += [launch(shortcut, settings, env) for _ in range(4)]
            assert max(startups) <= 3000, startups
            capture_output = project / f'output/evidence/npcap-installed-{version}.json'
            powershell = Path(env['WINDIR']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            adapter = subprocess.check_output([str(powershell), '-NoProfile', '-Command',
                       "Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty InterfaceGuid"], startupinfo=startup).decode('ascii').strip()
            assert adapter, 'No active physical adapter'
            device = '\\Device\\NPF_' + (adapter if adapter.startswith('{') else '{' + adapter + '}')
            probe = subprocess.Popen([str(project / 'build/msvc-release/capture_probe.exe'), '--device', device, '--output', str(capture_output), '--duration-ms', '5000'],
                                     env=env, cwd=application_root, startupinfo=startup)
            subprocess.run(['ping.exe', '-n', '4', '-w', '500', '1.1.1.1'], stdout=subprocess.DEVNULL, startupinfo=startup, timeout=10)
            probe_code = probe.wait(timeout=10)
            capture = json.loads(capture_output.read_text(encoding='utf-8'))
            assert probe_code == 0 and capture['passed'] and capture['stop_completed_ms'] <= 1000, capture
            report.update({'archive_integrity': True, 'program_installer_only': True, 'driver_external_download': True,
                           'current_binary': True, 'install_upgrade': True, 'preserved_settings': True,
                           'shortcut_target': True, 'bundled_dependencies': True, 'ipv6_file_open': True, 'mit_notice': True, 'previous_installer': previous_checked,
                           'startup_ms': startups, 'live_capture': capture, 'installer_bytes': installer.stat().st_size})
        finally:
            uninstaller = application_root / 'unins000.exe'
            if installed and uninstaller.is_file():
                subprocess.run([str(uninstaller), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'],
                               check=True, timeout=60, cwd=root, startupinfo=startup)
                deadline = time.monotonic() + 10
                while (application_root / 'EtherScope.exe').exists() and time.monotonic() < deadline:
                    time.sleep(0.1)
                assert not (application_root / 'EtherScope.exe').exists()
                assert not registered()
                assert not shortcut.exists()
                report['uninstall'] = True
        for path in profile_files:
            assert (path.read_bytes() if path.exists() else None) == profiles[str(path)], 'Personal settings changed'
        report['personal_settings_untouched'] = True
        report['passed'] = True
    assert (shortcut_path.read_bytes() if shortcut_path.exists() else None) == shortcut_before
    report['existing_shortcut_preserved'] = True
    output = project / f'output/installer-check-{version}.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
