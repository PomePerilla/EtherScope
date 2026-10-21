"""Build pinned static dependencies on POSIX hosts."""
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
subprocess.run([sys.executable, str(root / 'scripts/fetch-dependencies.py')], check=True)
cache = root / '.tools/dependencies'
prefix = cache / 'install'
openssl = cache / 'openssl-3.5.9'
if not (prefix / 'lib/libcrypto.a').exists():
    subprocess.run(['./Configure', 'no-shared', 'no-tests', 'no-module', 'no-engine', 'no-asm',
                    f'--prefix={prefix}', '--libdir=lib'], cwd=openssl, check=True)
    subprocess.run(['make', f'-j{min(os.cpu_count() or 2, 4)}', 'build_libs'], cwd=openssl, check=True)
    subprocess.run(['make', 'install_dev'], cwd=openssl, check=True)
subprocess.run(['cmake', '-S', str(cache / 'nghttp2-1.70.0'), '-B', str(cache / 'nghttp2-build'),
                '-DCMAKE_BUILD_TYPE=Release', f'-DCMAKE_INSTALL_PREFIX={prefix}',
                '-DENABLE_LIB_ONLY=ON', '-DBUILD_STATIC_LIBS=ON', '-DBUILD_SHARED_LIBS=OFF',
                '-DBUILD_TESTING=OFF', '-DENABLE_DOC=OFF'], check=True)
subprocess.run(['cmake', '--build', str(cache / 'nghttp2-build'), '--target', 'install', '-j', '4'], check=True)
