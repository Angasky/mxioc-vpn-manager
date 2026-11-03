"""Exercise real code installation without pip, services or system paths."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash') or (
    'C:/Program Files/Git/bin/bash.exe'
    if Path('C:/Program Files/Git/bin/bash.exe').exists() else None
)


@unittest.skipUnless(BASH, 'requires Bash to exercise install.sh')
class InstallerModuleTests(unittest.TestCase):
    def install(self, directory, installer=None):
        # All installation destinations stay inside this test's temporary root.
        # A fake venv executable replaces pip; the real stage/copy/backup logic runs.
        script = r'''
set -Eeuo pipefail
export MXIOC_SOURCE_ONLY=1
source "$1"
fixture_source="$3"
APP_DIR="$2/app"
CONFIG_DIR="$2/config"
SERVICE_FILE="$2/service"
install_shortcut() { :; }
curl() {
    local relative="" destination=""
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            "${RAW_BASE}/"*) relative="${1#"${RAW_BASE}/"}"; shift ;;
            -o) destination="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    [[ -n "$relative" && -n "$destination" ]]
    cp -- "$fixture_source/$relative" "$destination"
}
install -d "$APP_DIR/venv/bin"
printf '#!/usr/bin/env bash\nexit 0\n' > "$APP_DIR/venv/bin/python"
chmod +x "$APP_DIR/venv/bin/python"
install_application
'''
        result = subprocess.run(
            [BASH, '-s', '--', (installer or ROOT / 'install.sh').as_posix(),
             Path(directory).as_posix(), ROOT.as_posix()], input=script, text=True,
            capture_output=True, timeout=45,
            env={**os.environ, 'MXIOC_SOURCE_ONLY': '1'},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fresh_install_imports_modules_and_update_backs_up_managed_nodes(self):
        with tempfile.TemporaryDirectory() as directory:
            self.install(directory)
            app = Path(directory) / 'app'
            result = subprocess.run(
                [sys.executable, '-I', '-c',
                 'import sys; sys.path.insert(0, sys.argv[1]); '
                 'import managed_nodes; '
                 'assert managed_nodes.references([{"name":"fixture"}])[0]["identity"]; '
                 'print("managed_nodes import OK")', str(app)],
                text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for source in ROOT.glob('*.py'):
                self.assertTrue((app / source.name).is_file(), source.name)
                self.assertEqual((app / source.name).read_bytes(), source.read_bytes())
            (app / 'managed_nodes.py').write_text('# previous module\n', encoding='utf-8')
            # The self-updater runs a standalone downloaded installer without
            # adjacent sources. Exercise that download branch using local bytes.
            updater = Path(directory) / 'updater'
            updater.mkdir()
            installer = updater / 'install.sh'
            installer.write_bytes((ROOT / 'install.sh').read_bytes())
            self.install(directory, installer)
            self.assertEqual((app / 'managed_nodes.py').read_bytes(),
                             (ROOT / 'managed_nodes.py').read_bytes())
            backups = list((app / 'code-backups').glob('managed_nodes.py.*'))
            self.assertTrue(backups, 'update did not back up managed_nodes.py')
            self.assertTrue(any(p.read_text(encoding='utf-8') == '# previous module\n'
                                for p in backups))


if __name__ == '__main__':
    unittest.main()
