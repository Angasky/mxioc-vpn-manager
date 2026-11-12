"""One-time backend notice and an isolated, reversible Python -> Go handover."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.request import Request, urlopen

NOTICE_ID = 'python-maintenance-go-2026-11'
VERSION = 'v0.1.30'
RELEASE = f'https://github.com/Angasky/Mx-Panel/releases/download/go-{VERSION}'
ROOT = Path('/opt/mxioc-rule-manager')
AUTH = Path('/etc/mxioc-rule-manager.auth.json')
SUBSCRIBE = Path('/etc/sing-box/subscribe')
NGINX = Path('/etc/nginx/conf.d/mxioc-rule-manager.conf')
GO_BASE = Path('/opt/mxioc-go')
GO_UNIT = Path('/etc/systemd/system/mxioc-go.service')
SHORTCUT = Path('/usr/local/bin/mx-p')
BACKUPS = Path('/var/backups/mx-panel')
LEGACY = 'mxioc-rule-manager.service'
GO_SERVICE = 'mxioc-go.service'
LOCK_PATH = Path('/run/lock/mxioc-backend-migration.lock')
ACTIVE = {'queued', 'downloading', 'backup', 'installing', 'switching'}
LOCK = threading.RLock()
SEEN = {}


def read_state(root=ROOT):
    path = root / 'backend-choice.json'
    if not path.exists():
        return {}
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('后端选择记录损坏，请检查 backend-choice.json')
    return value


def save_state(root, value):
    root.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.backend-choice-', dir=root)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False)
        os.replace(name, root / 'backend-choice.json')
    finally:
        if os.path.exists(name):
            os.unlink(name)


def notice_status(root, session_key):
    with LOCK:
        state = read_state(root)
        job = state.get('migration', {})
        if job.get('status') in ACTIVE and time.time() - job.get('startedAt', 0) > 30:
            unit = job.get('unit', '')
            if re.fullmatch(r'mxioc-backend-migration-[0-9a-f]{12}', unit):
                current = command('systemctl', 'show', unit, '--property=ActiveState', '--value', check=False, timeout=5)
                if current.stdout.strip() not in {'active', 'activating', 'reloading'}:
                    job.update(status='recovery-required', message='迁移进程已停止，请检查服务器任务日志和迁移备份后恢复；不会自动重复迁移')
                    save_state(root, state)
        now = time.monotonic()
        # Entries are bound to authenticated sessions, never to client timestamps.
        for key, started in list(SEEN.items()):
            if now - started > 86400:
                SEEN.pop(key, None)
        key = (str(root), session_key)
        if len(SEEN) >= 256 and key not in SEEN:
            SEEN.pop(next(iter(SEEN)))
        started = SEEN.setdefault(key, now)
        return {'noticeId': NOTICE_ID, 'acknowledged': state.get('noticeId') == NOTICE_ID,
                'waitSeconds': max(0, 5 - int(now - started)),
                'choice': state.get('choice', ''), 'migration': state.get('migration', {})}


def acknowledge(root, session_key):
    with LOCK:
        state = read_state(root)
        if state.get('noticeId') != NOTICE_ID:
            started = SEEN.get((str(root), session_key))
            if started is None or time.monotonic() - started < 5:
                raise ValueError('请阅读公告满 5 秒后再点击“我已知晓”')
            state.update(noticeId=NOTICE_ID, acknowledgedAt=int(time.time()))
            save_state(root, state)
        return {'ok': True}


def migration_active(root):
    return read_state(root).get('migration', {}).get('status') in ACTIVE | {'recovery-required'}


def keep_python(root):
    with LOCK:
        state = read_state(root)
        if migration_active(root):
            raise ValueError('迁移任务正在执行，暂时不能修改选择')
        state.update(choice='python', chosenAt=int(time.time()))
        save_state(root, state)
        return {'ok': True, 'choice': 'python'}


def command(*args, check=True, timeout=120):
    return subprocess.run(list(map(str, args)), check=check, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


UPSTREAM = re.compile(r'(\bproxy_pass\s+http://(?:127\.0\.0\.1|localhost|\[::1\]):)62577(\s*;)')


def migrated_nginx(text):
    """Change only legacy upstream directives and their local proxy header.

    Tokenize quotes/comments so braces in strings or commented directives do
    not affect scope. A location with any proxy_set_header does not inherit
    headers from its server, so each affected scope needs its own scheme header.
    """
    tokens = list(re.finditer(r'''\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};"'\#]+''', text))
    stack, scopes, edits = [0], {0: []}, []
    directive = []
    for token in tokens:
        value = token.group()
        if value.isspace() or value.startswith('#'):
            continue
        if value == '{':
            stack.append(token.start())
            scopes[token.start()] = []
            directive = []
        elif value == '}':
            if len(stack) == 1:
                raise ValueError('Nginx 配置括号不完整')
            stack.pop()
            directive = []
        elif value == ';':
            if directive:
                scopes[stack[-1]].append((directive, token.end()))
            directive = []
        else:
            directive.append(token)
    if len(stack) != 1:
        raise ValueError('Nginx 配置括号不完整')
    count = 0
    for directives in scopes.values():
        targets = [(parts, end) for parts, end in directives
                   if len(parts) == 2 and parts[0].group() == 'proxy_pass'
                   and re.fullmatch(r'http://(?:127\.0\.0\.1|localhost|\[::1\]):62577', parts[1].group())]
        if not targets:
            continue
        for parts, end in targets:
            target = parts[1]
            edits.append((target.start(), target.end(), target.group()[:-5] + '62578'))
            count += 1
        headers = [(parts, end) for parts, end in directives if len(parts) >= 2
                   and parts[0].group() == 'proxy_set_header'
                   and parts[1].group().strip('"\'').lower() == 'x-forwarded-proto']
        # Remove any duplicate or hardcoded value, then install one trusted value.
        for parts, end in headers:
            edits.append((parts[0].start(), end, ''))
        end = targets[0][1]
        edits.append((end, end, '\n        proxy_set_header X-Forwarded-Proto $scheme;'))
    if not count:
        raise ValueError('未找到可迁移的 Python 转发指令，原配置未改动')
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def discover_nginx():
    # nginx -T lists only loaded files, including sites-enabled and custom includes.
    result = command('nginx', '-T', check=False, timeout=20)
    if result.returncode:
        # Do not return the configuration dump (it may contain credentials).
        errors = [line for line in result.stdout.splitlines()
                  if '[emerg]' in line or '[alert]' in line or line.startswith('nginx: [')]
        detail = errors[0][:600] if errors else '请在服务器执行 nginx -t 查看具体原因'
        raise ValueError('宿主机 Nginx 配置检查失败，原服务未改动：' + detail)
    candidates = {}
    blocks = re.split(r'^# configuration file (.+):\s*$', result.stdout, flags=re.M)
    for index in range(1, len(blocks) - 1, 2):
        content = re.sub(r'#.*', '', blocks[index + 1])
        if UPSTREAM.search(content):
            path = Path(blocks[index]).resolve()
            candidates[path] = content
    if not candidates:
        raise ValueError('未找到生效的 Nginx 配置转发到 Python 后端 62577 端口。请检查是否使用其他反向代理或自定义端口；原服务未改动')
    if len(candidates) != 1:
        raise ValueError('发现多个 Nginx 配置转发到 Python 后端，无法安全自动选择：' + '、'.join(map(str, candidates)))
    path = next(iter(candidates))
    if not path.is_file():
        raise ValueError('Nginx 生效配置文件已不存在，请检查配置后重试：' + str(path))
    return path


def preflight(check_nginx=True):
    global NGINX
    if os.geteuid() != 0 or platform.system() != 'Linux' or not Path('/run/systemd/system').is_dir():
        raise ValueError('自动迁移需要 root 运行的 Linux / systemd 安装')
    if platform.machine() not in ('x86_64', 'aarch64', 'arm64'):
        raise ValueError('暂不支持此 CPU 架构自动迁移')
    for tool in ('systemd-run', 'systemctl', 'nginx', 'bash', 'curl', 'flock', 'sha256sum'):
        if not shutil.which(tool):
            raise ValueError(f'自动迁移缺少命令：{tool}')
    if GO_UNIT.exists() or (GO_BASE / 'current').exists() or (GO_BASE / 'current').is_symlink() or SHORTCUT.exists():
        raise ValueError('已检测到 Go 安装或 mx-p 命令，请先在服务器检查，避免覆盖已有安装')
    if not AUTH.is_file() or ROOT.is_symlink() or AUTH.is_symlink():
        raise ValueError('数据、账号或 Nginx 路径不符合标准安装布局')
    # The web service has ProtectHome/PrivateTmp: certificates visible to nginx
    # may be hidden here. Only the independent systemd migration job can check
    # the host configuration. This still runs before downloading/stopping Python.
    if check_nginx:
        NGINX = discover_nginx()
        text = NGINX.read_text()
        migrated_nginx(text)
        if not re.search(r'^\s*listen\s+[^;]*\bssl\b', text, re.M):
            raise ValueError('请先在旧版启用 HTTPS；新版 Go 后台要求 HTTPS 登录')
    profiles = json.loads((ROOT / 'profiles.json').read_text()).get('profiles', [])
    for profile in profiles:
        for file in profile.get('files', []):
            path = Path(file).resolve()
            if not any(path == parent.resolve() or parent.resolve() in path.parents for parent in (ROOT, SUBSCRIBE)):
                raise ValueError('订阅文件位于标准备份目录外，需要人工迁移：' + str(path))
    # Symlinked subscription directories cannot be snapshotted consistently.
    if SUBSCRIBE.is_symlink():
        raise ValueError('订阅目录是符号链接，需要人工迁移')


def start(root):
    with LOCK:
        if root != ROOT:
            raise ValueError('自动迁移仅支持标准安装路径')
        if migration_active(root):
            raise ValueError('迁移任务正在执行，请勿重复点击')
        preflight(check_nginx=False)
        state = read_state(root)
        unit = 'mxioc-backend-migration-' + secrets.token_hex(6)
        state['migration'] = {'status': 'queued', 'unit': unit, 'startedAt': int(time.time()),
                              'message': '迁移任务已排队，正在准备下载'}
        save_state(root, state)
        try:
            command('systemd-run', '--unit', unit, '--collect', '--no-block',
                    '--property=Type=oneshot', '--property=TimeoutStartSec=30min',
                    '--property=UMask=0077', sys.executable, Path(__file__).resolve(), '--run', timeout=20)
        except Exception:
            state['migration'].update(status='failed', message='迁移任务未能启动，原服务未改动')
            save_state(root, state)
            raise
        return {'ok': True, 'migration': state['migration']}


def mark(status, message, **values):
    state = read_state(ROOT)
    job = state.setdefault('migration', {})
    job.update(status=status, message=message, **values)
    if status == 'complete':
        state['choice'] = 'go'
    save_state(ROOT, state)


def download(url, destination, limit):
    request = Request(url, headers={'User-Agent': 'Mx-Panel-migration'})
    with urlopen(request, timeout=60) as source, destination.open('wb') as target:
        size = 0
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError('下载文件超过大小限制')
            target.write(chunk)


def fetch_bundle(stage):
    arch = 'amd64' if platform.machine() == 'x86_64' else 'arm64'
    package = f'mxioc-go-{VERSION}-linux-{arch}.tar.gz'
    archive, sums = stage / package, stage / 'checksums'
    download(f'{RELEASE}/{package}', archive, 256 * 1024 * 1024)
    download(f'{RELEASE}/SHA256SUMS', sums, 16384)
    hashes = [m.group(1) for line in sums.read_text().splitlines()
              if (m := re.fullmatch(r'([0-9a-f]{64})  ' + re.escape(package), line))]
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if len(hashes) != 1 or digest.hexdigest() != hashes[0]:
        raise ValueError('Go 安装包 SHA256 校验失败，未停止旧服务')
    bundle = stage / 'bundle'
    bundle.mkdir()
    expected = {'ARCH', 'VERSION', 'SHA256SUMS', 'index.html', 'install-go.sh', 'mxioc', 'mxioc-go-release.service'}
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        if (len(members) != len(expected) or {m.name for m in members} != expected or
                any(not m.isfile() or m.size > 256 * 1024 * 1024 for m in members)):
            raise ValueError('Go 安装包文件清单或文件类型无效')
        for member in members:
            with tar.extractfile(member) as source, (bundle / member.name).open('wb') as target:
                shutil.copyfileobj(source, target)
    if (bundle / 'VERSION').read_text().strip() != VERSION or (bundle / 'ARCH').read_text().strip() != arch:
        raise ValueError('安装包版本或架构不符')
    (bundle / 'mxioc').chmod(0o700)
    return bundle


def snapshot(backup):
    # Python is stopped; both the program and all mutable data are preserved.
    shutil.copytree(ROOT, backup / 'root', symlinks=True)
    shutil.copy2(AUTH, backup / 'auth.json')
    shutil.copy2(NGINX, backup / 'nginx.conf')
    (backup / 'nginx-path.txt').write_text(str(NGINX) + '\n')
    if SUBSCRIBE.exists():
        shutil.copytree(SUBSCRIBE, backup / 'subscribe', symlinks=True)


def restore_tree(source, destination, suffix):
    staged = destination.with_name(destination.name + '.restore-' + suffix)
    failed = destination.with_name(destination.name + '.failed-' + suffix)
    shutil.copytree(source, staged, symlinks=True)
    if destination.exists():
        destination.rename(failed)
    staged.rename(destination)


def handover():
    import signal
    def interrupted(signum, frame):
        raise RuntimeError('迁移任务被中断')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with LOCK_PATH.open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stopped = False
        install_started = False
        backup_ready = False
        backup = None
        enabled = False
        nginx_text = None
        try:
            preflight()
            enabled = command('systemctl', 'is-enabled', '--quiet', LEGACY, check=False).returncode == 0
            mark('downloading', '正在下载并校验 Go 安装包；Python 仍正常运行')
            with tempfile.TemporaryDirectory(prefix='mx-panel-migrate-') as temporary:
                bundle = fetch_bundle(Path(temporary))
                # Validate while Python is still available; repeat under the installer after stopping it.
                command(bundle / 'mxioc', '--root', ROOT, '--auth', AUTH, '--check-data', timeout=180)
                nginx_text = NGINX.read_text()
                BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
                total = sum(item.stat().st_size for directory in (ROOT, SUBSCRIBE) if directory.exists()
                            for item in directory.rglob('*') if item.is_file() and not item.is_symlink())
                for directory in (BACKUPS, ROOT.parent):
                    if shutil.disk_usage(directory).free < 2 * total + 256 * 1024 * 1024:
                        raise ValueError('备份及恢复预留空间不足，请先清理磁盘')
                backup = Path(tempfile.mkdtemp(prefix='python-to-go-', dir=BACKUPS))
                mark('backup', '正在停止旧服务并备份数据', backupPath=str(backup))
                stopped = True
                command('systemctl', 'stop', LEGACY)
                snapshot(backup)
                backup_ready = True
                command('systemctl', 'disable', LEGACY)
                mark('installing', '备份完成，正在安装并检查 Go 后端', backupPath=str(backup))
                install_started = True
                command('bash', bundle / 'install-go.sh', 'install', timeout=600)
                mark('switching', 'Go 检查通过，正在切换网页转发')
                NGINX.write_text(migrated_nginx(nginx_text))
                command('nginx', '-t')
                command('systemctl', 'reload', 'nginx')
                command('systemctl', 'is-active', '--quiet', GO_SERVICE)
                health = command('curl', '-fsS', '--max-time', '5', 'http://127.0.0.1:62578/healthz')
                if json.loads(health.stdout).get('runtime') != 'go':
                    raise ValueError('切换后的 Go 健康检查失败')
                mark('complete', '迁移完成，请刷新页面并使用原账号重新登录', backupPath=str(backup))
        except BaseException as exc:
            # A second signal must not interrupt recovery halfway through.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            message = '迁移失败：' + str(exc)[:300]
            try:
                if stopped:
                    if install_started:
                        command('systemctl', 'stop', GO_SERVICE, check=False)
                        if command('systemctl', 'is-active', '--quiet', GO_SERVICE, check=False).returncode == 0:
                            raise RuntimeError('无法停止 Go，已保留数据，未启动 Python')
                        command('systemctl', 'disable', GO_SERVICE, check=False)
                        GO_UNIT.unlink(missing_ok=True)
                        (GO_BASE / 'current').unlink(missing_ok=True)
                        if SHORTCUT.exists() and '# Managed by Mx-Panel' in SHORTCUT.read_text():
                            SHORTCUT.unlink()
                    if install_started and backup_ready:
                        suffix = backup.name
                        restore_tree(backup / 'root', ROOT, suffix)
                        if (backup / 'subscribe').exists():
                            restore_tree(backup / 'subscribe', SUBSCRIBE, suffix)
                        shutil.copy2(backup / 'auth.json', AUTH)
                    if install_started and nginx_text is not None:
                        NGINX.write_text(nginx_text)
                        command('nginx', '-t')
                        command('systemctl', 'reload', 'nginx')
                    command('systemctl', 'daemon-reload')
                    if enabled:
                        command('systemctl', 'enable', LEGACY)
                    command('systemctl', 'start', LEGACY)
                    command('systemctl', 'is-active', '--quiet', LEGACY)
                    message += '；已恢复 Python 后端'
                mark('failed', message, backupPath=str(backup or ''))
            except BaseException as recovery:
                mark('recovery-required', message + '；自动恢复未完成，请检查服务器：' + str(recovery)[:250],
                     backupPath=str(backup or ''))
            raise


if __name__ == '__main__' and sys.argv[1:] == ['--run']:
    handover()
