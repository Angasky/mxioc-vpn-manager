import copy
import json
import socket
import ssl
import datetime
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import remote_manager as remote
import server
import paramiko


PIN = "SHA256:" + "a" * 43


class FakeAPI:
    def __init__(self):
        self.configuration = {"outbounds": [{"tag": "direct", "protocol": "freedom"}],
                              "routing": {"rules": [{"type": "field", "outboundTag": "direct", "domain": ["example.com"]}]}}
        self.rows = []
        self.calls = []
        self.fail_restart = False

    def request(self, path, payload=None, **kwargs):
        self.calls.append((path, copy.deepcopy(payload)))
        if path.endswith("getNewX25519Cert"):
            return {"privateKey": "private-test-key", "publicKey": "public-test-key"}
        if path == "panel/xray/":
            return json.dumps({"xraySetting": self.configuration, "outboundTestUrl": "https://example.com"})
        if path == "panel/xray/update":
            self.configuration = json.loads(payload["xraySetting"])
            return None
        if path.endswith("restartXrayService") and self.fail_restart:
            self.fail_restart = False
            raise ValueError("Xray config test failed")
        if path.endswith("inbounds/add"):
            row = {**payload, "id": len(self.rows) + 1, "tag": "inbound-" + str(payload["port"])}
            self.rows.append(row)
            return copy.deepcopy(row)
        if "/inbounds/del/" in path:
            identity = int(path.rsplit("/", 1)[1])
            self.rows = [row for row in self.rows if row["id"] != identity]
        if path.endswith("inbounds/list"):
            return copy.deepcopy(self.rows)
        if "/inbounds/get/" in path:
            return copy.deepcopy(next(row for row in self.rows if row["id"] == int(path.rsplit("/", 1)[1])))
        return None


class RemoteManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manager = remote.RemoteManager(self.root, server.parse_node_link, server.node_to_uri)
        self.payload = {"name": "入口服务器", "host": "198.51.100.20", "sshPort": 22, "sshUser": "root",
                        "sshPassword": "ssh-secret-123", "fingerprint": PIN, "domain": "",
                        "panelUser": "manager", "panelPassword": "panel-secret-123"}
        self.identity = self.manager.save(self.payload)["id"]

    def tearDown(self):
        self.temp.cleanup()

    def test_credentials_are_encrypted_persistent_and_never_returned(self):
        raw = self.manager.path.read_text(encoding="utf-8")
        self.assertNotIn(self.payload["sshPassword"], raw)
        self.assertNotIn(self.payload["panelPassword"], raw)
        public = self.manager.list()[0]
        self.assertNotIn("sshPassword", public)
        self.assertNotIn("panelPassword", public)
        restored = remote.RemoteManager(self.root, server.parse_node_link, server.node_to_uri)
        self.assertEqual(restored.secret(restored.record(self.identity), "sshPassword"), self.payload["sshPassword"])
        restored.save({**self.payload, "id": self.identity, "sshPassword": "", "panelPassword": ""})
        self.assertEqual(restored.secret(restored.record(self.identity), "panelPassword"), self.payload["panelPassword"])

    def test_invalid_targets_domains_ports_and_missing_pin_are_rejected(self):
        invalid = [{"host": "127.0.0.1"}, {"host": "169.254.169.254"}, {"host": "::1"},
                   {"host": "a;id"}, {"sshPort": "22;id"}, {"sshPort": 0}, {"fingerprint": ""},
                   {"domain": "x.example; touch /tmp/oops"}, {"domain": "https://panel.example"},
                   {"panelPassword": "short"}, {"sshPassword": "secret\ncommand"}]
        for bad in invalid:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.manager.save({**self.payload, **bad})
        self.assertEqual(remote.valid_ip("[2001:db8::1]"), "2001:db8::1")

    def test_host_key_mismatch_stops_authentication(self):
        fake = Mock()
        policy = []
        fake.set_missing_host_key_policy.side_effect = policy.append
        key = Mock()
        key.asbytes.return_value = b"a different host key"
        fake.connect.side_effect = lambda *a, **k: policy[0].missing_host_key(fake, "host", key)
        with patch("paramiko.SSHClient", return_value=fake), self.assertRaisesRegex(ValueError, "指纹"):
            self.manager.connect(self.manager.record(self.identity))
        fake.close.assert_called_once()

    def test_real_local_ssh_handshake_pin_and_streaming_execution(self):
        host_key = paramiko.RSAKey.generate(2048)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(8)
        executed = []

        class SSHServer(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                return paramiko.AUTH_SUCCESSFUL if username == "root" and password == "ssh-secret-123" else paramiko.AUTH_FAILED

            def get_allowed_auths(self, username):
                return "password"

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                executed.append(command)

                def respond():
                    script = bytearray()
                    while True:
                        chunk = channel.recv(8192)
                        if not chunk:
                            break
                        script.extend(chunk)
                    executed.append(script.decode())
                    channel.sendall(b"phase one\n")
                    channel.send_stderr(b"diagnostic stderr\n")
                    channel.send_exit_status(0)
                    channel.shutdown_write()

                threading.Thread(target=respond, daemon=True).start()
                return True

        state = {}

        def serve():
            connection, _ = listener.accept()
            transport = paramiko.Transport(connection)
            state["transport"] = transport
            transport.add_server_key(host_key)
            transport.start_server(server=SSHServer())
            state["channel"] = transport.accept(8)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        record = {**self.manager.record(self.identity), "host": "127.0.0.1", "sshPort": listener.getsockname()[1], "fingerprint": remote.fingerprint(host_key)}
        ssh = None
        try:
            ssh = self.manager.connect(record)
            lines = []
            code, output = self.manager.execute(ssh, record, "echo fixture-only", timeout=8, on_line=lines.append)
            self.assertEqual(code, 0)
            self.assertIn("phase one", output)
            self.assertIn("diagnostic stderr", output)
            self.assertEqual(executed[0], b"bash -s")
            self.assertIn("echo fixture-only", executed[1])
        finally:
            if ssh:
                ssh.close()
            if state.get("transport"):
                state["transport"].close()
            listener.close()
            thread.join(3)

    def test_script_modes_and_secret_quoting(self):
        record = copy.deepcopy(self.manager.record(self.identity))
        code = remote.install_script(record, "p'$(touch /tmp/not-executed)")
        self.assertIn("XUI_AUTO=1 bash", code)
        self.assertIn("curl -fLsS --retry 2", code)
        self.assertIn("MXIOC_STAGE=credentials", code)
        self.assertIn("'\"'\"'", code)
        record["domain"] = "panel.example.com"
        self.assertIn("XUI_DOMAIN=panel.example.com bash", remote.install_script(record, "password"))

    def test_cli_panel_url_parsing_ipv6_and_https(self):
        record = {"host": "2001:db8::1", "domain": ""}
        result = remote.parse_panel_settings("port: 2053\nwebBasePath: /secret-path/\ncert: \nkey: \n", record)
        self.assertEqual(result["panelUrl"], "http://[2001:db8::1]:2053/secret-path/")
        record["domain"] = "panel.example.com"
        result = remote.parse_panel_settings("port: 443\nwebBasePath: key\ncert: /root/cert.pem\n", record)
        self.assertEqual(result["panelUrl"], "https://panel.example.com:443/key/")
        with self.assertRaises(ValueError):
            remote.parse_panel_settings("nothing", record)

    def test_logs_redact_secrets_and_identify_real_failure(self):
        source = "\x1b[31mPassword: generated-secret\x1b[0m\nAPI Token: bearer-secret\ncurl: (6) Could not resolve host\n" + self.payload["sshPassword"]
        sanitized = remote.clean_log(source, [self.payload["sshPassword"]])
        for forbidden in ("generated-secret", "bearer-secret", self.payload["sshPassword"], "\x1b"):
            self.assertNotIn(forbidden, sanitized)
        self.assertIn("Could not resolve host", remote.installation_error(sanitized, "download", 6))

    def make_job(self):
        job = {"id": "test-job", "serverId": self.identity, "status": "running", "stage": "connecting", "log": "", "error": ""}
        self.manager.data["jobs"].append(job)
        return job

    def test_install_success_checks_credentials_and_api_before_success(self):
        job, api = self.make_job(), FakeAPI()
        record = copy.deepcopy(self.manager.record(self.identity))

        def panel(ssh, item):
            item.update(panelUrl="http://198.51.100.20:2053/secret/", panelTLS=False)
            return api

        with patch.object(self.manager, "connect", return_value=Mock()), patch.object(self.manager, "execute", return_value=(0, "")), patch.object(self.manager, "panel", side_effect=panel):
            self.manager.install_worker(record, job)
        self.assertEqual(job["status"], "succeeded")
        self.assertEqual(api.calls[0], ("login", {"username": "manager", "password": self.payload["panelPassword"]}))
        self.assertEqual(api.calls[1][0], "panel/api/inbounds/list")
        self.assertIn("panelUrl", job)

    def test_install_failure_keeps_output_and_runs_diagnostics(self):
        job = self.make_job()

        def execute(ssh, record, script, **kwargs):
            kwargs["on_line"]("MXIOC_STAGE=download\ncurl: (6) Could not resolve host\nPassword: random-initial-password\n")
            return 6, ""

        with patch.object(self.manager, "connect", return_value=Mock()), patch.object(self.manager, "execute", side_effect=execute), patch.object(self.manager, "diagnostics", return_value="service: inactive") as diagnostic:
            self.manager.install_worker(copy.deepcopy(self.manager.record(self.identity)), job)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["exitCode"], 6)
        self.assertIn("Could not resolve host", job["error"])
        self.assertIn("inactive", job["log"])
        self.assertNotIn("random-initial-password", job["log"])
        diagnostic.assert_called_once()

    def test_domain_install_without_certificate_is_not_reported_success(self):
        job, api = self.make_job(), FakeAPI()
        record = {**self.manager.record(self.identity), "domain": "panel.example.com"}

        def panel(ssh, item):
            item.update(panelTLS=False, panelUrl="http://198.51.100.20:2053/base/")
            return api

        with patch.object(self.manager, "connect", return_value=Mock()), patch.object(self.manager, "execute", return_value=(0, "")), patch.object(self.manager, "panel", side_effect=panel), patch.object(self.manager, "diagnostics", return_value="certificate failed"):
            self.manager.install_worker(record, job)
        self.assertEqual(job["status"], "failed")
        self.assertIn("证书", job["error"])
        self.assertIn("panelUrl", job)

    def test_restart_marks_jobs_interrupted_and_disallows_overlap(self):
        with patch("remote_manager.threading.Thread"):
            job = self.manager.start_install(self.identity, True)
        with self.assertRaisesRegex(ValueError, "已有安装"):
            self.manager.start_install(self.identity, True)
        with self.assertRaises(ValueError):
            self.manager.remove(self.identity)
        restored = remote.RemoteManager(self.root, server.parse_node_link, server.node_to_uri)
        self.assertEqual(restored.job(job["id"])["status"], "interrupted")
        with self.assertRaises(ValueError):
            restored.start_install(self.identity, False)

    def with_fake_api(self, api):
        return patch.object(self.manager, "with_panel", side_effect=lambda identity, action: action(api, copy.deepcopy(self.manager.record(identity))))

    def test_relay_preserves_existing_config_and_removes_its_own_route(self):
        api = FakeAPI()
        original = copy.deepcopy(api.configuration)
        with self.with_fake_api(api):
            result = self.manager.create_relay(self.identity, {"remark": "中转", "port": 443,
                "landingLink": "socks5://user:password@203.0.113.10:1080#landing"})
            self.assertTrue(result["shareLinks"][0].startswith("vless://"))
            self.assertEqual(api.configuration["routing"]["rules"][1:], original["routing"]["rules"])
            self.assertEqual(api.configuration["outbounds"][0], original["outbounds"][0])
            self.assertEqual(api.configuration["outbounds"][1]["protocol"], "socks")
            saved = self.manager.record(self.identity)["lastXrayBackup"]
            self.assertNotIn('"outbounds"', saved)
            with self.assertRaisesRegex(ValueError, "关联路由"):
                self.manager.update_inbound(self.identity, result["inbound"]["id"],
                                            {**result["inbound"], "port": 8443})
            self.manager.delete_inbound(self.identity, result["inbound"]["id"])
        self.assertEqual(api.configuration, original)
        self.assertEqual(api.rows, [])

    def test_full_panel_address_is_parsed_used_and_preserved(self):
        address = 'https://panel.example.com:13145/riben/'
        saved = self.manager.save({**self.payload, 'id': self.identity, 'installType': 'x-panel',
                                   'connectionMode': 'existing', 'panelAddress': address})
        self.assertEqual(saved['panelAddress'], address)
        record = copy.deepcopy(self.manager.record(self.identity))
        with patch.object(self.manager, 'execute', return_value=(1, 'no api token')) as execute:
            api = self.manager.panel(Mock(), record)
        self.assertEqual(api.record['panelPort'], 13145)
        self.assertEqual(api.record['panelPath'], '/riben/')
        self.assertTrue(api.record['panelTLS'])
        self.assertEqual(api.record['panelUrl'], address)
        execute.assert_not_called()
        self.assertEqual(self.manager.public(self.manager.record(self.identity))['panelAddress'], address)
        self.manager.save({**self.payload, 'id': self.identity, 'installType':'x-panel',
                           'connectionMode':'existing', 'panelAddress':''})
        self.assertNotIn('panelAddress', self.manager.record(self.identity))

    def test_panel_address_validation_and_default_ports(self):
        for url, port, path in [('https://panel.example.com',443,'/'),
                                ('http://198.51.100.1/admin',80,'/admin/'),
                                ('https://[2001:db8::1]:8443/a/',8443,'/a/')]:
            with self.subTest(url=url):
                result = remote.parse_panel_address(url)
                self.assertEqual(result['panelPort'],port)
                self.assertEqual(result['panelPath'],path)
        for url in ['panel.example.com', 'ftp://panel.example.com', 'https://user:pass@panel.example.com/',
                    'https://panel.example.com:0/', 'https://panel.example.com:65536/',
                    'https://panel.example.com/a?token=secret', 'https://panel.example.com/a#section',
                    'https://panel.example.com/%2e%2e/', 'https://panel.example.com/%0d%0a/',
                    'https://panel.example.com/%zz/', 'https://panel.example.com/a b/']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                remote.parse_panel_address(url)
        with self.assertRaisesRegex(ValueError, '仅用于接入'):
            self.manager.save({**self.payload, 'panelAddress':'https://panel.example.com/'})

    def test_attach_existing_preserves_password_and_never_installs(self):
        saved = self.manager.save({**self.payload, "id": self.identity,
                                   "connectionMode": "existing", "panelUser": "a", "panelPassword": "old"})
        self.assertEqual(saved["connectionMode"], "existing")
        api = FakeAPI()
        with self.with_fake_api(api):
            result = self.manager.attach_existing(self.identity)
        self.assertIn("验证成功", result["message"])
        self.assertTrue(result["server"]["existingVerifiedAt"])
        self.assertEqual([path for path, _ in api.calls], ["login", "panel/api/inbounds/list"])
        self.assertEqual(self.manager.secret(self.manager.record(self.identity), "panelPassword"), "old")
        with patch("remote_manager.threading.Thread") as worker, self.assertRaisesRegex(ValueError, "不会执行安装"):
            self.manager.start_install(self.identity, True)
        worker.assert_not_called()

    def test_existing_panel_without_token_uses_session_fallback(self):
        self.manager.save({**self.payload, "id": self.identity, "connectionMode": "existing"})
        record = copy.deepcopy(self.manager.record(self.identity))
        with patch.object(self.manager, "execute", side_effect=[(0, "port: 2053\nwebBasePath: /old/\ncert: \nkey: \n"), (1, "flag provided but not defined: -getApiToken")]):
            api = self.manager.panel(Mock(), record)
        self.assertEqual(api.token, "")
        self.assertEqual(record["panelUrl"], "http://198.51.100.20:2053/old/")

    def test_relay_failure_compensates_inbound_and_config(self):
        api = FakeAPI()
        original = copy.deepcopy(api.configuration)
        api.fail_restart = True
        with self.with_fake_api(api), self.assertRaisesRegex(ValueError, "已撤回"):
            self.manager.create_relay(self.identity, {"remark": "中转", "port": 443,
                "landingLink": "socks5://user:password@203.0.113.10:1080"})
        self.assertEqual(api.configuration, original)
        self.assertEqual(api.rows, [])
        self.assertFalse(self.manager.record(self.identity).get("relays"))

    def test_unsupported_landing_is_rejected_before_connect(self):
        with patch.object(self.manager, "connect") as connection, self.assertRaises(ValueError):
            self.manager.create_relay(self.identity, {"landingLink": "hysteria2://password@203.0.113.10:443"})
        connection.assert_not_called()

    def test_inbound_templates_export_and_validate(self):
        api = FakeAPI()
        for kind in ("vless-reality", "vmess-tcp", "shadowsocks"):
            payload = remote.build_inbound(api, {"remark": "节点", "port": 443, "template": kind})
            nodes = remote.inbound_nodes(payload, self.manager.record(self.identity))
            self.assertEqual(len(nodes), 1)
            self.assertIn("://", server.node_to_uri(nodes[0]))
        with self.assertRaises(ValueError):
            remote.prepare_inbound({"protocol": "vless", "port": 443, "settings": "[]"})

    def test_template_default_port_is_random_high_and_reality_target_is_current(self):
        api=FakeAPI()
        ports=set()
        for _ in range(12):
            body=remote.build_inbound(api, {'remark':'random','template':'vless-reality'})
            self.assertGreater(body['port'],20000);self.assertLessEqual(body['port'],65535)
            ports.add(body['port'])
            self.assertEqual(json.loads(body['streamSettings'])['realitySettings']['target'],'raw.githubusercontent.com:443')
        self.assertGreater(len(ports),1)

    def test_verified_sni_uses_pinned_target_and_expired_result_is_rejected(self):
        import time
        record=self.manager.record(self.identity)
        key=(record['id'],record.get('fingerprint'),'raw.githubusercontent.com','8.8.8.8')
        self.manager.sni_cache[key]=(time.monotonic(),True)
        payload=self.manager.verified_template_payload(record,{'remark':'verified','port':24443,'sniVerified':True})
        body=remote.build_inbound(FakeAPI(),payload)
        reality=json.loads(body['streamSettings'])['realitySettings']
        self.assertEqual(reality['target'],'8.8.8.8:443')
        self.assertEqual(reality['serverNames'],['raw.githubusercontent.com'])
        self.manager.sni_cache.clear()
        with self.assertRaisesRegex(ValueError,'过期'):
            self.manager.verified_template_payload(record,{'sniVerified':True})

    def test_selected_address_is_pinned_and_valid_for_ten_minutes_only(self):
        import time
        record=self.manager.record(self.identity)
        now=time.monotonic()
        prefix=(record['id'],record.get('fingerprint'),'raw.githubusercontent.com')
        self.manager.sni_cache[prefix+('8.8.8.8',)]=(now-300,True)
        self.manager.sni_cache[prefix+('1.1.1.1',)]=(now,True)
        payload={'sniVerified':True,'sniAddress':'8.8.8.8'}
        self.assertEqual(self.manager.verified_template_payload(record,payload)['_verifiedRealityAddress'],'8.8.8.8')
        self.manager.sni_cache[prefix+('8.8.8.8',)]=(now-601,True)
        with self.assertRaisesRegex(ValueError,'过期'):
            self.manager.verified_template_payload(record,payload)


class PanelTunnelTests(unittest.TestCase):
    def test_https_loopback_inside_ssh_tunnel_supports_panel_certificate(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        observed = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append((self.path, self.headers.get('Host')))
                body = b'{"success":true,"obj":[{"id":1}]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        with tempfile.TemporaryDirectory() as temporary:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "panel.example.com")])
            now = datetime.datetime.now(datetime.timezone.utc)
            certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1)).sign(key, hashes.SHA256())
            cert_path, key_path = Path(temporary)/"certificate.pem", Path(temporary)/"private.pem"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            ssh, transport = Mock(), Mock()
            transport.open_channel.side_effect = lambda *a, **k: socket.create_connection(httpd.server_address)
            ssh.get_transport.return_value = transport
            try:
                api = remote.PanelAPI(ssh, {"host":"198.51.100.1", "domain":"panel.example.com", "panelPort":2053, "panelPath":"/secret/", "panelTLS":True}, "token")
                self.assertEqual(api.request("panel/api/inbounds/list"), [{"id":1}])
                supplied = remote.parse_panel_address('https://panel.example.com:13145/riben/')
                api = remote.PanelAPI(ssh, {"host":"198.51.100.1", "domain":"", "panelAddress":supplied['panelUrl'], **supplied}, "token")
                self.assertEqual(api.request("panel/api/inbounds/list"), [{"id":1}])
                self.assertEqual(transport.open_channel.call_args.args[1], ('127.0.0.1',13145))
                self.assertEqual(observed[-1], ('/riben/panel/api/inbounds/list', 'panel.example.com:13145'))
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(3)

    def test_login_fetches_csrf_and_keeps_session_cookie_inside_tunnel(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def reply(self, value):
                body = json.dumps({"success": True, "obj": value}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Set-Cookie", "session=test-session; HttpOnly; Path=/")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                received.append((self.path, None, None))
                if getattr(self.server, "legacy", False):
                    if self.path.endswith("csrf-token"):
                        self.send_error(404)
                        return
                    self.reply([])
                    return
                self.reply("test-csrf")

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, self.headers.get("Cookie"), self.headers.get("X-CSRF-Token")))
                self.reply(None)

            def log_message(self, *_):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        ssh, transport = Mock(), Mock()
        transport.open_channel.side_effect = lambda *a, **k: socket.create_connection(httpd.server_address)
        ssh.get_transport.return_value = transport
        try:
            api = remote.PanelAPI(ssh, {"host": "198.51.100.1", "panelPort": 2053, "panelPath": "/secret/", "panelUser": "admin"}, "api-token", "private-password")
            api.request("panel/xray/", {})
            self.assertEqual(received[0][0], "/secret/csrf-token")
            self.assertEqual(received[1], ("/secret/login", "session=test-session", "test-csrf"))
            self.assertEqual(received[2], ("/secret/panel/xray/", "session=test-session", "test-csrf"))
            api.request("panel/xray/update", {"xraySetting": "{}"})
            self.assertEqual(len(received), 4)
            httpd.legacy = True
            received.clear()
            api = remote.PanelAPI(ssh, {"host": "198.51.100.1", "panelPort": 2053, "panelPath": "/secret/",
                                       "panelUser": "admin", "connectionMode": "existing"}, "", "old-password")
            self.assertEqual(api.request("panel/api/inbounds/list"), [])
            self.assertEqual([row[0] for row in received], ["/secret/csrf-token", "/secret/login", "/secret/panel/api/inbounds/list"])
            self.assertIsNone(received[1][2])
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(3)

    def test_classic_xui_route_fallback_uses_authenticated_read_only_probe(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def reply(self, obj):
                raw = json.dumps({"success": True, "obj": obj}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Set-Cookie", "session=legacy; HttpOnly")
                self.end_headers()
                self.wfile.write(raw)
            def do_GET(self):
                received.append((self.command, self.path))
                if self.path.endswith("csrf-token") or "/panel/api/" in self.path:
                    return self.send_error(404)
                self.reply([])
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                received.append((self.command, self.path))
                self.reply(None)
            def log_message(self, *_):
                pass
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        ssh, transport = Mock(), Mock()
        ssh.get_transport.return_value = transport
        transport.open_channel.side_effect = lambda *args, **kwargs: socket.create_connection(httpd.server_address)
        try:
            api = remote.PanelAPI(ssh, {"host": "198.51.100.2", "panelPort": 2053, "panelPath": "/secret/",
                "panelUser": "admin", "connectionMode": "existing", "installType": "x-ui"}, "", "old-password")
            self.assertEqual(api.request("panel/api/inbounds/list"), [])
            self.assertIn(("GET", "/secret/panel/api/inbounds/list"), received)
            self.assertIn(("GET", "/secret/xui/API/inbounds/list"), received)
            self.assertEqual([p for method, p in received if method == "POST"], ["/secret/login"])
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(3)

    def test_http_api_stays_on_ssh_loopback_and_sends_bearer_and_form(self):
        received = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.update(path=self.path, bearer=self.headers.get("Authorization"), host=self.headers.get("Host"),
                                body=self.rfile.read(int(self.headers["Content-Length"])).decode())
                body = b'{"success":true,"obj":{"ok":true}}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        transport = Mock()
        transport.open_channel.side_effect = lambda *a, **k: socket.create_connection(httpd.server_address)
        ssh = Mock()
        ssh.get_transport.return_value = transport
        try:
            api = remote.PanelAPI(ssh, {"host": "198.51.100.1", "panelPort": 2053, "panelPath": "/secret/"}, "hidden-token")
            self.assertEqual(api.request("panel/api/inbounds/add", {"settings": {"clients": []}, "enable": True}), {"ok": True})
            self.assertEqual(transport.open_channel.call_args.args[1], ("127.0.0.1", 2053))
            self.assertEqual(received["path"], "/secret/panel/api/inbounds/add")
            self.assertEqual(received["bearer"], "Bearer hidden-token")
            self.assertEqual(received["host"], "198.51.100.1:2053")
            self.assertIn("enable=true", received["body"])
            self.assertIn("settings=", received["body"])
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(3)


if __name__ == "__main__":
    unittest.main()
