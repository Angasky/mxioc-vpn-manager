import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import certificate_manager as certificates
import remote_manager as remote
import server


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = remote.RemoteManager(Path(self.temp.name), server.parse_node_link, server.node_to_uri)
        self.identity = self.manager.save({'name': 'test', 'host': '198.51.100.20', 'sshUser': 'root', 'sshPassword': 'test-ssh-password', 'fingerprint': 'SHA256:'+'a'*43, 'panelUser':'admin', 'panelPassword': 'test-panel-password'})['id']
        self.record = self.manager.record(self.identity)

    def wait(self, identity):
        deadline = time.monotonic()+3
        while time.monotonic()<deadline:
            job = self.manager.certificate_job(self.identity, job_id=identity)
            if job['status'] in ('succeeded', 'failed'):
                return job
            time.sleep(.01)
        self.fail('worker stuck')

    def test_input_validation_before_remote_execution(self):
        for domain in ('', 'x.example;id', '*.example.com', 'https://example.com', 'example.com/../../'):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                certificates.certificate_script(domain, '198.51.100.20', 'x-ui')
        with self.assertRaises(ValueError):
            certificates.certificate_script('node.example.com', '127.0.0.1', 'x-ui')
        with self.assertRaises(ValueError):
            certificates.certificate_script('node.example.com', '198.51.100.20', 'x-ui;id')

    def test_preparation_failure_has_no_inbound_write(self):
        api = SimpleNamespace(ssh=object(), request=Mock())
        with patch.object(self.manager, 'execute', return_value=(1, '域名解析错误')):
            with self.assertRaisesRegex(ValueError, '域名解析错误'):
                certificates.prepare_certificate(self.manager, api, self.record, {'serverName':'node.example.com'})
        api.request.assert_not_called()

    def test_auto_mode_ignores_supplied_paths_and_checks_job(self):
        from test_remote_manager import FakeAPI
        api = FakeAPI()
        api.ssh = object()
        self.manager.with_panel = lambda identity, action: action(api, self.record)
        payload = {'template':'hysteria2', 'certificateMode':'auto', 'serverName':'node.example.com', 'port':23456, 'certFile':'/bad', 'keyFile':'/bad'}
        with patch.object(self.manager, 'execute', return_value=(0, 'MXIOC_CERT_READY\n')):
            result = self.manager.create_inbound(self.identity, payload)
        tls = json.loads(result['inbound']['streamSettings'])['tlsSettings']
        self.assertEqual(tls['certificates'][0]['certificateFile'], '/etc/mxioc-certificates/node.example.com/fullchain.pem')
        with self.assertRaisesRegex(ValueError, '任务不存在'):
            self.manager.create_inbound(self.identity, {**payload, 'certificateJobId':'missing'})
        self.assertEqual(len(api.rows), 1)

    def test_jobs_deduplicate_bind_server_and_preserve_failure(self):
        started, release = threading.Event(), threading.Event()
        def action(identity, callback):
            started.set()
            release.wait(2)
            raise ValueError('TCP 80 已被占用，未创建节点')
        with patch.object(self.manager, 'with_panel', side_effect=action):
            first = self.manager.certificate_job(self.identity, {'serverName':'node.example.com'})
            self.assertTrue(started.wait(1))
            repeated = self.manager.certificate_job(self.identity, {'serverName':'node.example.com'})
            self.assertEqual(first['id'], repeated['id'])
            with self.assertRaises(ValueError):
                self.manager.certificate_job(self.identity, {'serverName':'other.example.com'})
            release.set()
            result = self.wait(first['id'])
        self.assertEqual(result['status'], 'failed')
        self.assertIn('TCP 80', result['error'])
        self.record['host']='198.51.100.21'
        with self.assertRaisesRegex(ValueError, '连接信息已变化'):
            self.manager.certificate_job(self.identity, job_id=first['id'])

    def test_completed_job_updates_only_domain_metadata(self):
        self.manager.with_panel = lambda identity, action: {'certFile':'/etc/test/fullchain.pem', 'keyFile':'/etc/test/key.pem'}
        job = self.manager.certificate_job(self.identity, {'serverName':'node.example.com'})
        self.assertEqual(self.wait(job['id'])['status'], 'succeeded')
        self.assertEqual(self.manager.list()[0]['certificateDomains'], ['node.example.com'])
        self.assertEqual(self.manager.record(self.identity)['host'], '198.51.100.20')
        self.assertNotIn('privateKey', self.wait(job['id']))
