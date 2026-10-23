import json
import subprocess
import unittest

from reality_probe import probe_batch_script


class BatchRealityProbeTests(unittest.TestCase):
    def config(self, script, tag):
        return json.loads(script.split("<<'" + tag + "'", 1)[1].split('\n', 1)[1].split('\n' + tag, 1)[0])

    def test_batch_uses_two_processes_and_unique_isolated_routes(self):
        targets = [('test-' + str(i) + '.example.com', '8.8.8.8') for i in range(20)]
        script = probe_batch_script(targets)
        subprocess.run(['bash', '-n'], input=script, text=True, check=True, capture_output=True)
        server = self.config(script, 'MXIOC_TEST_SERVER')
        client = self.config(script, 'MXIOC_TEST_CLIENT')
        self.assertEqual(script.count('"$binary" run -config'), 2)
        self.assertEqual(len(server['inbounds']), 20)
        self.assertEqual(len(client['inbounds']), 20)
        self.assertEqual(len(client['routing']['rules']), 20)
        all_ports = [row['port'] for row in server['inbounds'] + client['inbounds']]
        self.assertEqual(len(set(all_ports)), 40)
        self.assertTrue(all(row['listen'] == '127.0.0.1' for row in server['inbounds'] + client['inbounds']))
        for index in range(20):
            source, outbound = server['inbounds'][index], client['outbounds'][index]
            self.assertEqual(source['settings']['clients'][0]['id'], outbound['settings']['vnext'][0]['users'][0]['id'])
            self.assertEqual(source['port'], outbound['settings']['vnext'][0]['port'])
            self.assertEqual(source['streamSettings']['realitySettings']['serverNames'], [targets[index][0]])
            self.assertEqual(client['routing']['rules'][index]['outboundTag'], outbound['tag'])
        self.assertEqual(script.count('for pid in $pids; do wait'), 5)
        self.assertIn('for attempt in 1 2;', script)
        self.assertIn('trap cleanup EXIT', script)
        self.assertNotIn('systemctl', script)
        self.assertNotIn('python', script)
        self.assertNotIn('mktemp', script)
        self.assertNotIn('0.0.0.0', script)

    def test_invalid_and_private_targets_fail_before_execution(self):
        for targets in ([], [('example.com','127.0.0.1')], [('example.com','10.0.0.1')],
                        [('example.com','8.8.8.8')] * 21):
            with self.subTest(targets=len(targets)), self.assertRaises(ValueError):
                probe_batch_script(targets)

    def test_ipv6_target_is_bracketed(self):
        script = probe_batch_script([('example.com','2606:4700:4700::1111')])
        server = self.config(script,'MXIOC_TEST_SERVER')
        self.assertEqual(server['inbounds'][0]['streamSettings']['realitySettings']['target'], '[2606:4700:4700::1111]:443')
