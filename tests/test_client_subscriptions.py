import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import client_adapter
import server
import test_public_subscriptions as fixtures


class ClientSubscriptionTests(unittest.TestCase):
    def setUp(self):
        fixtures.PublicSubscriptionTests.setUp(self)
        self.nodes=[{'name':'HA / 1','type':'vless','server':'198.51.100.1','port':24443,
                     'uuid':'22453845-ff1a-471d-8214-25952a9348a6','tls':True,'servername':'www.microsoft.com',
                     'reality-opts':{'public-key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','short-id':'001234'}},
                    {'name':'HA / 2','type':'ss','server':'198.51.100.2','port':24443,'cipher':'aes-128-gcm','password':'secret'},
                    {'name':'TUIC','type':'tuic','server':'198.51.100.3','port':443,'uuid':'22453845-ff1a-471d-8214-25952a9348a6','password':'tuic-secret'}]
        doc=server.minimal_profile_config();doc['proxies']=self.nodes
        doc['proxy-groups'].append(server.failover_group('HA',[n['name'] for n in self.nodes[:2]],30))
        server.FILES[0].write_text(server.yaml_dump(doc))
        self.record=server.profile_record()
        self.record['failovers']=[{'name':'HA','paths':[n['name'] for n in self.nodes[:2]],
                                   'entries':['primary','backup'],'exit':'fixed-exit','interval':30,'status':'active'}]
        self.record['serverChains']=[{'name':n['name'],'exit':'fixed-exit','serverId':f's-{i}','inboundId':50} for i,n in enumerate(self.nodes[:2])]
        self.record['remoteNodes']=[{'serverId':f's-{i}','inboundId':50,'status':'active'} for i in range(2)]
        server.update_traffic({'upload':1024,'download':2048,'total':1048576,'expire':1893456000})
        self.base=f'http://127.0.0.1:{self.httpd.server_address[1]}/convert/{self.record["slug"]}/'

    tearDown=fixtures.PublicSubscriptionTests.tearDown

    def test_all_client_formats_preserve_usage_headers_and_head_semantics(self):
        for format_id in server.CONVERSION_FORMATS:
            for method in ('GET','HEAD'):
                with self.subTest(format_id=format_id,method=method):
                    with urlopen(Request(self.base+format_id,method=method),timeout=3) as response:
                        self.assertEqual(response.headers['Subscription-Userinfo'],'upload=1024; download=2048; total=1048576; expire=1893456000')
                        self.assertEqual(response.headers['Cache-Control'],'no-store')
                        self.assertIn('Content-Length',response.headers)
                        if method=='HEAD':self.assertEqual(response.read(),b'')
                        elif format_id.endswith('-ha') and format_id.startswith('v2ray'):
                            configs=json.load(response);self.assertEqual(len(configs),1)
                            self.assertIn('application/json',response.headers['Content-Type'])
                            self.assertIn('.json',response.headers['Content-Disposition'])
                        elif format_id=='shadowrocket-config':
                            self.assertIn('[Proxy Group]',response.read().decode())
                            self.assertIn('.conf',response.headers['Content-Disposition'])
                        else:self.assertIn('://',base64.b64decode(response.read()).decode())

    def test_desktop_usage_label_and_android_protocol_filter_do_not_modify_source(self):
        before=copy.deepcopy(server.read_config())
        desktop,_=server.converted_subscription('clash','v2rayn')
        first=server.parse_node_link(base64.b64decode(desktop).decode().splitlines()[0])
        self.assertIn('已用',first['name'])
        self.assertEqual(first['server'],'127.0.0.1')
        entries=[server.parse_node_link(link) for link in base64.b64decode(desktop).decode().splitlines()]
        self.assertIn('剩余流量',entries[1]['name'])
        self.assertIn('剩余',entries[2]['name'])
        self.assertEqual(entries[3]['name'],self.nodes[0]['name'])
        self.assertEqual(entries[3]['uuid'],self.nodes[0]['uuid'])
        mobile,skipped=server.converted_subscription('clash','v2rayng')
        self.assertEqual(skipped,['TUIC']);self.assertNotIn('tuic://',base64.b64decode(mobile).decode())
        self.assertIn('TUIC',[n['name'] for n in server.read_config()['proxies']])
        self.assertEqual(before,server.read_config())

    def test_usage_nodes_for_all_uri_clients_and_unconfigured_profiles(self):
        for kind in ('v2rayn','v2rayng','v2ray','shadowrocket'):
            body,_=server.converted_subscription('clash',kind)
            entries=[server.parse_node_link(link) for link in base64.b64decode(body).decode().splitlines()]
            self.assertTrue(all(n['server']=='127.0.0.1' and n['port']==9 for n in entries[:3]))
            self.assertEqual(entries[3]['name'],self.nodes[0]['name'])
        self.assertEqual(client_adapter.usage_nodes({'configured':False}),[])

    def test_clash_export_preserves_imported_reality_keyshare(self):
        original = server.FILES[0].read_text()
        doc,text=server.get_cached_config(server.FILES[0])
        self.assertNotIn('support-x25519mlkem768',doc['proxies'][0]['reality-opts'])
        self.assertEqual(text, original)

    def test_shadowrocket_paired_names_match_exactly_without_direct_or_unknown_members(self):
        body,_=server.converted_subscription('clash','shadowrocket-ha')
        names=[server.parse_node_link(link)['name'] for link in base64.b64decode(body).decode().splitlines()]
        self.assertEqual(len(names),2)
        body,_=server.converted_subscription('clash','shadowrocket-config');text=body.decode()
        fallback=next(line for line in text.splitlines() if ' = fallback,' in line)
        members=fallback.split(' = fallback,')[1].split(',')[:2]
        self.assertEqual(members,names)
        self.assertIn('interval=30,timeout=5',fallback)
        self.assertIn('FINAL,MX-Select',text)
        self.assertNotIn('DIRECT',text)

    def test_partial_missing_or_revoked_paths_never_silently_export_reduced_ha_group(self):
        formats=('v2rayn-ha','v2rayng-ha','shadowrocket-ha','shadowrocket-config')
        self.record['remoteNodes'][0]['status']='revoked'
        for format_id in formats:
            with self.subTest(format_id=format_id),self.assertRaises(ValueError):
                server.converted_subscription('clash',format_id)
        report={f['id']:f for f in server.conversion_report()}
        self.assertTrue(all(report[f]['available'] is False for f in formats))
        self.assertTrue(report['v2rayng']['available'])

    def test_expiry_and_quota_deny_every_new_export(self):
        for changes in ({'expire':1},{'expire':1893456000,'total':1}):
            server._update_traffic({'upload':1024,'download':2048,'total':1048576,'enforce':True,**changes})
            for format_id in server.CONVERSION_FORMATS:
                for method in ('GET','HEAD'):
                    with self.subTest(changes=changes,format_id=format_id,method=method),self.assertRaises(HTTPError) as error:
                        urlopen(Request(self.base+format_id,method=method),timeout=3)
                    self.assertEqual(error.exception.code,403)

    def test_shadowrocket_unsafe_names_cannot_inject_configuration(self):
        alias=client_adapter.shadowrocket_name('n,evil=1\n[Rule]\rFINAL,DIRECT;#\\"x')
        for character in ',=\r\n;#[]\\"':self.assertNotIn(character,alias)
        self.assertEqual(alias,client_adapter.shadowrocket_name('n,evil=1\n[Rule]\rFINAL,DIRECT;#\\"x'))
        self.assertNotEqual(alias,client_adapter.shadowrocket_name('n evil 1 Rule FINAL DIRECT x'))

    def test_shadowrocket_names_are_scoped_and_unicode_line_breaks_are_filtered(self):
        a=client_adapter.shadowrocket_name('HA / 1',scope='subscription-a')
        b=client_adapter.shadowrocket_name('HA / 1',scope='subscription-b')
        self.assertNotEqual(a,b)
        unsafe=client_adapter.shadowrocket_name('HA\u0085test\u2028second\u2029third')
        self.assertEqual(len(unsafe.splitlines()),1)

    def test_xray_unsupported_parameters_reject_the_whole_group(self):
        for changes in ({'plugin':'obfs'},{'smux':{'enabled':True}},
                        {'fingerprint':'a'*64},{'ws-opts':{'max-early-data':2048}},
                        {'packet-encoding':'packetaddr'},{'grpc-opts':{'grpc-multi-mode':True}}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                client_adapter.xray_failover('HA',[{**self.nodes[0],**changes},self.nodes[1]],30)

    def test_exports_remain_isolated_after_switching_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            old=server.BACKUP_DIR;server.BACKUP_DIR=Path(directory)
            try:other=server.create_profile({'name':'other'})
            finally:server.BACKUP_DIR=old
        for format_id in ('v2rayn-ha','v2rayng-ha','shadowrocket-ha','shadowrocket-config'):
            with self.assertRaises(ValueError):server.converted_subscription(other['id'],format_id)
        body,_=server.converted_subscription('clash','v2rayng-ha')
        self.assertEqual(json.loads(body)[0]['remarks'].split(' | ')[0],'HA')


@unittest.skipUnless(os.environ.get('MXIOC_XRAY_BIN'),'set MXIOC_XRAY_BIN for native client configuration checks')
class NativeClientConfigTests(unittest.TestCase):
    def test_supported_server_paths_compile_with_real_core(self):
        base={'name':'path','server':'198.51.100.1','port':443,'uuid':'22453845-ff1a-471d-8214-25952a9348a6','password':'secret','cipher':'aes-128-gcm'}
        nodes=[dict(base,type=t,cipher='auto' if t=='vmess' else 'aes-128-gcm') for t in ['vless','vmess','ss','trojan','socks5','http']]
        nodes.append(dict(base,type='vless',tls=True,servername='example.com',**{'reality-opts':{'public-key':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA','short-id':'001234'}}))
        with tempfile.TemporaryDirectory() as directory:
            for node in nodes:
                with self.subTest(kind=node['type'],reality=bool(node.get('reality-opts'))):
                    config=client_adapter.xray_failover('HA',[node,node],30)
                    path=Path(directory)/'config.json';path.write_text(json.dumps(config))
                    result=subprocess.run([os.environ['MXIOC_XRAY_BIN'],'run','-test','-config',str(path)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
