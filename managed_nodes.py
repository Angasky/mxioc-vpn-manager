"""Local ownership proofs; a remote ID or display name alone is never enough."""
import hashlib
import struct

FIELDS = ('type', 'server', 'port', 'uuid', 'password', 'psk', 'username')


def node_identity(node):
    digest = hashlib.sha256(b'mxioc-node-v1')
    for key in FIELDS:
        value = str(node.get(key) or '').encode('utf-8')
        digest.update(struct.pack('>I', len(value)))
        digest.update(value)
    return digest.hexdigest()


def references(nodes):
    return [{'name': node['name'], 'identity': node_identity(node)} for node in nodes]


def owns_node(binding, node):
    refs = binding.get('importedNodes') or []
    if refs:
        return any(ref.get('identity') == node_identity(node) for ref in refs if isinstance(ref, dict))
    # Upgrade old user bindings using the original email + credential fingerprint.
    # A reused name, inbound ID, port, or another user's UUID never authorizes removal.
    if binding.get('scope') != 'user' or not binding.get('userHash'):
        return False
    if str(node.get('port')) != str(binding.get('port')):
        return False
    from shared_users import user_identity
    kind = node.get('type')
    if kind not in ('vless', 'vmess', 'tuic', 'trojan', 'hysteria2'):
        return False
    client = {'id': node.get('uuid') if kind in ('vless', 'vmess', 'tuic') else None,
              'password': node.get('password') if kind in ('trojan', 'tuic', 'hysteria2') else None,
              'email': binding.get('userEmail')}
    for flow in (node.get('flow'), ''):
        client['flow'] = flow
        if user_identity(client) == binding['userHash']:
            return True
        if kind == 'hysteria2':
            auth = {**client, 'password': None, 'auth': node.get('password')}
            if user_identity(auth) == binding['userHash']:
                return True
    return False
