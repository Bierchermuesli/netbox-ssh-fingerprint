from nsf import policy, probe


def test_pq_ready():
    assert policy.assess(kex=['mlkem768x25519-sha256', 'curve25519-sha256']).pq_ready
    assert policy.assess(kex=['sntrup761x25519-sha512@openssh.com']).pq_ready
    assert not policy.assess(kex=['curve25519-sha256', 'ext-info-s']).pq_ready


def test_legacy_cisco():
    result = policy.assess(
        kex=['diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
        host_key_algorithms=['ssh-rsa'],
        ciphers=['aes128-cbc', '3des-cbc', 'aes256-ctr'],
        macs=['hmac-sha1', 'hmac-md5', 'hmac-sha2-256'],
    )
    assert not result.pq_ready
    assert result.weak['kex'] == ['diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1',
                                  'diffie-hellman-group1-sha1']
    assert result.weak['hostkey'] == ['ssh-rsa']
    assert result.weak['cipher'] == ['aes128-cbc', '3des-cbc']
    assert 'mac:hmac-md5' in result.weak_list


def test_modern_has_no_weak():
    result = policy.assess(
        kex=['mlkem768x25519-sha256', 'curve25519-sha256', 'kex-strict-s-v00@openssh.com'],
        host_key_algorithms=['ssh-ed25519', 'rsa-sha2-512'],
        ciphers=['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
        macs=['hmac-sha2-256-etm@openssh.com'],
    )
    assert result.pq_ready and result.weak == {}


def test_modp_primes():
    # RFC 3526 group 14 ends in ...15728E5A 8AACAA68 FFFFFFFF FFFFFFFF; RFC 2409 group 2 in ...FFFFFFFF FFFFFFFF
    p14 = probe._prime(2048)
    assert p14.bit_length() == 2048 and hex(p14).endswith('15728e5a8aacaa68ffffffffffffffff')
    p1 = probe._prime(1024)
    assert p1.bit_length() == 1024 and hex(p1).startswith('0xffffffffffffffffc90fdaa22168c234')
    assert hex(p1).endswith('ffffffffffffffff')


def test_parse_kexinit():
    payload = bytes(16) + b''.join(probe._namelist(n) for n in (
        ['curve25519-sha256'], ['ssh-ed25519'], ['aes128-ctr'], ['aes128-ctr'], ['hmac-sha2-256'],
        ['hmac-sha2-256'], ['none'], ['none'], [], [])) + b'\x00' + bytes(4)
    offer = probe.parse_kexinit(probe._Reader(payload))
    assert offer.kex == ['curve25519-sha256'] and offer.host_key_algorithms == ['ssh-ed25519']
    assert offer.ciphers == ['aes128-ctr'] and offer.macs == ['hmac-sha2-256']
