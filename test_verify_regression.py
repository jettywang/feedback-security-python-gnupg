# -*- coding: utf-8 -*-
"""
Regression tests for verification of artefacts carrying more than one
OpenPGP signature.

They pin down what the three pieces of evidence returned by
:class:`gnupg.Verify` can actually prove:

* ``bool(result)`` (:attr:`gnupg.Verify.valid`) reflects only the *last*
  signature status gpg reported, so for mixed good/bad signatures it depends
  on the order of the status stream.
* ``result.returncode`` is the gpg child process exit code: non-zero means at
  least one signature could not be validated, but a zero code says nothing
  about *which* configured signer signed.
* The per-signature records (``result.signatures`` / ``result.sig_info``) and
  :meth:`gnupg.Verify.is_fingerprint_valid` identify, for each signature, the
  signer and whether the cryptographic checks passed.

The core tests feed fixed, hand-written ``--status-fd`` streams so they are
deterministic and do not need a working gpg-agent. A small set of tests also
drives a fake gpg subprocess end to end, and an optional set uses a real gpg
when an agent (needed to create signatures) is available.
"""
import io
import logging
import os
import shutil
import tempfile
import unittest

import gnupg

logger = logging.getLogger(__name__)

GPGBINARY = os.environ.get('GPGBINARY', 'gpg')

# Fixed identities used in the canned status streams. These are fake test
# fingerprints, never real keys.
ALICE_FP = 'AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111'
BOB_FP = 'BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222'
BOB_SUBKEY_FP = 'CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333'
CAROL_FP = 'DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444'
ALICE_KEYID = ALICE_FP[-16:]
BOB_KEYID = BOB_FP[-16:]
CAROL_KEYID = CAROL_FP[-16:]
ALICE_USER = 'Alice A <alice@example.com>'
BOB_USER = 'Bob B <bob@example.com>'


def status_line(key, value=''):
    return '[GNUPG:] %s %s' % (key, value) if value else '[GNUPG:] %s' % key


def good_signature_stream(fingerprint, keyid, user, pubkey_fingerprint=None):
    """The status-fd lines gpg emits for a fully validated signature."""
    pubkey_fingerprint = pubkey_fingerprint or fingerprint
    return [
        status_line('NEWSIG'),
        status_line('SIG_ID', '%sID 2023-11-14 1700000000' % keyid[:8]),
        status_line('GOODSIG', '%s %s' % (keyid, user)),
        status_line('VALIDSIG', '%s 2023-11-14 1700000000 0 12 11 2 22 109 %s'
                    % (fingerprint, pubkey_fingerprint)),
        status_line('TRUST_ULTIMATE', '4 12 0 0'),
    ]


def bad_signature_stream(keyid, user):
    """A signature whose cryptographic checks fail (e.g. tampered data)."""
    return [
        status_line('NEWSIG'),
        status_line('BADSIG', '%s %s' % (keyid, user)),
    ]


def unknown_key_stream(keyid, fingerprint):
    """A signature gpg cannot check because the public key is absent."""
    return [
        status_line('NEWSIG'),
        status_line('NO_PUBKEY', keyid),
        status_line('ERRSIG', '%s 1 8 00 1700000000 22 %s' % (keyid, fingerprint)),
    ]


def feed_status(gpg, lines):
    """Drive a fresh Verify result through a fixed status stream."""
    result = gnupg.Verify(gpg)
    for line in lines:
        assert line.startswith('[GNUPG:] ')
        payload = line[9:]
        key, _, value = payload.partition(' ')
        result.handle_status(key, value)
    return result


class VerifyStatusStreamTestCase(unittest.TestCase):
    """Deterministic tests against canned --status-fd streams (no subprocess)."""

    def setUp(self):
        self.gpg = gnupg.GPG(gpgbinary=GPGBINARY)

    def make_result(self, *streams):
        lines = []
        for stream in streams:
            lines.extend(stream)
        return feed_status(self.gpg, lines)

    def test_single_good_signature_keeps_legacy_behaviour(self):
        result = self.make_result(good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER))
        self.assertTrue(result)
        self.assertEqual(result.fingerprint, ALICE_FP)
        self.assertEqual(result.status, 'signature valid')
        self.assertEqual(result.trust_text, 'TRUST_ULTIMATE')
        # One signature, one record, no problems: single-signature callers see
        # exactly the same shape as before.
        self.assertEqual(len(result.sig_info), 1)
        self.assertEqual(len(result.signatures), 1)
        self.assertEqual(result.problems, [])
        record = result.signatures[0]
        self.assertEqual(record['fingerprint'], ALICE_FP)
        self.assertEqual(record['status'], 'signature valid')

    def test_good_then_bad_bool_is_false_but_good_signer_still_identifiable(self):
        result = self.make_result(
            good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER),
            bad_signature_stream(BOB_KEYID, BOB_USER),
        )
        # bool() follows the last status reported (BADSIG).
        self.assertFalse(result)
        self.assertEqual(result.status, 'signature bad')
        # ... yet both signatures are recorded individually, and the good one
        # can still be matched against a configured signer fingerprint.
        self.assertEqual(len(result.signatures), 2)
        statuses = [r['status'] for r in result.signatures]
        self.assertEqual(statuses, ['signature valid', 'signature bad'])
        self.assertTrue(result.is_fingerprint_valid(ALICE_FP))
        self.assertFalse(result.is_fingerprint_valid(BOB_FP))
        self.assertEqual(result.valid_fingerprints(), [ALICE_FP])
        self.assertEqual(len(result.problems), 1)
        self.assertEqual(result.problems[0]['keyid'], BOB_KEYID)

    def test_bad_then_good_bool_is_true_showing_bool_is_order_dependent(self):
        # Same two signatures as the previous test, only the order is swapped.
        result = self.make_result(
            bad_signature_stream(BOB_KEYID, BOB_USER),
            good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER),
        )
        # Now bool() is True even though the bad signature is still present.
        self.assertTrue(result)
        self.assertEqual(result.status, 'signature valid')
        # The fingerprint-based judgement is unaffected by ordering.
        self.assertEqual(len(result.signatures), 2)
        statuses = [r['status'] for r in result.signatures]
        self.assertEqual(statuses, ['signature bad', 'signature valid'])
        self.assertTrue(result.is_fingerprint_valid(ALICE_FP))
        self.assertFalse(result.is_fingerprint_valid(BOB_FP))
        self.assertEqual(result.valid_fingerprints(), [ALICE_FP])
        self.assertEqual(len(result.problems), 1)

    def test_two_good_signatures(self):
        result = self.make_result(
            good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER),
            good_signature_stream(BOB_FP, BOB_KEYID, BOB_USER),
        )
        self.assertTrue(result)
        self.assertEqual(len(result.signatures), 2)
        self.assertEqual(set(result.valid_fingerprints()), {ALICE_FP, BOB_FP})
        self.assertTrue(result.is_fingerprint_valid(ALICE_FP))
        self.assertTrue(result.is_fingerprint_valid(BOB_FP))
        self.assertEqual(result.problems, [])

    def test_unknown_public_key_is_recorded_but_never_valid(self):
        result = self.make_result(unknown_key_stream(BOB_KEYID, BOB_FP))
        self.assertFalse(result)
        self.assertEqual(result.status, 'signature error')
        self.assertEqual(len(result.signatures), 1)
        record = result.signatures[0]
        self.assertEqual(record['keyid'], BOB_KEYID)
        self.assertIn(record['status'], ('no public key', 'signature error'))
        self.assertFalse(result.is_fingerprint_valid(BOB_FP))
        self.assertEqual(result.valid_fingerprints(), [])
        problem_statuses = [p['status'] for p in result.problems]
        self.assertIn('no public key', problem_statuses)

    def test_good_and_unknown_mixed(self):
        result = self.make_result(
            good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER),
            unknown_key_stream(BOB_KEYID, BOB_FP),
        )
        self.assertEqual(len(result.signatures), 2)
        self.assertTrue(result.is_fingerprint_valid(ALICE_FP))
        self.assertFalse(result.is_fingerprint_valid(BOB_FP))
        self.assertEqual(result.valid_fingerprints(), [ALICE_FP])

    def test_subkey_signature_is_attributed_to_primary_key(self):
        result = self.make_result(
            good_signature_stream(BOB_SUBKEY_FP, BOB_KEYID, BOB_USER,
                                  pubkey_fingerprint=BOB_FP),
        )
        self.assertTrue(result)
        record = result.signatures[0]
        # The signing subkey fingerprint ...
        self.assertEqual(record['fingerprint'], BOB_SUBKEY_FP)
        # ... plus the primary key fingerprint gpg reports in field 10.
        self.assertEqual(record['pubkey_fingerprint'], BOB_FP)
        # Configuring the *primary* key fingerprint still matches this signature.
        self.assertTrue(result.is_fingerprint_valid(BOB_FP))
        self.assertTrue(result.is_fingerprint_valid(BOB_SUBKEY_FP))
        self.assertFalse(result.is_fingerprint_valid(ALICE_FP))

    def test_fingerprint_match_is_case_insensitive(self):
        result = self.make_result(good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER))
        self.assertTrue(result.is_fingerprint_valid(ALICE_FP.lower()))

    def test_unconfigured_fingerprint_never_matches(self):
        result = self.make_result(good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER))
        self.assertFalse(result.is_fingerprint_valid(CAROL_FP))
        self.assertEqual(result.signatures_for_fingerprint(CAROL_FP), [])

    def test_sig_info_includes_failed_signatures(self):
        # Previously sig_info only held signatures with a SIG_ID (i.e. valid ones);
        # failed signatures now get synthetic keys and appear there too.
        result = self.make_result(
            good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER),
            bad_signature_stream(BOB_KEYID, BOB_USER),
        )
        self.assertEqual(len(result.sig_info), 2)
        self.assertEqual(len(result.signatures), 2)
        bad_records = [r for r in result.signatures if r['status'] == 'signature bad']
        self.assertEqual(len(bad_records), 1)
        self.assertEqual(bad_records[0]['keyid'], BOB_KEYID)


class FakeProcess(object):
    """Minimal stand-in for the subprocess.Popen object GPG expects."""

    def __init__(self, status_lines, returncode, payload=b''):
        stderr_text = '\n'.join(status_lines) + '\n'
        self.stderr = io.BytesIO(stderr_text.encode('ascii'))
        self.stdout = io.BytesIO(payload)
        self.stdin = io.BytesIO()
        self.pid = -1
        self._returncode = returncode

    @property
    def returncode(self):
        return self._returncode

    def wait(self):
        return self._returncode


class VerifySubprocessTestCase(unittest.TestCase):
    """End-to-end tests with a fake gpg, covering the child return code."""

    def _run_verify(self, status_lines, returncode, payload=b''):
        gpg = gnupg.GPG(gpgbinary=GPGBINARY)
        fake = FakeProcess(status_lines, returncode, payload)

        def fake_open(args, passphrase=False):
            return fake

        gpg._open_subprocess = fake_open
        stream = io.BytesIO(b'-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n')
        return gpg.verify_file(stream)

    def test_returncode_nonzero_for_mixed_signatures(self):
        lines = (good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER)
                 + bad_signature_stream(BOB_KEYID, BOB_USER))
        result = self._run_verify(lines, returncode=1)
        # The process exit code records that at least one signature failed ...
        self.assertEqual(result.returncode, 1)
        # ... while the configured good signer can still be positively identified.
        self.assertFalse(result)  # last status was BADSIG
        self.assertTrue(result.is_fingerprint_valid(ALICE_FP))
        self.assertFalse(result.is_fingerprint_valid(BOB_FP))

    def test_returncode_zero_only_proves_process_success(self):
        lines = good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER)
        result = self._run_verify(lines, returncode=0)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result)
        self.assertTrue(result.is_fingerprint_valid(ALICE_FP))
        # A zero return code must not be treated as proof that an arbitrary
        # configured signer signed the artefact.
        self.assertFalse(result.is_fingerprint_valid(CAROL_FP))

    def test_returncode_unknown_key_then_good(self):
        lines = (unknown_key_stream(CAROL_KEYID, CAROL_FP)
                 + good_signature_stream(ALICE_FP, ALICE_KEYID, ALICE_USER))
        result = self._run_verify(lines, returncode=2)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(result.signatures), 2)
        self.assertTrue(result.is_fingerprint_valid(ALICE_FP))
        self.assertFalse(result.is_fingerprint_valid(CAROL_FP))


AGENT_CONFIG = 'allow-loopback-pinentry\n'


def agent_can_create_keys():
    """Return True only if a real gpg-agent can start (Unix sockets allowed)."""
    home = tempfile.mkdtemp(prefix='gpg-agent-probe-')
    try:
        with open(os.path.join(home, 'gpg-agent.conf'), 'w') as f:
            f.write(AGENT_CONFIG)
        probe = gnupg.GPG(gnupghome=home, gpgbinary=GPGBINARY)
        if not probe.version:
            return False
        result = probe.gen_key(probe.gen_key_input(
            **{'Key-Type': 'RSA', 'Key-Length': 1024, 'Name-Real': 'Probe',
               'Name-Email': 'probe@example.com', 'Expire-Date': 0,
               'Passphrase': 'probe-passphrase'}))
        return result.returncode == 0
    except Exception:  # pragma: no cover - environment dependent
        return False
    finally:
        shutil.rmtree(home, ignore_errors=True)


@unittest.skipUnless(agent_can_create_keys(),
                     'gpg-agent cannot create keys in this environment (sockets disabled)')
class RealGPGVerificationTestCase(unittest.TestCase):
    """Integration tests using a real gpg; skipped when no agent is available."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix='keys-')
        os.chmod(self.home, 0o700)
        with open(os.path.join(self.home, 'gpg-agent.conf'), 'w') as f:
            f.write(AGENT_CONFIG)
        self.gpg = gnupg.GPG(gnupghome=self.home, gpgbinary=GPGBINARY)
        self.data = b'release artifact contents'

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def _gen_key(self, name, email, passphrase):
        params = {'Key-Type': 'RSA', 'Key-Length': 1024, 'Name-Real': name,
                  'Name-Email': email, 'Expire-Date': 0, 'Passphrase': passphrase}
        result = self.gpg.gen_key(self.gpg.gen_key_input(**params))
        self.assertEqual(result.returncode, 0)
        return result

    def _detached_sig(self, fingerprint, passphrase):
        return self.gpg.sign(self.data, keyid=fingerprint,
                             passphrase=passphrase, detach=True)

    def _combine_and_verify(self, *signatures):
        fd, fn = tempfile.mkstemp(prefix='pygpg-reg-')
        for sig in signatures:
            os.write(fd, sig.data)
        os.close(fd)
        try:
            return self.gpg.verify_data(fn, self.data)
        finally:
            os.remove(fn)

    def test_real_good_and_bad_combined_signatures(self):
        alice = self._gen_key('Alice A', 'alice@example.com', 'alice-pass')
        bob = self._gen_key('Bob B', 'bob@example.com', 'bob-pass')
        good = self._detached_sig(alice.fingerprint, 'alice-pass')
        # A valid signature over *different* data becomes a BADSIG against self.data.
        bad = self.gpg.sign(b'other data', keyid=bob.fingerprint,
                            passphrase='bob-pass', detach=True)
        result = self._combine_and_verify(good, bad)
        self.assertEqual(len(result.signatures), 2)
        self.assertTrue(result.is_fingerprint_valid(alice.fingerprint))
        self.assertFalse(result.is_fingerprint_valid(bob.fingerprint))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(p['status'] == 'signature bad' for p in result.problems))

    def test_real_two_good_signatures(self):
        alice = self._gen_key('Alice A', 'alice@example.com', 'alice-pass')
        bob = self._gen_key('Bob B', 'bob@example.com', 'bob-pass')
        sig_a = self._detached_sig(alice.fingerprint, 'alice-pass')
        sig_b = self._detached_sig(bob.fingerprint, 'bob-pass')
        result = self._combine_and_verify(sig_a, sig_b)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.is_fingerprint_valid(alice.fingerprint))
        self.assertTrue(result.is_fingerprint_valid(bob.fingerprint))


if __name__ == '__main__':
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
