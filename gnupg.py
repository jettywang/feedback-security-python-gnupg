""" A wrapper for the GnuPG `gpg` command.

Portions of this module are derived from A.M. Kuchling's well-designed
GPG.py, using Richard Jones' updated version 1.3, which can be found
in the pycrypto CVS repository on Sourceforge:

http://pycrypto.cvs.sourceforge.net/viewvc/pycrypto/gpg/GPG.py

This module is *not* forward-compatible with amk's; some of the
old interface has changed.  For instance, since I've added decrypt
functionality, I elected to initialize with a 'gnupghome' argument
instead of 'keyring', so that gpg can find both the public and secret
keyrings.  I've also altered some of the returned objects in order for
the caller to not have to know as much about the internals of the
result classes.

While the rest of ISconf is released under the GPL, I am releasing
this single file under the same terms that A.M. Kuchling used for
pycrypto.

Steve Traugott, stevegt@terraluna.org
Thu Jun 23 21:27:20 PDT 2005

This version of the module has been modified from Steve Traugott's version
(see http://trac.t7a.org/isconf/browser/trunk/lib/python/isconf/GPG.py) by
Vinay Sajip to make use of the subprocess module (Steve's version uses os.fork()
and so does not work on Windows). Renamed to gnupg.py to avoid confusion with
the previous versions.

Modifications Copyright (C) 2008-2026 Vinay Sajip. All rights reserved.

For the full documentation, see https://docs.red-dove.com/python-gnupg/ or
https://gnupg.readthedocs.io/
"""

import codecs
from datetime import datetime
from email.utils import parseaddr
from io import StringIO
import logging
import os
try:
    from queue import Queue, Empty
except ImportError:
    from Queue import Queue, Empty
import re
import socket
from subprocess import Popen, PIPE
import sys
import threading

__version__ = '0.5.8.dev0'
__author__ = 'Vinay Sajip'
__date__ = '$30-Sep-2026 17:36:03$'

STARTUPINFO = None
if os.name == 'nt':  # pragma: no cover
    try:
        from subprocess import STARTUPINFO, STARTF_USESHOWWINDOW, SW_HIDE
    except ImportError:
        STARTUPINFO = None

try:
    unicode
    _py3k = False
    string_types = basestring
    text_type = unicode
    path_types = (bytes, str)
except NameError:
    _py3k = True
    string_types = str
    text_type = str
    path_types = (str, )

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())

# See gh-196: Logging could show sensitive data. It also produces some voluminous
# output. Hence, split into two tiers - stuff that's always logged, and stuff that's
# only logged if log_everything is True. (This is set by the test script.)
#
# For now, only debug logging of chunks falls into the optionally-logged category.
log_everything = False

# We use the test below because it works for Jython as well as CPython
if os.path.__name__ == 'ntpath':  # pragma: no cover
    # On Windows, we don't need shell quoting, other than worrying about
    # paths with spaces in them.
    def shell_quote(s):
        return '"%s"' % s
else:
    # Section copied from sarge

    # This regex determines which shell input needs quoting
    # because it may be unsafe
    UNSAFE = re.compile(r'[^\w%+,./:=@-]')

    def shell_quote(s):
        """
        Quote text so that it is safe for POSIX command shells.

        For example, "*.py" would be converted to "'*.py'". If the text is considered safe it is returned unquoted.

        Args:
            s (str): The value to quote
        Returns:
            str: A safe version of the input, from the point of view of POSIX
                 command shells.
        """
        if not isinstance(s, string_types):  # pragma: no cover
            raise TypeError('Expected string type, got %s' % type(s))
        if not s:  # pragma: no cover
            result = "''"
        elif not UNSAFE.search(s):  # pragma: no cover
            result = s
        else:
            result = "'%s'" % s.replace("'", r"'\''")
        return result

    # end of sarge code

# Now that we use shell=False, we shouldn't need to quote arguments.
# Use no_quote instead of shell_quote to remind us of where quoting
# was needed. However, note that we still need, on 2.x, to encode any
# Unicode argument with the file system encoding - see Issue #41 and
# Python issue #1759845 ("subprocess.call fails with unicode strings in
# command line").

# Allows the encoding used to be overridden in special cases by setting
# this module attribute appropriately.
fsencoding = sys.getfilesystemencoding()


def no_quote(s):
    """
    Legacy function which is a no-op on Python 3.
    """
    if not _py3k and isinstance(s, text_type):
        s = s.encode(fsencoding)
    return s


def _copy_data(instream, outstream, buffer_size, error_queue):
    # Copy one stream to another
    assert buffer_size > 0
    sent = 0
    if hasattr(sys.stdin, 'encoding'):
        enc = sys.stdin.encoding
    else:  # pragma: no cover
        enc = 'ascii'
    while True:
        # See issue #39: read can fail when e.g. a text stream is provided
        # for what is actually a binary file
        try:
            data = instream.read(buffer_size)
        except Exception as e:  # pragma: no cover
            logger.warning('Exception occurred while reading', exc_info=1)
            error_queue.put_nowait(e)
            break
        if not data:
            break
        sent += len(data)
        # logger.debug('sending chunk (%d): %r', sent, data[:256])
        try:
            outstream.write(data)
        except UnicodeError:  # pragma: no cover
            outstream.write(data.encode(enc))
        except Exception as e:  # pragma: no cover
            # Can sometimes get 'broken pipe' errors even when the data has all
            # been sent
            logger.exception('Error sending data')
            error_queue.put_nowait(e)
            break
    try:
        outstream.close()
    except IOError:  # pragma: no cover
        logger.warning('Exception occurred while closing: ignored', exc_info=1)
    logger.debug('closed output, %d bytes sent', sent)


def _threaded_copy_data(instream, outstream, buffer_size, error_queue):
    assert buffer_size > 0
    wr = threading.Thread(target=_copy_data, args=(instream, outstream, buffer_size, error_queue))
    wr.daemon = True
    logger.debug('data copier: %r, %r, %r', wr, instream, outstream)
    wr.start()
    return wr


def _write_passphrase(stream, passphrase, encoding):
    passphrase = '%s\n' % passphrase
    passphrase = passphrase.encode(encoding)
    stream.write(passphrase)
    logger.debug('Wrote passphrase')


def _is_sequence(instance):
    return isinstance(instance, (list, tuple, set, frozenset))


def _make_memory_stream(s):
    try:
        from io import BytesIO
        rv = BytesIO(s)
    except ImportError:  # pragma: no cover
        rv = StringIO(s)
    return rv


def _make_binary_stream(s, encoding):
    if _py3k:
        if isinstance(s, str):
            s = s.encode(encoding)
    else:
        if type(s) is not str:
            s = s.encode(encoding)
    return _make_memory_stream(s)


class StatusHandler(object):
    """
    The base class for handling status messages from `gpg`.
    """

    on_data_failure = None  # set at instance level when failures occur

    def __init__(self, gpg):
        """
        Initialize an instance.

        Args:
            gpg (GPG): The :class:`GPG` instance in use.
        """
        self.gpg = gpg

    def handle_status(self, key, value):
        """
        Handle status messages from the `gpg` child process. These are lines of the format

            [GNUPG:] <key> <value>

        Args:
            key (str): Identifies what the status message is.
            value (str): Identifies additional data, which differs depending on the key.
        """
        raise NotImplementedError


class Verify(StatusHandler):
    """
    This class handles status messages during signature verificaton.
    """

    TRUST_EXPIRED = 0
    TRUST_UNDEFINED = 1
    TRUST_NEVER = 2
    TRUST_MARGINAL = 3
    TRUST_FULLY = 4
    TRUST_ULTIMATE = 5

    TRUST_LEVELS = {
        'TRUST_EXPIRED': TRUST_EXPIRED,
        'TRUST_UNDEFINED': TRUST_UNDEFINED,
        'TRUST_NEVER': TRUST_NEVER,
        'TRUST_MARGINAL': TRUST_MARGINAL,
        'TRUST_FULLY': TRUST_FULLY,
        'TRUST_ULTIMATE': TRUST_ULTIMATE,
    }

    # for now, just the most common error codes. This can be expanded as and
    # when reports come in of other errors.
    GPG_SYSTEM_ERROR_CODES = {
        1: 'permission denied',
        35: 'file exists',
        81: 'file not found',
        97: 'not a directory',
    }

    GPG_ERROR_CODES = {
        11: 'incorrect passphrase',
    }

    returncode = None

    def __init__(self, gpg):
        StatusHandler.__init__(self, gpg)
        self.valid = False
        self.fingerprint = self.creation_date = self.timestamp = None
        self.signature_id = self.key_id = None
        self.username = None
        self.key_id = None
        self.key_status = None
        self.status = None
        self.pubkey_fingerprint = None
        self.expire_timestamp = None
        self.sig_timestamp = None
        self.trust_text = None
        self.trust_level = None
        self.sig_info = {}
        self.problems = []

    def __nonzero__(self):  # pragma: no cover
        return self.valid

    __bool__ = __nonzero__

    def handle_status(self, key, value):

        def update_sig_info(**kwargs):
            sig_id = self.signature_id
            if sig_id:
                info = self.sig_info[sig_id]
                info.update(kwargs)
            else:
                logger.debug('Ignored due to missing sig iD: %s', kwargs)

        if key in self.TRUST_LEVELS:
            self.trust_text = key
            self.trust_level = self.TRUST_LEVELS[key]
            update_sig_info(trust_level=self.trust_level, trust_text=self.trust_text)
            # See Issue #214. Once we see this, we're done with the signature just seen.
            # Zap the signature ID, because we don't see a SIG_ID unless we have a new
            # good signature.
            self.signature_id = None
        elif key in ('WARNING', 'ERROR'):  # pragma: no cover
            logger.warning('potential problem: %s: %s', key, value)
        elif key == 'BADSIG':  # pragma: no cover
            self.valid = False
            self.status = 'signature bad'
            self.key_id, self.username = value.split(None, 1)
            self.problems.append({'status': self.status, 'keyid': self.key_id, 'user': self.username})
            update_sig_info(keyid=self.key_id, username=self.username, status=self.status)
        elif key == 'ERRSIG':  # pragma: no cover
            self.valid = False
            parts = value.split()
            (self.key_id, algo, hash_algo, cls, self.timestamp) = parts[:5]
            # Since GnuPG 2.2.7, a fingerprint is tacked on
            if len(parts) >= 7:
                self.fingerprint = parts[6]
            self.status = 'signature error'
            update_sig_info(keyid=self.key_id,
                            timestamp=self.timestamp,
                            fingerprint=self.fingerprint,
                            status=self.status)
            self.problems.append({
                'status': self.status,
                'keyid': self.key_id,
                'timestamp': self.timestamp,
                'fingerprint': self.fingerprint
            })
        elif key == 'EXPSIG':  # pragma: no cover
            self.valid = False
            self.status = 'signature expired'
            self.key_id, self.username = value.split(None, 1)
            update_sig_info(keyid=self.key_id, username=self.username, status=self.status)
            self.problems.append({'status': self.status, 'keyid': self.key_id, 'user': self.username})
        elif key == 'GOODSIG':
            self.valid = True
            self.status = 'signature good'
            self.key_id, self.username = value.split(None, 1)
            update_sig_info(keyid=self.key_id, username=self.username, status=self.status)
        elif key == 'VALIDSIG':
            parts = value.split()
            fingerprint, creation_date, sig_ts, expire_ts = parts[:4]
            (self.fingerprint, self.creation_date, self.sig_timestamp,
             self.expire_timestamp) = (fingerprint, creation_date, sig_ts, expire_ts)
            # may be different if signature is made with a subkey
            if len(parts) >= 10:
                self.pubkey_fingerprint = parts[9]
            self.status = 'signature valid'
            update_sig_info(fingerprint=fingerprint,
                            creation_date=creation_date,
                            timestamp=sig_ts,
                            expiry=expire_ts,
                            pubkey_fingerprint=self.pubkey_fingerprint,
                            status=self.status)
        elif key == 'SIG_ID':
            sig_id, creation_date, timestamp = value.split()
            self.sig_info[sig_id] = {'creation_date': creation_date, 'timestamp': timestamp}
            (self.signature_id, self.creation_date, self.timestamp) = (sig_id, creation_date, timestamp)
        elif key == 'NO_PUBKEY':  # pragma: no cover
            self.valid = False
            self.key_id = value
            self.status = 'no public key'
            self.problems.append({'status': self.status, 'keyid': self.key_id})
        elif key == 'NO_SECKEY':  # pragma: no cover
            self.valid = False
            self.key_id = value
            self.status = 'no secret key'
            self.problems.append({'status': self.status, 'keyid': self.key_id})
        elif key in ('EXPKEYSIG', 'REVKEYSIG'):  # pragma: no cover
            # signed with expired or revoked key
            self.valid = False
            self.key_id, self.username = value.split(None, 1)
            if key == 'EXPKEYSIG':
                self.key_status = 'signing key has expired'
            else:
                self.key_status = 'signing key was revoked'
            self.status = self.key_status
            update_sig_info(status=self.status, keyid=self.key_id)
            self.problems.append({'status': self.status, 'keyid': self.key_id})
        elif key in ('UNEXPECTED', 'FAILURE'):  # pragma: no cover
            self.valid = False
            if key == 'UNEXPECTED':
                self.status = 'unexpected data'
            else:
                # N.B. there might be other reasons. For example, if an output
                # file can't  be created - /dev/null/foo will lead to a
                # "not a directory" error, but which is not sent as a status
                # message with the [GNUPG:] prefix. Similarly if you try to
                # write to "/etc/foo" as a non-root user, a "permission denied"
                # error will be sent as a non-status message.
                message = 'error - %s' % value
                operation, code = value.rsplit(' ', 1)
                if code.isdigit():
                    code = int(code) & 0xFFFFFF  # lose the error source
                    if self.gpg.error_map and code in self.gpg.error_map:
                        message = '%s: %s' % (operation, self.gpg.error_map[code])
                    else:
                        system_error = bool(code & 0x8000)
                        code = code & 0x7FFF
                        if system_error:
                            mapping = self.GPG_SYSTEM_ERROR_CODES
                        else:
                            mapping = self.GPG_ERROR_CODES
                        if code in mapping:
                            message = '%s: %s' % (operation, mapping[code])
                if not self.status:
                    self.status = message
        elif key == 'NODATA':  # pragma: no cover
            # See issue GH-191
            self.valid = False
            self.status = 'signature expected but not found'
        elif key in ('DECRYPTION_INFO', 'PLAINTEXT', 'PLAINTEXT_LENGTH', 'BEGIN_SIGNING', 'KEY_CONSIDERED'):
            pass
        elif key in ('NEWSIG', ):
            # Only sent in gpg2. Clear any signature ID, to be set by a following SIG_ID
            self.signature_id = None
        else:  # pragma: no cover
            logger.debug('message ignored: %r, %r', key, value)


class ImportResult(StatusHandler):
    """
    This class handles status messages during key import.
    """

    counts = '''count no_user_id imported imported_rsa unchanged n_uids n_subk n_sigs n_revoc sec_read sec_imported
            sec_dups not_imported'''.split()

    returncode = None

    def __init__(self, gpg):
        StatusHandler.__init__(self, gpg)
        self.results = []
        self.fingerprints = []
        for result in self.counts:
            setattr(self, result, 0)

    def __nonzero__(self):
        return bool(not self.not_imported and self.fingerprints)

    __bool__ = __nonzero__

    ok_reason = {
        '0': 'Not actually changed',
        '1': 'Entirely new key',
        '2': 'New user IDs',
        '4': 'New signatures',
        '8': 'New subkeys',
        '16': 'Contains private key',
    }

    problem_reason = {
        '0': 'No specific reason given',
        '1': 'Invalid Certificate',
        '2': 'Issuer Certificate missing',
        '3': 'Certificate Chain too long',
        '4': 'Error storing certificate',
    }

    def handle_status(self, key, value):
        if key in ('WARNING', 'ERROR'):  # pragma: no cover
            logger.warning('potential problem: %s: %s', key, value)
        elif key in ('IMPORTED', 'KEY_CONSIDERED'):
            # this duplicates info we already see in import_ok & import_problem
            pass
        elif key == 'NODATA':  # pragma: no cover
            self.results.append({'fingerprint': None, 'problem': '0', 'text': 'No valid data found'})
        elif key == 'IMPORT_OK':
            reason, fingerprint = value.split()
            reasons = []
            for code, text in list(self.ok_reason.items()):
                if int(reason) | int(code) == int(reason):
                    reasons.append(text)
            reasontext = '\n'.join(reasons) + '\n'
            self.results.append({'fingerprint': fingerprint, 'ok': reason, 'text': reasontext})
            self.fingerprints.append(fingerprint)
        elif key == 'IMPORT_PROBLEM':  # pragma: no cover
            try:
                reason, fingerprint = value.split()
            except Exception:
                reason = value
                fingerprint = '<unknown>'
            self.results.append({'fingerprint': fingerprint, 'problem': reason, 'text': self.problem_reason[reason]})
        elif key == 'IMPORT_RES':
            import_res = value.split()
            for i, count in enumerate(self.counts):
                setattr(self, count, int(import_res[i]))
        elif key == 'KEYEXPIRED':  # pragma: no cover
            self.results.append({'fingerprint': None, 'problem': '0', 'text': 'Key expired'})
        elif key == 'SIGEXPIRED':  # pragma: no cover
            self.results.append({'fingerprint': None, 'problem': '0', 'text': 'Signature expired'})
        elif key == 'FAILURE':  # pragma: no cover
            self.results.append({'fingerprint': None, 'problem': '0', 'text': 'Other failure'})
        else:  # pragma: no cover
            logger.debug('message ignored: %s, %s', key, value)

    def summary(self):
        """
        Return a summary indicating how many keys were imported and how many were not imported.
        """
        result = []
        result.append('%d imported' % self.imported)
        if self.not_imported:  # pragma: no cover
            result.append('%d not imported' % self.not_imported)
        return ', '.join(result)


# Full fingerprints only: 32 hex chars (v3), 40 (v4) or 64 (v5). Short or
# long key IDs are never acceptable where a fingerprint is required.
_FULL_FINGERPRINT_RE = re.compile(r'^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$', re.I)

# Messages written by gpg to stderr when key material can't be fully parsed.
# These indicate truncated or otherwise corrupt key data (a "mid-way" error),
# as opposed to keys which are merely unusable.
_IMPORT_DATA_ERROR_RE = re.compile(r'invalid packet|read error|no valid OpenPGP data|'
                                   r'invalid keyring|import from .* failed|premature end|'
                                   r'truncated', re.I)


def _normalize_fingerprint(fp):
    """
    Normalize a full fingerprint to uppercase hex, tolerating a ``0x`` prefix
    and embedded spaces. Anything which isn't a full fingerprint (e.g. a key
    ID) is rejected with a ``ValueError``.
    """
    if not isinstance(fp, string_types):
        raise ValueError('Not a valid fingerprint: %r' % (fp, ))
    s = fp.strip()
    if s[:2].lower() == '0x':
        s = s[2:]
    s = s.replace(' ', '').upper()
    if not _FULL_FINGERPRINT_RE.match(s):
        raise ValueError('Not a full fingerprint: %r' % (fp, ))
    return s


def _is_full_fingerprint(fp):
    "Return True if fp looks like a full fingerprint."
    return bool(fp) and bool(_FULL_FINGERPRINT_RE.match(fp))


def _contains_secret_key_material(key_data):
    "Check armored key data for secret/secret-key blocks."
    if isinstance(key_data, bytes):
        return b'PRIVATE KEY BLOCK' in key_data or b'SECRET KEY BLOCK' in key_data
    return 'PRIVATE KEY BLOCK' in key_data or 'SECRET KEY BLOCK' in key_data


def _controlled_import_problem(import_result):
    """
    Examine an ImportResult for problems relating to the key *data* (as
    opposed to environmental issues such as a missing agent). Returns a
    ``(reason, message)`` tuple, or ``None`` if no problem was found.
    """
    stderr = import_result.stderr or ''
    if _IMPORT_DATA_ERROR_RE.search(stderr):
        return ('invalid-key-data', 'key data could not be fully parsed')
    if import_result.sec_read or import_result.sec_imported:
        return ('secret-material', 'key data contains secret key material')
    if import_result.not_imported:
        return ('invalid-key-data', '%d key(s) could not be imported' % import_result.not_imported)
    for entry in import_result.results:
        if 'ok' in entry and int(entry['ok']) & 16:
            return ('secret-material', 'key data contains secret key material')
        if entry.get('fingerprint') and 'problem' in entry:
            return ('invalid-key-data',
                    'key %s could not be imported: %s' % (entry['fingerprint'], entry.get('text')))
    return None


class ControlledImportResult(ImportResult):
    """
    The result of a fingerprint-controlled import (see
    :meth:`GPG.import_keys_controlled`).

    In addition to the usual :class:`ImportResult` attributes (which describe
    the actual import, if one was performed), an instance of this class
    carries a ``report`` dictionary describing the candidate key material and
    the policy decision. Report entries can also be accessed as attributes
    (e.g. ``result.primary_keys``) or as items (e.g. ``result['updates']``).
    """

    def __init__(self, gpg):
        ImportResult.__init__(self, gpg)
        self.report = {}
        self.rejected = False
        self.reason = None
        self.errors = []
        self.dry_run = False
        self.status = 'pending'

    def __nonzero__(self):
        return not self.rejected and ImportResult.__nonzero__(self)

    __bool__ = __nonzero__

    def __getattr__(self, name):
        # Only called when normal attribute lookup fails, so report entries
        # can be read as attributes without shadowing real attributes.
        try:
            return self.__dict__['report'][name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, key):
        return self.report[key]

    def __contains__(self, key):
        return key in self.report

    def get(self, key, default=None):
        return self.report.get(key, default)

    def summary(self):
        """
        Return a summary of the controlled import.
        """
        if self.rejected:
            return 'rejected: %s' % (self.reason or 'unknown reason')
        if self.dry_run:
            return 'validated (dry run - nothing imported)'
        return ImportResult.summary(self)


ESCAPE_PATTERN = re.compile(r'\\x([0-9a-f][0-9a-f])', re.I)
BASIC_ESCAPES = {
    r'\n': '\n',
    r'\r': '\r',
    r'\f': '\f',
    r'\v': '\v',
    r'\b': '\b',
    r'\0': '\0',
}


class SendResult(StatusHandler):
    """
    This class handles status messages during key sending.
    """

    returncode = None

    def handle_status(self, key, value):
        logger.debug('SendResult: %s: %s', key, value)


def _set_fields(target, fieldnames, args):
    for i, var in enumerate(fieldnames):
        if i < len(args):
            target[var] = args[i]
        else:
            target[var] = 'unavailable'


class SearchKeys(StatusHandler, list):
    """
    This class handles status messages during key search.
    """

    # Handle pub and uid (relating the latter to the former).
    # Don't care about the rest

    UID_INDEX = 1
    FIELDS = 'type keyid algo length date expires'.split()
    returncode = None

    def __init__(self, gpg):
        StatusHandler.__init__(self, gpg)
        self.curkey = None
        self.fingerprints = []
        self.uids = []
        self.uid_map = {}

    def get_fields(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        result = {}
        _set_fields(result, self.FIELDS, args)
        result['uids'] = []
        result['sigs'] = []
        return result

    def pub(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        self.curkey = curkey = self.get_fields(args)
        self.append(curkey)

    def uid(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        uid = args[self.UID_INDEX]
        uid = ESCAPE_PATTERN.sub(lambda m: chr(int(m.group(1), 16)), uid)
        for k, v in BASIC_ESCAPES.items():
            uid = uid.replace(k, v)
        self.curkey['uids'].append(uid)
        self.uids.append(uid)
        uid_data = {}
        self.uid_map[uid] = uid_data
        for fn, fv in zip(self.FIELDS, args):
            uid_data[fn] = fv

    def handle_status(self, key, value):  # pragma: no cover
        pass


class ListKeys(SearchKeys):
    """
    This class handles status messages during listing keys and signatures.

    Handle pub and uid (relating the latter to the former).

    We don't care about (info from GnuPG DETAILS file):

    crt = X.509 certificate
    crs = X.509 certificate and private key available
    uat = user attribute (same as user id except for field 10).
    sig = signature
    rev = revocation signature
    pkd = public key data (special field format, see below)
    grp = reserved for gpgsm
    rvk = revocation key
    """

    UID_INDEX = 9
    FIELDS = ('type trust length algo keyid date expires dummy ownertrust uid sig'
              ' cap issuer flag token hash curve compliance updated origin keygrip').split()

    def __init__(self, gpg):
        super(ListKeys, self).__init__(gpg)
        self.in_subkey = False
        self.key_map = {}

    def key(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        self.curkey = curkey = self.get_fields(args)
        if curkey['uid']:  # pragma: no cover
            curkey['uids'].append(curkey['uid'])
        del curkey['uid']
        curkey['subkeys'] = []
        self.append(curkey)
        self.in_subkey = False

    pub = sec = key

    def fpr(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        fp = args[9]
        if fp in self.key_map and self.gpg.check_fingerprint_collisions:  # pragma: no cover
            raise ValueError('Unexpected fingerprint collision: %s' % fp)
        if not self.in_subkey:
            self.curkey['fingerprint'] = fp
            self.fingerprints.append(fp)
            self.key_map[fp] = self.curkey
        else:
            self.curkey['subkeys'][-1][2] = fp
            self.key_map[fp] = self.curkey

    def grp(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        grp = args[9]
        if not self.in_subkey:
            self.curkey['keygrip'] = grp
        else:
            self.curkey['subkeys'][-1][3] = grp

    def _collect_subkey_info(self, curkey, args):
        info_map = curkey.setdefault('subkey_info', {})
        info = {}
        _set_fields(info, self.FIELDS, args)
        info_map[args[4]] = info

    def sub(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        # See issue #81. We create a dict with more information about
        # subkeys, but for backward compatibility reason, have to add it in
        # as a separate entry 'subkey_info'
        subkey = [args[4], args[11], None, None]  # keyid, type, fp, grp
        self.curkey['subkeys'].append(subkey)
        self._collect_subkey_info(self.curkey, args)
        self.in_subkey = True

    def ssb(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        subkey = [args[4], None, None, None]  # keyid, type, fp, grp
        self.curkey['subkeys'].append(subkey)
        self._collect_subkey_info(self.curkey, args)
        self.in_subkey = True

    def sig(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        # keyid, uid, sigclass
        self.curkey['sigs'].append((args[4], args[9], args[10]))


class ScanKeys(ListKeys):
    """
    This class handles status messages during scanning keys.
    """

    def sub(self, args):
        """
        Internal method used to update the instance from a `gpg` status message.
        """
        # --with-fingerprint --with-colons somehow outputs fewer colons,
        # use the last value args[-1] instead of args[11]
        subkey = [args[4], args[-1], None, None]
        self.curkey['subkeys'].append(subkey)
        self._collect_subkey_info(self.curkey, args)
        self.in_subkey = True


class TextHandler(object):

    def _as_text(self):
        return self.data.decode(self.gpg.encoding, self.gpg.decode_errors)

    if _py3k:
        __str__ = _as_text
    else:
        __unicode__ = _as_text

        def __str__(self):
            return self.data


_INVALID_KEY_REASONS = {
    0: 'no specific reason given',
    1: 'not found',
    2: 'ambiguous specification',
    3: 'wrong key usage',
    4: 'key revoked',
    5: 'key expired',
    6: 'no crl known',
    7: 'crl too old',
    8: 'policy mismatch',
    9: 'not a secret key',
    10: 'key not trusted',
    11: 'missing certificate',
    12: 'missing issuer certificate',
    13: 'key disabled',
    14: 'syntax error in specification',
}


def _determine_invalid_recipient_or_signer(s):  # pragma: no cover
    parts = s.split()
    if len(parts) >= 2:
        code, ident = parts[:2]
    else:
        code = parts[0]
        ident = '<no ident>'
    unexpected = 'unexpected return code %r' % code
    try:
        key = int(code)
        result = _INVALID_KEY_REASONS.get(key, unexpected)
    except ValueError:
        result = unexpected
    return '%s:%s' % (result, ident)


class Crypt(Verify, TextHandler):
    """
    This class handles status messages during encryption and decryption.
    """

    def __init__(self, gpg):
        Verify.__init__(self, gpg)
        self.data = ''
        self.ok = False
        self.status = ''
        self.status_detail = ''
        self.key_id = None

    def __nonzero__(self):
        return bool(self.ok)

    __bool__ = __nonzero__

    def handle_status(self, key, value):
        if key in ('WARNING', 'ERROR'):
            logger.warning('potential problem: %s: %s', key, value)
        elif key == 'NODATA':
            if self.status not in ('decryption failed', ):
                self.status = 'no data was provided'
        elif key in ('NEED_PASSPHRASE', 'BAD_PASSPHRASE', 'GOOD_PASSPHRASE', 'MISSING_PASSPHRASE', 'KEY_NOT_CREATED',
                     'NEED_PASSPHRASE_PIN'):  # pragma: no cover
            self.status = key.replace('_', ' ').lower()
        elif key == 'DECRYPTION_FAILED':  # pragma: no cover
            if self.status != 'no secret key':  # don't overwrite more useful message
                self.status = 'decryption failed'
        elif key == 'NEED_PASSPHRASE_SYM':
            self.status = 'need symmetric passphrase'
        elif key == 'BEGIN_DECRYPTION':
            if self.status != 'no secret key':  # don't overwrite more useful message
                self.status = 'decryption incomplete'
        elif key == 'BEGIN_ENCRYPTION':
            self.status = 'encryption incomplete'
        elif key == 'DECRYPTION_OKAY':
            self.status = 'decryption ok'
            self.ok = True
        elif key == 'END_ENCRYPTION':
            self.status = 'encryption ok'
            self.ok = True
        elif key == 'INV_RECP':  # pragma: no cover
            if not self.status:
                self.status = 'invalid recipient'
            else:
                self.status = 'invalid recipient: %s' % self.status
            self.status_detail = _determine_invalid_recipient_or_signer(value)
        elif key == 'KEYEXPIRED':  # pragma: no cover
            self.status = 'key expired'
        elif key == 'SIG_CREATED':  # pragma: no cover
            self.status = 'sig created'
        elif key == 'SIGEXPIRED':  # pragma: no cover
            self.status = 'sig expired'
        elif key == 'ENC_TO':  # pragma: no cover
            # ENC_TO <long_keyid> <keytype> <keylength>
            self.key_id = value.split(' ', 1)[0]
        elif key in ('USERID_HINT', 'GOODMDC', 'END_DECRYPTION', 'CARDCTRL', 'BADMDC', 'SC_OP_FAILURE',
                     'SC_OP_SUCCESS', 'PINENTRY_LAUNCHED'):
            pass
        else:
            Verify.handle_status(self, key, value)


class GenKey(StatusHandler):
    """
    This class handles status messages during key generation.
    """

    returncode = None

    def __init__(self, gpg):
        StatusHandler.__init__(self, gpg)
        self.type = None
        self.fingerprint = ''
        self.status = None

    def __nonzero__(self):  # pragma: no cover
        return bool(self.fingerprint)

    __bool__ = __nonzero__

    def __str__(self):  # pragma: no cover
        return self.fingerprint

    def handle_status(self, key, value):
        if key in ('WARNING', 'ERROR'):  # pragma: no cover
            logger.warning('potential problem: %s: %s', key, value)
        elif key == 'KEY_CREATED':
            parts = value.split()
            (self.type, self.fingerprint) = parts[:2]
            self.status = 'ok'
        elif key == 'KEY_NOT_CREATED':
            self.status = key.replace('_', ' ').lower()
        elif key in ('PROGRESS', 'GOOD_PASSPHRASE'):  # pragma: no cover
            pass
        else:  # pragma: no cover
            logger.debug('message ignored: %s, %s', key, value)


class AddSubkey(StatusHandler):
    """
    This class handles status messages during subkey addition.
    """

    returncode = None

    def __init__(self, gpg):
        StatusHandler.__init__(self, gpg)
        self.type = None
        self.fingerprint = ''
        self.status = None

    def __nonzero__(self):  # pragma: no cover
        return bool(self.fingerprint)

    __bool__ = __nonzero__

    def __str__(self):
        return self.fingerprint

    def handle_status(self, key, value):
        if key in ('WARNING', 'ERROR'):  # pragma: no cover
            logger.warning('potential problem: %s: %s', key, value)
        elif key == 'KEY_CREATED':
            (self.type, self.fingerprint) = value.split()
            self.status = 'ok'
        else:  # pragma: no cover
            logger.debug('message ignored: %s, %s', key, value)


class ExportResult(GenKey):
    """
    This class handles status messages during key export.
    """

    # For now, just use an existing class to base it on - if needed, we
    # can override handle_status for more specific message handling.

    def handle_status(self, key, value):
        if key in ('EXPORTED', 'EXPORT_RES'):
            pass
        else:
            super(ExportResult, self).handle_status(key, value)


class DeleteResult(StatusHandler):
    """
    This class handles status messages during key deletion.
    """

    returncode = None

    def __init__(self, gpg):
        StatusHandler.__init__(self, gpg)
        self.status = 'ok'

    def __str__(self):
        return self.status

    problem_reason = {
        '1': 'No such key',
        '2': 'Must delete secret key first',
        '3': 'Ambiguous specification',
    }

    def handle_status(self, key, value):
        if key == 'DELETE_PROBLEM':  # pragma: no cover
            self.status = self.problem_reason.get(value, 'Unknown error: %r' % value)
        else:  # pragma: no cover
            logger.debug('message ignored: %s, %s', key, value)

    def __nonzero__(self):  # pragma: no cover
        return self.status == 'ok'

    __bool__ = __nonzero__


class TrustResult(DeleteResult):
    """
    This class handles status messages during key trust setting.
    """
    pass


class Sign(StatusHandler, TextHandler):
    """
    This class handles status messages during signing.
    """

    returncode = None

    def __init__(self, gpg):
        StatusHandler.__init__(self, gpg)
        self.type = None
        self.hash_algo = None
        self.fingerprint = None
        self.status = None
        self.status_detail = None
        self.key_id = None
        self.username = None

    def __nonzero__(self):
        return self.fingerprint is not None

    __bool__ = __nonzero__

    def handle_status(self, key, value):
        if key in ('WARNING', 'ERROR', 'FAILURE'):  # pragma: no cover
            logger.warning('potential problem: %s: %s', key, value)
        elif key in ('KEYEXPIRED', 'SIGEXPIRED'):  # pragma: no cover
            self.status = 'key expired'
        elif key == 'KEYREVOKED':  # pragma: no cover
            self.status = 'key revoked'
        elif key == 'SIG_CREATED':
            (self.type, algo, self.hash_algo, cls, self.timestamp, self.fingerprint) = value.split()
            self.status = 'signature created'
        elif key == 'USERID_HINT':  # pragma: no cover
            self.key_id, self.username = value.split(' ', 1)
        elif key == 'BAD_PASSPHRASE':  # pragma: no cover
            self.status = 'bad passphrase'
        elif key in ('INV_SGNR', 'INV_RECP'):  # pragma: no cover
            # INV_RECP is returned in older versions
            if not self.status:
                self.status = 'invalid signer'
            else:
                self.status = 'invalid signer: %s' % self.status
            self.status_detail = _determine_invalid_recipient_or_signer(value)
        elif key in ('NEED_PASSPHRASE', 'GOOD_PASSPHRASE', 'BEGIN_SIGNING'):
            pass
        else:  # pragma: no cover
            logger.debug('message ignored: %s, %s', key, value)


class AutoLocateKey(StatusHandler):
    """
    This class handles status messages during key auto-locating.
    fingerprint: str
    key_length: int
    created_at: date
    email: str
    email_real_name: str
    """

    def __init__(self, gpg):
        StatusHandler.__init__(self, gpg)
        self.fingerprint = None
        self.type = None
        self.created_at = None
        self.email = None
        self.email_real_name = None

    def handle_status(self, key, value):
        if key == "IMPORTED":
            _, email, display_name = value.split()

            self.email = email
            self.email_real_name = display_name[1:-1]
        elif key == "KEY_CONSIDERED":
            self.fingerprint = value.strip().split()[0]

    def pub(self, args):
        """
        Internal method to handle the 'pub' status message.
        `pub` message contains the fingerprint of the public key, its type and its creation date.
        """
        pass

    def uid(self, args):
        self.created_at = datetime.fromtimestamp(int(args[5]))
        raw_email_content = args[9]
        email, real_name = parseaddr(raw_email_content)
        self.email = email
        self.email_real_name = real_name

    def sub(self, args):
        self.key_length = int(args[2])

    def fpr(self, args):
        # Only store the first fingerprint
        self.fingerprint = self.fingerprint or args[9]


VERSION_RE = re.compile(r'\bcfg:version:(\d+(\.\d+)*)'.encode('ascii'))
HEX_DIGITS_RE = re.compile(r'[0-9a-f]+$', re.I)
PUBLIC_KEY_RE = re.compile(r'gpg: public key is (\w+)')


class GPG(object):
    """
    This class provides a high-level programmatic interface for `gpg`.
    """
    error_map = None

    decode_errors = 'strict'

    buffer_size = 16384  # override in instance if needed

    result_map = {
        'crypt': Crypt,
        'delete': DeleteResult,
        'generate': GenKey,
        'addSubkey': AddSubkey,
        'import': ImportResult,
        'send': SendResult,
        'list': ListKeys,
        'scan': ScanKeys,
        'search': SearchKeys,
        'sign': Sign,
        'trust': TrustResult,
        'verify': Verify,
        'export': ExportResult,
        'auto-locate-key': AutoLocateKey,
    }
    "A map of GPG operations to result object types."

    def __init__(self,
                 gpgbinary='gpg',
                 gnupghome=None,
                 verbose=False,
                 use_agent=False,
                 keyring=None,
                 options=None,
                 secret_keyring=None,
                 env=None,
                 encoding='latin-1'):
        """Initialize a GPG process wrapper.

        Args:
            gpgbinary (str): A pathname for the GPG binary to use.

            gnupghome (str): A pathname to where we can find the public and private keyrings. The default is
                             whatever `gpg` defaults to.

            keyring (str|list): The name of alternative keyring file to use, or a list of such keyring files. If
                                specified, the default keyring is not used.

            options (list): A list of additional options to pass to the GPG binary.

            secret_keyring (str|list): The name of an alternative secret keyring file to use, or a list of such
                                       keyring files.

            env (dict): A dict of environment variables to be used for the GPG subprocess.
        """
        self.gpgbinary = gpgbinary
        self.gnupghome = gnupghome
        self.env = env
        # issue 112: fail if the specified value isn't a directory
        if gnupghome and not os.path.isdir(gnupghome):
            raise ValueError('gnupghome should be a directory (it isn\'t): %s' % gnupghome)
        if keyring:
            # Allow passing a string or another iterable. Make it uniformly
            # a list of keyring filenames
            if isinstance(keyring, string_types):
                keyring = [keyring]
        self.keyring = keyring
        if secret_keyring:  # pragma: no cover
            # Allow passing a string or another iterable. Make it uniformly
            # a list of keyring filenames
            if isinstance(secret_keyring, string_types):
                secret_keyring = [secret_keyring]
        self.secret_keyring = secret_keyring
        self.verbose = verbose
        self.use_agent = use_agent
        if isinstance(options, str):  # pragma: no cover
            options = [options]
        self.options = options
        self.on_data = None  # or a callable - will be called with data chunks
        # Changed in 0.3.7 to use Latin-1 encoding rather than
        # locale.getpreferredencoding falling back to sys.stdin.encoding
        # falling back to utf-8, because gpg itself uses latin-1 as the default
        # encoding. Changed in 0.5.7 to use a new kwarg defaulting to Latin-1.
        self.encoding = encoding
        if gnupghome and not os.path.isdir(self.gnupghome):  # pragma: no cover
            os.makedirs(self.gnupghome, 0o700)
        try:
            p = self._open_subprocess(['--list-config', '--with-colons'])
        except OSError:
            msg = 'Unable to run gpg (%s) - it may not be available.' % self.gpgbinary
            logger.exception(msg)
            raise OSError(msg)
        result = self.result_map['verify'](self)  # any result will do for this
        self._collect_output(p, result, stdin=p.stdin)
        if p.returncode != 0:  # pragma: no cover
            raise ValueError('Error invoking gpg: %s: %s' % (p.returncode, result.stderr))
        m = VERSION_RE.search(result.data)
        if not m:  # pragma: no cover
            self.version = None
        else:
            dot = '.'.encode('ascii')
            self.version = tuple([int(s) for s in m.groups()[0].split(dot)])

        # See issue #97. It seems gpg allow duplicate keys in keyrings, so we
        # can't be too strict.
        self.check_fingerprint_collisions = False

    def make_args(self, args, passphrase):
        """
        Make a list of command line elements for GPG. The value of ``args``
        will be appended. The ``passphrase`` argument needs to be True if
        a passphrase will be sent to `gpg`, else False.

        Args:
            args (list[str]): A list of arguments.
            passphrase (str): The passphrase to use.
        """
        cmd = [self.gpgbinary, '--status-fd', '2', '--no-tty', '--no-verbose']
        if 'DEBUG_IPC' in os.environ:  # pragma: no cover
            cmd.extend(['--debug', 'ipc'])
        if passphrase and hasattr(self, 'version'):
            if self.version >= (2, 1):
                cmd[1:1] = ['--pinentry-mode', 'loopback']
        cmd.extend(['--fixed-list-mode', '--batch', '--with-colons'])
        if self.gnupghome:
            cmd.extend(['--homedir', no_quote(self.gnupghome)])
        if self.keyring:
            cmd.append('--no-default-keyring')
            for fn in self.keyring:
                cmd.extend(['--keyring', no_quote(fn)])
        if self.secret_keyring:  # pragma: no cover
            for fn in self.secret_keyring:
                cmd.extend(['--secret-keyring', no_quote(fn)])
        if passphrase:
            cmd.extend(['--passphrase-fd', '0'])
        if self.use_agent:  # pragma: no cover
            cmd.append('--use-agent')
        if self.options:
            cmd.extend(self.options)
        cmd.extend(args)
        return cmd

    def _open_subprocess(self, args, passphrase=False):
        # Internal method: open a pipe to a GPG subprocess and return
        # the file objects for communicating with it.

        from subprocess import list2cmdline as debug_print

        cmd = self.make_args(args, passphrase)
        if self.verbose:  # pragma: no cover
            print(debug_print(cmd))
        if not STARTUPINFO:
            si = None
        else:  # pragma: no cover
            si = STARTUPINFO()
            si.dwFlags = STARTF_USESHOWWINDOW
            si.wShowWindow = SW_HIDE
        result = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE, startupinfo=si, env=self.env)
        logger.debug('%s: %s', result.pid, debug_print(cmd))
        return result

    def _read_response(self, stream, result):
        # Internal method: reads all the stderr output from GPG, taking notice
        # only of lines that begin with the magic [GNUPG:] prefix.
        #
        # Calls methods on the response object for each valid token found,
        # with the arg being the remainder of the status line.
        lines = []
        while True:
            line = stream.readline()
            if len(line) == 0:
                break
            lines.append(line)
            line = line.rstrip()
            if self.verbose:  # pragma: no cover
                print(line)
            logger.debug('%s', line)
            if line[0:9] == '[GNUPG:] ':
                # Chop off the prefix
                line = line[9:]
                L = line.split(None, 1)
                keyword = L[0]
                if len(L) > 1:
                    value = L[1]
                else:
                    value = ''
                result.handle_status(keyword, value)
        result.stderr = ''.join(lines)

    def _read_data(self, stream, result, on_data=None, buffer_size=1024):
        # Read the contents of the file from GPG's stdout
        assert buffer_size > 0
        chunks = []
        on_data_failure = None
        while True:
            data = stream.read(buffer_size)
            if len(data) == 0:
                if on_data:
                    try:
                        on_data(data)
                    except Exception as e:
                        if on_data_failure is None:
                            on_data_failure = e
                break
            if log_everything:
                logger.debug('chunk: %r' % data[:256])
            append = True
            if on_data:
                try:
                    on_data_result = on_data(data)
                    append = on_data_result is not False
                except Exception as e:
                    if on_data_failure is None:
                        on_data_failure = e
            if append:
                chunks.append(data)
        if _py3k:
            # Join using b'' or '', as appropriate
            result.data = type(data)().join(chunks)
        else:
            result.data = ''.join(chunks)
        if on_data_failure:
            result.on_data_failure = on_data_failure

    def _collect_output(self, process, result, writer=None, stdin=None):
        """
        Drain the subprocesses output streams, writing the collected output to the result. If a writer thread (writing
        to the subprocess) is given, make sure it's joined before returning. If a stdin stream is given, close it
        before returning.
        """
        stderr = codecs.getreader(self.encoding)(process.stderr)
        rr = threading.Thread(target=self._read_response, args=(stderr, result))
        rr.daemon = True
        logger.debug('stderr reader: %r', rr)
        rr.start()

        stdout = process.stdout
        dr = threading.Thread(target=self._read_data, args=(stdout, result, self.on_data, self.buffer_size))
        dr.daemon = True
        logger.debug('stdout reader: %r', dr)
        dr.start()

        dr.join()
        rr.join()
        if writer is not None:
            writer.join(0.01)
        process.wait()
        result.returncode = rc = process.returncode
        if rc != 0:
            logger.warning('gpg returned a non-zero error code: %d', rc)
        if stdin is not None:
            try:
                stdin.close()
            except IOError:  # pragma: no cover
                pass
        stderr.close()
        stdout.close()
        return rc

    def is_valid_file(self, fileobj):
        """
        A simplistic check for a file-like object.

        Args:
            fileobj (object): The object to test.
        Returns:
            bool: ``True`` if it's a file-like object, else ``False``.
        """
        return hasattr(fileobj, 'read')

    def _get_fileobj(self, fileobj_or_path):
        if self.is_valid_file(fileobj_or_path):
            result = fileobj_or_path
        elif not isinstance(fileobj_or_path, path_types):
            raise TypeError('Not a valid file or path: %s' % fileobj_or_path)
        elif not os.path.exists(fileobj_or_path):
            raise ValueError('No such file: %s' % fileobj_or_path)
        else:
            result = open(fileobj_or_path, 'rb')
        return result

    def _handle_io(self, args, fileobj_or_path, result, passphrase=None, binary=False):
        "Handle a call to GPG - pass input data, collect output data"
        # Handle a basic data call - pass data to GPG, handle the output
        # including status information. Garbage In, Garbage Out :)
        fileobj = self._get_fileobj(fileobj_or_path)
        writer = None  # See issue #237
        try:
            p = self._open_subprocess(args, passphrase is not None)
            if not binary:  # pragma: no cover
                stdin = codecs.getwriter(self.encoding)(p.stdin)
            else:
                stdin = p.stdin
            if passphrase:
                _write_passphrase(stdin, passphrase, self.encoding)
            error_queue = Queue()
            writer = _threaded_copy_data(fileobj, stdin, self.buffer_size, error_queue)
            self._collect_output(p, result, writer, stdin)
            try:
                exc = error_queue.get_nowait()
                # if we get here, that means an error occurred in the copying thread
                raise exc
            except Empty:
                pass
            return result
        finally:
            if writer:
                writer.join(0.01)
            if fileobj is not fileobj_or_path:
                fileobj.close()

    #
    # SIGNATURE METHODS
    #

    def sign(self, message, **kwargs):
        """
        Sign a message. This method delegates most of the work to the `sign_file()` method.

        Args:
            message (str|bytes): The data to sign.
            kwargs (dict): Keyword arguments, which are passed to `sign_file()`:

                * keyid (str): The key id of the signer.

                * passphrase (str): The passphrase for the key.

                * clearsign (bool): Whether to use clear signing.

                * detach (bool): Whether to produce a detached signature.

                * binary (bool): Whether to produce a binary signature.

                * output (str): The path to write a detached signature to.

                * extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        f = _make_binary_stream(message, self.encoding)
        result = self.sign_file(f, **kwargs)
        f.close()
        return result

    def set_output_without_confirmation(self, args, output):
        """
        If writing to a file which exists, avoid a confirmation message by
        updating the *args* value in place to set the output path and avoid
        any cpmfirmation prompt.

        Args:
            args (list[str]): A list of arguments.
            output (str): The path to the outpur file.
        """
        if os.path.exists(output):
            # We need to avoid an overwrite confirmation message
            args.extend(['--yes'])
        args.extend(['--output', no_quote(output)])

    def is_valid_passphrase(self, passphrase):
        """
        Confirm that the passphrase doesn't contain newline-type characters - it is passed in a pipe to `gpg`,
        and so not checking could lead to spoofing attacks by passing arbitrary text after passphrase and newline.

        Args:
            passphrase (str): The passphrase to test.

        Returns:
            bool: ``True`` if it's a valid passphrase, else ``False``.
        """
        return ('\n' not in passphrase and '\r' not in passphrase and '\x00' not in passphrase)

    def sign_file(self,
                  fileobj_or_path,
                  keyid=None,
                  passphrase=None,
                  clearsign=True,
                  detach=False,
                  binary=False,
                  output=None,
                  extra_args=None):
        """
        Sign data in a file or file-like object.

        Args:
            fileobj_or_path (str|file): The file or file-like object to sign.

            keyid (str): The key id of the signer.

            passphrase (str): The passphrase for the key.

            clearsign (bool): Whether to use clear signing.

            detach (bool): Whether to produce a detached signature.

            binary (bool): Whether to produce a binary signature.

            output (str): The path to write a detached signature to.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        if passphrase and not self.is_valid_passphrase(passphrase):
            raise ValueError('Invalid passphrase')
        logger.debug('sign_file: %s', fileobj_or_path)
        if binary:  # pragma: no cover
            args = ['-s']
        else:
            args = ['-sa']
        # You can't specify detach-sign and clearsign together: gpg ignores
        # the detach-sign in that case.
        if detach:
            args.append('--detach-sign')
        elif clearsign:
            args.append('--clearsign')
        if keyid:
            args.extend(['--default-key', no_quote(keyid)])
        if output:  # pragma: no cover
            # write the output to a file with the specified name
            self.set_output_without_confirmation(args, output)

        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        result = self.result_map['sign'](self)
        # We could use _handle_io here except for the fact that if the
        # passphrase is bad, gpg bails and you can't write the message.
        fileobj = self._get_fileobj(fileobj_or_path)
        p = self._open_subprocess(args, passphrase is not None)
        writer = None
        try:
            stdin = p.stdin
            if passphrase:
                _write_passphrase(stdin, passphrase, self.encoding)
            error_queue = Queue()
            writer = _threaded_copy_data(fileobj, stdin, self.buffer_size, error_queue)
            try:
                exc = error_queue.get_nowait()
                # if we get here, that means an error occurred in the copying thread
                raise exc
            except Empty:
                pass
        except IOError:  # pragma: no cover
            logging.exception('error writing message')
        finally:
            if writer:
                writer.join(0.01)
            if fileobj is not fileobj_or_path:
                fileobj.close()
        self._collect_output(p, result, writer, stdin)
        return result

    def verify(self, data, **kwargs):
        """
        Verify the signature on the contents of the string *data*. This method delegates most of the work to
        `verify_file()`.

        Args:
            data (str|bytes): The data to verify.
            kwargs (dict): Keyword arguments, which are passed to `verify_file()`:

                * fileobj_or_path (str|file): A path to a signature, or a file-like object containing one.

                * data_filename (str): If the signature is a detached one, the path to the data that was signed.

                * close_file (bool): If a file-like object is passed in, whether to close it.

                * extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        f = _make_binary_stream(data, self.encoding)
        result = self.verify_file(f, **kwargs)
        f.close()
        return result

    def verify_file(self, fileobj_or_path, data_filename=None, close_file=True, extra_args=None):
        """
        Verify a signature.

        Args:
            fileobj_or_path (str|file): A path to a signature, or a file-like object containing one.

            data_filename (str): If the signature is a detached one, the path to the data that was signed.

            close_file (bool): If a file-like object is passed in, whether to close it.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        logger.debug('verify_file: %r, %r', fileobj_or_path, data_filename)
        result = self.result_map['verify'](self)
        args = ['--verify']
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        if data_filename is None:
            self._handle_io(args, fileobj_or_path, result, binary=True)
        else:
            logger.debug('Handling detached verification')
            import tempfile
            fileobj = self._get_fileobj(fileobj_or_path)
            fd, fn = tempfile.mkstemp(prefix='pygpg-')
            s = fileobj.read()
            if fileobj is not fileobj_or_path:
                fileobj.close()
            elif close_file:
                fileobj_or_path.close()
            logger.debug('Wrote to temp file: %r', s)
            os.write(fd, s)
            os.close(fd)
            args.append(no_quote(fn))
            args.append(no_quote(data_filename))
            try:
                p = self._open_subprocess(args)
                self._collect_output(p, result, stdin=p.stdin)
            finally:
                os.remove(fn)
        return result

    def verify_data(self, sig_filename, data, extra_args=None):
        """
        Verify the signature in sig_filename against data in memory

        Args:
            sig_filename (str): The path to a signature.

            data (str|bytes): The data to be verified.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        logger.debug('verify_data: %r, %r ...', sig_filename, data[:16])
        result = self.result_map['verify'](self)
        args = ['--verify']
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        args.extend([no_quote(sig_filename), '-'])
        stream = _make_memory_stream(data)
        self._handle_io(args, stream, result, binary=True)
        return result

    #
    # KEY MANAGEMENT
    #

    def import_keys(self, key_data, extra_args=None, passphrase=None, allowed_fingerprints=None):
        """
        Import the key_data into our keyring.

        Args:
            key_data (str|bytes): The key data to import.

            passphrase (str): The passphrase to use.

            extra_args (list[str]): Additional arguments to pass to `gpg`.

            allowed_fingerprints (str|list[str]): If specified, the import is
                delegated to :meth:`import_keys_controlled`, which only imports
                public keys whose primary-key fingerprints are all in this
                approved set.
        """
        if allowed_fingerprints is not None:
            return self.import_keys_controlled(key_data,
                                               allowed_fingerprints,
                                               extra_args=extra_args,
                                               passphrase=passphrase)
        result = self.result_map['import'](self)
        logger.debug('import_keys: %r', key_data[:256])
        data = _make_binary_stream(key_data, self.encoding)
        args = ['--import']
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        self._handle_io(args, data, result, passphrase=passphrase, binary=True)
        logger.debug('import_keys result: %r', result.__dict__)
        data.close()
        return result

    def import_keys_file(self, key_path, **kwargs):
        """
        Import the key data in key_path into our keyring.

        Args:
            key_path (str): A path to the key data to be imported.
        """
        with open(key_path, 'rb') as f:
            return self.import_keys(f.read(), **kwargs)

    # Filenames (relative to the GnuPG home directory) which hold the public
    # keyring and the local ownertrust. Snapshotted before a controlled
    # import so that a failed import can be rolled back.
    _KEYRING_BASENAMES = ('pubring.kbx', 'pubring.kbx~', 'pubring.gpg', 'pubring.gpg~', 'trustdb.gpg')

    def _snapshot_keyring_files(self):
        """
        Return a dict mapping keyring-related file paths to their current
        contents (or ``None`` if the file doesn't exist). Best-effort: only
        files which can be located are included.
        """
        paths = []
        if self.gnupghome:
            for name in self._KEYRING_BASENAMES:
                paths.append(os.path.join(self.gnupghome, name))
            # Used by keyboxd (GnuPG >= 2.3) if enabled.
            pkd = os.path.join(self.gnupghome, 'public-keys.d')
            if os.path.isdir(pkd):  # pragma: no cover
                for name in sorted(os.listdir(pkd)):
                    path = os.path.join(pkd, name)
                    if os.path.isfile(path):
                        paths.append(path)
        if self.keyring:
            for fn in self.keyring:
                paths.extend([fn, fn + '~'])
        snapshot = {}
        for path in paths:
            try:
                with open(path, 'rb') as f:
                    snapshot[path] = f.read()
            except IOError:
                snapshot[path] = None
        return snapshot

    def _restore_keyring_files(self, snapshot):
        """
        Restore keyring-related files from a snapshot made by
        :meth:`_snapshot_keyring_files`. Best-effort: failures are logged
        rather than raised.
        """
        for path, content in snapshot.items():
            try:
                if content is None:
                    if os.path.exists(path):
                        os.remove(path)
                else:
                    with open(path, 'wb') as f:
                        f.write(content)
            except IOError:  # pragma: no cover
                logger.warning('unable to restore %s', path)

    def import_keys_controlled(self,
                               key_data,
                               allowed_fingerprints,
                               extra_args=None,
                               passphrase=None,
                               dry_run=False,
                               allow_updates=True):
        """
        Import public keys from ``key_data`` only if every primary key in it
        has a full fingerprint in ``allowed_fingerprints``.

        The candidate material is first read in an isolated, temporary GnuPG
        home directory, so nothing in this instance's keyring is touched
        while the data is examined. A :class:`ControlledImportResult` is
        returned whose ``report`` describes the primary keys, subkeys and
        observable updates (new keys, user IDs, signatures and subkeys)
        relative to the current keyring.

        The import is rejected (``result.rejected`` is true and the keyring
        is left unchanged) if the key data:

        * contains secret key material (``'secret-material'``),
        * contains primary keys whose fingerprints are not in
          ``allowed_fingerprints`` (``'extra-primary-key'``),
        * contains keys whose full fingerprints cannot be determined
          (``'unconfirmable-fingerprint'``),
        * is truncated or otherwise not fully parseable
          (``'invalid-key-data'``), or
        * would update keys already in the keyring and ``allow_updates`` is
          false (``'already-exists'``).

        Keys which are already present in the keyring are treated as updates:
        new user IDs, signatures and subkeys are merged by `gpg`, and an
        unchanged key is a no-op. Local ownertrust is never modified by the
        import - ownertrust values are recorded before and checked after the
        import, and any unexpected change causes a rollback and rejection.

        Args:
            key_data (str|bytes): The candidate key data.

            allowed_fingerprints (str|list[str]): The approved set of full
                primary-key fingerprints.

            extra_args (list[str]): Additional arguments to pass to `gpg`.

            passphrase (str): The passphrase to use.

            dry_run (bool): If true, only validate and report - the keyring
                is never modified.

            allow_updates (bool): Whether candidate keys which are already
                present in the keyring are allowed.

        Returns:
            ControlledImportResult: The result of the validation and, unless
            rejected or a dry run, of the actual import.
        """
        import shutil
        import tempfile

        if isinstance(allowed_fingerprints, string_types):
            allowed_fingerprints = [allowed_fingerprints]
        allowed = [_normalize_fingerprint(fp) for fp in allowed_fingerprints]
        allowed_set = set(allowed)

        result = ControlledImportResult(self)
        result.dry_run = bool(dry_run)
        report = result.report
        report.update({
            'allowed_fingerprints': allowed,
            'dry_run': bool(dry_run),
            'primary_keys': [],
            'subkeys': [],
            'updates': [],
            'update_summary': {},
            'existing_fingerprints': [],
            'new_fingerprints': [],
            'extra_primary_fingerprints': [],
            'unconfirmed_fingerprints': [],
            'secret_material': False,
            'ownertrust_preserved': True,
        })

        # Snapshot the current state of the target keyring, so that we can
        # report on it and verify that a rejected import changed nothing.
        before_keys = self.list_keys()
        target_before = list(before_keys.fingerprints)
        target_before_set = set(target_before)
        ownertrust_before = {}
        for key in before_keys:
            ownertrust_before[key['fingerprint']] = key.get('ownertrust')
        secret_before = set(self.list_keys(secret=True).fingerprints)
        report['target_fingerprints_before'] = target_before
        report['target_fingerprints_after'] = list(target_before)
        report['ownertrust_before'] = ownertrust_before
        report['ownertrust_after'] = dict(ownertrust_before)

        def finalize(status):
            result.status = status
            report['status'] = status
            report['rejected'] = result.rejected
            report['reason'] = result.reason
            report['errors'] = list(result.errors)
            return result

        def reject(reason, message):
            result.rejected = True
            result.reason = reason
            if message not in result.errors:
                result.errors.append(message)
            logger.debug('controlled import rejected: %s: %s', reason, message)
            return finalize('rejected')

        isolated_home = tempfile.mkdtemp(prefix='pygpg-controlled-')
        try:
            os.chmod(isolated_home, 0o700)
            isolated = GPG(gpgbinary=self.gpgbinary, gnupghome=isolated_home, encoding=self.encoding)
            scan = isolated.scan_keys_mem(key_data)

            # Reject secret key material - only public keys may be imported.
            secret_material = _contains_secret_key_material(key_data)
            primary_records = []
            for record in scan:
                if record.get('type') in ('sec', 'ssb'):
                    secret_material = True
                else:
                    primary_records.append(record)
            report['secret_material'] = secret_material
            if secret_material:
                return reject('secret-material', 'key data contains secret key material')
            if not primary_records:
                return reject('invalid-key-data', 'no public key material found in key data')
            if scan.returncode or _IMPORT_DATA_ERROR_RE.search(scan.stderr or ''):
                return reject('invalid-key-data', 'key data could not be fully parsed')

            primary_keys = []
            subkey_report = []
            unconfirmed = []
            for record in primary_records:
                fp = record.get('fingerprint')
                if not _is_full_fingerprint(fp):
                    unconfirmed.append(record.get('keyid') or '<unknown>')
                subkeys = []
                for keyid, capability, sub_fp, _grip in record.get('subkeys', []):
                    if not _is_full_fingerprint(sub_fp):
                        unconfirmed.append(keyid or '<unknown>')
                    subkey = {'keyid': keyid, 'capabilities': capability, 'fingerprint': sub_fp}
                    subkeys.append(subkey)
                    entry = dict(subkey)
                    entry['primary_fingerprint'] = fp
                    subkey_report.append(entry)
                primary_keys.append({
                    'fingerprint': fp,
                    'keyid': record.get('keyid'),
                    'uids': list(record.get('uids', [])),
                    'subkeys': subkeys,
                })
            report['primary_keys'] = primary_keys
            report['subkeys'] = subkey_report
            report['unconfirmed_fingerprints'] = unconfirmed
            if unconfirmed:
                return reject('unconfirmable-fingerprint',
                              'unable to confirm fingerprints for: %s' % ', '.join(unconfirmed))

            primary_fps = []
            for pk in primary_keys:
                if pk['fingerprint'] not in primary_fps:
                    primary_fps.append(pk['fingerprint'])
            extra = [fp for fp in primary_fps if fp not in allowed_set]
            report['extra_primary_fingerprints'] = extra
            if extra:
                return reject('extra-primary-key',
                              'key data contains unapproved primary keys: %s' % ', '.join(extra))

            existing = [fp for fp in primary_fps if fp in target_before_set]
            report['existing_fingerprints'] = existing
            report['new_fingerprints'] = [fp for fp in primary_fps if fp not in target_before_set]
            if existing and not allow_updates:
                return reject('already-exists',
                              'key data would update keys already in the keyring: %s' % ', '.join(existing))

            # Observe what the import would change, in the isolated home
            # pre-populated with the current contents of the target keyring.
            if target_before:
                exported = self.export_keys(target_before)
                if exported:
                    isolated.import_keys(exported)
            isolated_result = isolated.import_keys(key_data)
            problem = _controlled_import_problem(isolated_result)
            if problem:
                return reject(*problem)

            updates = []
            for entry in isolated_result.results:
                if 'ok' not in entry:
                    continue
                bits = int(entry['ok'])
                updates.append({
                    'fingerprint': entry['fingerprint'],
                    'new_key': bool(bits & 1),
                    'new_user_ids': bool(bits & 2),
                    'new_signatures': bool(bits & 4),
                    'new_subkeys': bool(bits & 8),
                    'contains_private_key': bool(bits & 16),
                    'unchanged': not bits,
                })
            report['updates'] = updates
            report['update_summary'] = {
                'imported': isolated_result.imported,
                'unchanged': isolated_result.unchanged,
                'new_user_ids': isolated_result.n_uids,
                'new_subkeys': isolated_result.n_subk,
                'new_signatures': isolated_result.n_sigs,
            }

            if dry_run:
                return finalize('validated')

            # Everything checked out - do the actual import, with a snapshot
            # to roll back to if anything unexpected happens.
            snapshot = self._snapshot_keyring_files()
            data = _make_binary_stream(key_data, self.encoding)
            args = ['--import']
            if extra_args:  # pragma: no cover
                args.extend(extra_args)
            try:
                self._handle_io(args, data, result, passphrase=passphrase, binary=True)
            finally:
                data.close()

            after_keys = self.list_keys()
            target_after = list(after_keys.fingerprints)
            target_after_set = set(target_after)
            ownertrust_after = {}
            for key in after_keys:
                ownertrust_after[key['fingerprint']] = key.get('ownertrust')
            secret_after = set(self.list_keys(secret=True).fingerprints)
            report['target_fingerprints_after'] = target_after
            report['ownertrust_after'] = ownertrust_after

            def rollback(reason, message):
                self._restore_keyring_files(snapshot)
                report['target_fingerprints_after'] = list(target_before)
                report['ownertrust_after'] = dict(ownertrust_before)
                report['ownertrust_preserved'] = True
                return reject(reason, message)

            problem = _controlled_import_problem(result)
            if problem:
                return rollback(*problem)
            unexpected = target_after_set - target_before_set - set(primary_fps)
            if unexpected:  # pragma: no cover
                return rollback('import-failed',
                                'unexpected keys appeared in the keyring: %s' % ', '.join(sorted(unexpected)))
            missing = [fp for fp in primary_fps if fp not in target_after_set]
            if missing:
                return rollback('import-failed',
                                'approved keys were not imported: %s' % ', '.join(missing))
            if secret_after != secret_before:  # pragma: no cover
                return rollback('secret-material', 'secret keys appeared in the keyring')
            preserved = all(ownertrust_after.get(fp) == trust for fp, trust in ownertrust_before.items())
            report['ownertrust_preserved'] = preserved
            if not preserved:  # pragma: no cover
                return rollback('ownertrust-changed', 'local ownertrust values changed during import')
            if result.imported or result.n_uids or result.n_subk or result.n_sigs:
                status = 'imported'
            else:
                status = 'unchanged'
            return finalize(status)
        finally:
            shutil.rmtree(isolated_home, ignore_errors=True)

    def import_keys_file_controlled(self, key_path, allowed_fingerprints, **kwargs):
        """
        Import the key data in ``key_path`` under fingerprint control, as for
        :meth:`import_keys_controlled`.

        Args:
            key_path (str): A path to the key data to be imported.

            allowed_fingerprints (str|list[str]): The approved set of full
                primary-key fingerprints.
        """
        with open(key_path, 'rb') as f:
            return self.import_keys_controlled(f.read(), allowed_fingerprints, **kwargs)

    def recv_keys(self, keyserver, *keyids, **kwargs):
        """
        Import one or more keys from a keyserver.

        Args:
            keyserver (str): The key server hostname.

            keyids (str): A list of key ids to receive.
        """
        result = self.result_map['import'](self)
        logger.debug('recv_keys: %r', keyids)
        data = _make_binary_stream('', self.encoding)
        args = ['--keyserver', no_quote(keyserver)]
        if 'extra_args' in kwargs:  # pragma: no cover
            args.extend(kwargs['extra_args'])
        args.append('--recv-keys')
        args.extend([no_quote(k) for k in keyids])
        self._handle_io(args, data, result, binary=True)
        logger.debug('recv_keys result: %r', result.__dict__)
        data.close()
        return result

    # This function isn't exercised by tests, to avoid polluting external
    # key servers with test keys
    def send_keys(self, keyserver, *keyids, **kwargs):  # pragma: no cover
        """
        Send one or more keys to a keyserver.

        Args:
            keyserver (str): The key server hostname.

            keyids (list[str]): A list of key ids to send.
        """

        # Note: it's not practical to test this function without sending
        # arbitrary data to live keyservers.

        result = self.result_map['send'](self)
        logger.debug('send_keys: %r', keyids)
        data = _make_binary_stream('', self.encoding)
        args = ['--keyserver', no_quote(keyserver)]
        if 'extra_args' in kwargs:
            args.extend(kwargs['extra_args'])
        args.append('--send-keys')
        args.extend([no_quote(k) for k in keyids])
        self._handle_io(args, data, result, binary=True)
        logger.debug('send_keys result: %r', result.__dict__)
        data.close()
        return result

    def delete_keys(self, fingerprints, secret=False, passphrase=None, expect_passphrase=True, exclamation_mode=False):
        """
        Delete the indicated keys.

        Args:
            fingerprints (str|list[str]): The keys to delete.

            secret (bool): Whether to delete secret keys.

            passphrase (str): The passphrase to use.

            expect_passphrase (bool): Whether a passphrase is expected.

            exclamation_mode (bool): If specified, a `'!'` is appended to each fingerprint. This deletes only a subkey
                                     or an entire key, depending on what the fingerprint refers to.

        .. note:: Passphrases

           Since GnuPG 2.1, you can't delete secret keys without providing a passphrase. However, if you're expecting
           the passphrase to go to `gpg` via pinentry, you should specify expect_passphrase=False. (It's only checked
           for GnuPG >= 2.1).
        """
        if passphrase and not self.is_valid_passphrase(passphrase):  # pragma: no cover
            raise ValueError('Invalid passphrase')
        which = 'key'
        if secret:  # pragma: no cover
            if self.version >= (2, 1) and passphrase is None and expect_passphrase:
                raise ValueError('For GnuPG >= 2.1, deleting secret keys '
                                 'needs a passphrase to be provided')
            which = 'secret-key'
        if _is_sequence(fingerprints):  # pragma: no cover
            fingerprints = [no_quote(s) for s in fingerprints]
        else:
            fingerprints = [no_quote(fingerprints)]

        if exclamation_mode:
            fingerprints = [f + '!' for f in fingerprints]

        args = ['--delete-%s' % which]
        if secret and self.version >= (2, 1):
            args.insert(0, '--yes')
        args.extend(fingerprints)
        result = self.result_map['delete'](self)
        if not secret or self.version < (2, 1):
            p = self._open_subprocess(args)
            self._collect_output(p, result, stdin=p.stdin)
        else:
            # Need to send in a passphrase.
            f = _make_binary_stream('', self.encoding)
            try:
                self._handle_io(args, f, result, passphrase=passphrase, binary=True)
            finally:
                f.close()
        return result

    def export_keys(self,
                    keyids,
                    secret=False,
                    armor=True,
                    minimal=False,
                    passphrase=None,
                    expect_passphrase=True,
                    output=None):
        """
        Export the indicated keys. A 'keyid' is anything `gpg` accepts.

        Args:
            keyids (str|list[str]): A single keyid or a list of them.

            secret (bool): Whether to export secret keys.

            armor (bool): Whether to ASCII-armor the output.

            minimal (bool): Whether to pass `--export-options export-minimal` to `gpg`.

            passphrase (str): The passphrase to use.

            expect_passphrase (bool): Whether a passphrase is expected.

            output (str): If specified, the path to write the exported key(s) to.

        .. note:: Passphrases

           Since GnuPG 2.1, you can't export secret keys without providing a passphrase. However, if you're expecting
           the passphrase to go to `gpg` via pinentry, you should specify expect_passphrase=False. (It's only checked
           for GnuPG >= 2.1).
        """
        if passphrase and not self.is_valid_passphrase(passphrase):  # pragma: no cover
            raise ValueError('Invalid passphrase')
        which = ''
        if secret:
            which = '-secret-key'
            if self.version >= (2, 1) and passphrase is None and expect_passphrase:  # pragma: no cover
                raise ValueError('For GnuPG >= 2.1, exporting secret keys '
                                 'needs a passphrase to be provided')
        if _is_sequence(keyids):
            keyids = [no_quote(k) for k in keyids]
        else:
            keyids = [no_quote(keyids)]
        args = ['--export%s' % which]
        if armor:
            args.append('--armor')
        if minimal:  # pragma: no cover
            args.extend(['--export-options', 'export-minimal'])
        if output:  # pragma: no cover
            # write the output to a file with the specified name
            self.set_output_without_confirmation(args, output)
        args.extend(keyids)
        # gpg --export produces no status-fd output; stdout will be
        # empty in case of failure
        result = self.result_map['export'](self)
        if not secret or self.version < (2, 1):
            p = self._open_subprocess(args)
            self._collect_output(p, result, stdin=p.stdin)
        else:
            # Need to send in a passphrase.
            f = _make_binary_stream('', self.encoding)
            try:
                self._handle_io(args, f, result, passphrase=passphrase, binary=True)
            finally:
                f.close()
        logger.debug('export_keys result[:100]: %r', result.data[:100])
        # Issue #49: Return bytes if armor not specified, else text
        result = result.data
        if armor:
            result = result.decode(self.encoding, self.decode_errors)
        return result

    def _decode_result(self, result):
        lines = result.data.decode(self.encoding, self.decode_errors).splitlines()
        valid_keywords = 'pub uid sec fpr sub ssb sig grp'.split()
        for line in lines:
            if self.verbose:  # pragma: no cover
                print(line)
            logger.debug('line: %r', line.rstrip())
            if not line:  # pragma: no cover
                break
            L = line.strip().split(':')
            if not L:  # pragma: no cover
                continue
            keyword = L[0]
            if keyword in valid_keywords:
                getattr(result, keyword)(L)
        return result

    def _get_list_output(self, p, kind):
        # Get the response information
        result = self.result_map[kind](self)
        self._collect_output(p, result, stdin=p.stdin)
        return self._decode_result(result)

    def list_keys(self, secret=False, keys=None, sigs=False):
        """
        List the keys currently in the keyring.

        Args:
            secret (bool): Whether to list secret keys.

            keys (str|list[str]): A list of key ids to match.

            sigs (bool): Whether to include signature information.

        Returns:
            list[dict]: A list of dictionaries with key information.
        """

        if secret:
            which = 'secret-keys'
        else:
            which = 'sigs' if sigs else 'keys'
        args = ['--list-%s' % which, '--fingerprint', '--fingerprint']  # get subkey FPs, too

        if self.version >= (2, 1):
            args.append('--with-keygrip')

        if keys:
            if isinstance(keys, string_types):
                keys = [keys]
            args.extend(keys)
        p = self._open_subprocess(args)
        result = self._get_list_output(p, 'list')
        # Fix up subkey_info with fingerprint and grip values
        for key in result:
            # import pdb; pdb.set_trace()
            subkeys = key['subkeys']
            subkey_info = key.get('subkey_info')
            if subkey_info:
                for sk in subkeys:
                    skid, capability, fp, grp = sk
                    d = subkey_info[skid]
                    d['capability'] = capability
                    d['fingerprint'] = fp
                    d['keygrip'] = grp
        return result

    def scan_keys(self, filename):
        """
        List details of an ascii armored or binary key file without first importing it to the local keyring.

        Args:
            filename (str): The path to the file containing the key(s).

        .. warning:: Warning:
            Care is needed. The function works on modern GnuPG by running:

                $ gpg --dry-run --import-options import-show --import filename

            On older versions, it does the *much* riskier:

                $ gpg --with-fingerprint --with-colons filename
        """
        if self.version >= (2, 1):
            args = ['--dry-run', '--import-options', 'import-show', '--import']
        else:
            logger.warning('Trying to list packets, but if the file is not a '
                           'keyring, might accidentally decrypt')
            args = ['--with-fingerprint', '--with-colons', '--fixed-list-mode']
        args.append(no_quote(filename))
        p = self._open_subprocess(args)
        return self._get_list_output(p, 'scan')

    def scan_keys_mem(self, key_data):
        """
        List details of an ascii armored or binary key without first importing it to the local keyring.

        Args:
            key_data (str|bytes): The key data to import.

        .. warning:: Warning:
            Care is needed. The function works on modern GnuPG by running:

                $ gpg --dry-run --import-options import-show --import filename

            On older versions, it does the *much* riskier:

                $ gpg --with-fingerprint --with-colons filename
        """
        result = self.result_map['scan'](self)
        logger.debug('scan_keys: %r', key_data[:256])
        data = _make_binary_stream(key_data, self.encoding)
        if self.version >= (2, 1):
            args = ['--dry-run', '--import-options', 'import-show', '--import']
        else:
            logger.warning('Trying to list packets, but if the file is not a '
                           'keyring, might accidentally decrypt')
            args = ['--with-fingerprint', '--with-colons', '--fixed-list-mode']
        self._handle_io(args, data, result, binary=True)
        logger.debug('scan_keys result: %r', result.__dict__)
        data.close()
        return self._decode_result(result)

    def search_keys(self, query, keyserver='pgp.mit.edu', extra_args=None):
        """
        search a keyserver by query (using the `--search-keys` option).

        Args:
            query(str): The query to use.

            keyserver (str): The key server hostname.

            extra_args (list[str]): Additional arguments to pass to `gpg`.
        """
        query = query.strip()
        if HEX_DIGITS_RE.match(query):
            query = '0x' + query
        args = ['--fingerprint', '--keyserver', no_quote(keyserver)]
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        args.extend(['--search-keys', no_quote(query)])
        p = self._open_subprocess(args)

        # Get the response information
        result = self.result_map['search'](self)
        self._collect_output(p, result, stdin=p.stdin)
        lines = result.data.decode(self.encoding, self.decode_errors).splitlines()
        valid_keywords = ['pub', 'uid']
        for line in lines:
            if self.verbose:  # pragma: no cover
                print(line)
            logger.debug('line: %r', line.rstrip())
            if not line:  # sometimes get blank lines on Windows
                continue
            L = line.strip().split(':')
            if not L:  # pragma: no cover
                continue
            keyword = L[0]
            if keyword in valid_keywords:
                getattr(result, keyword)(L)
        return result

    def auto_locate_key(self, email, mechanisms=None, **kwargs):
        """
        Auto locate a public key by `email`.

        Args:
            email (str): The email address to search for.
            mechanisms (list[str]): A list of mechanisms to use. Valid mechanisms can be found
            here https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html
            under "--auto-key-locate". Default: ['wkd', 'ntds', 'ldap', 'cert', 'dane', 'local']
        """
        mechanisms = mechanisms or ['wkd', 'ntds', 'ldap', 'cert', 'dane', 'local']

        args = ['--auto-key-locate', ','.join(mechanisms), '--locate-keys', email]

        result = self.result_map['auto-locate-key'](self)

        if 'extra_args' in kwargs:
            args.extend(kwargs['extra_args'])

        process = self._open_subprocess(args)
        self._collect_output(process, result, stdin=process.stdin)
        self._decode_result(result)
        return result

    def gen_key(self, input):
        """
        Generate a key; you might use `gen_key_input()` to create the input.

        Args:
            input (str): The input to the key creation operation.
        """
        args = ['--gen-key']
        result = self.result_map['generate'](self)
        f = _make_binary_stream(input, self.encoding)
        self._handle_io(args, f, result, binary=True)
        f.close()
        return result

    def gen_key_input(self, **kwargs):
        """
        Generate `--gen-key` input  (see `gpg` documentation in DETAILS).

        Args:
            kwargs (dict): A list of keyword arguments.
        Returns:
            str: A string suitable for passing to the `gen_key()` method.
        """

        parms = {}
        no_protection = kwargs.pop('no_protection', False)
        for key, val in list(kwargs.items()):
            key = key.replace('_', '-').title()
            if str(val).strip():  # skip empty strings
                parms[key] = val
        parms.setdefault('Key-Type', 'RSA')
        if 'key_curve' not in kwargs:
            parms.setdefault('Key-Length', 2048)
        parms.setdefault('Name-Real', 'Autogenerated Key')
        logname = (os.environ.get('LOGNAME') or os.environ.get('USERNAME') or 'unspecified')
        hostname = socket.gethostname()
        parms.setdefault('Name-Email', '%s@%s' % (logname.replace(' ', '_'), hostname))
        out = 'Key-Type: %s\n' % parms.pop('Key-Type')
        for key, val in list(parms.items()):
            out += '%s: %s\n' % (key, val)
        if no_protection:  # pragma: no cover
            out += '%no-protection\n'
        out += '%commit\n'
        return out

        # Key-Type: RSA
        # Key-Length: 1024
        # Name-Real: ISdlink Server on %s
        # Name-Comment: Created by %s
        # Name-Email: isdlink@%s
        # Expire-Date: 0
        # %commit
        #
        #
        # Key-Type: DSA
        # Key-Length: 1024
        # Subkey-Type: ELG-E
        # Subkey-Length: 1024
        # Name-Real: Joe Tester
        # Name-Comment: with stupid passphrase
        # Name-Email: joe@foo.bar
        # Expire-Date: 0
        # Passphrase: abc
        # %pubring foo.pub
        # %secring foo.sec
        # %commit

    def add_subkey(self, master_key, master_passphrase=None, algorithm='rsa', usage='encrypt', expire='-'):
        """
        Add subkeys to a master key,

        Args:
            master_key (str): The master key.

            master_passphrase (str): The passphrase for the master key.

            algorithm (str): The key algorithm to use.

            usage (str): The desired uses for the subkey.

            expire (str): The expiration date of the subkey.
        """
        if self.version[0] < 2:
            raise NotImplementedError('Not available in GnuPG 1.x')
        if not master_key:  # pragma: no cover
            raise ValueError('No master key fingerprint specified')

        if master_passphrase and not self.is_valid_passphrase(master_passphrase):  # pragma: no cover
            raise ValueError('Invalid passphrase')

        args = ['--quick-add-key', master_key, algorithm, usage, str(expire)]

        result = self.result_map['addSubkey'](self)

        f = _make_binary_stream('', self.encoding)
        self._handle_io(args, f, result, passphrase=master_passphrase, binary=True)
        return result

    def quick_sign_key(self, certifier_fingerprint, recipient_fingerprint, certifier_passphrase=None):
        """
        Certify a key using quick-sign-key function.

        Args:
            certifier_fingerprint (str): The fingerprint for the certifying key.

            recipient_fingerprint (str): The fingerprint of the key being signed.

            certifier_passphrase (str): The passphrase for the certifing key.
        """
        if self.version[0] < 2:
            raise NotImplementedError('Not available in GnuPG 1.x')
        if not certifier_fingerprint:  # pragma: no cover
            raise ValueError('No certifier key fingerprint specified')
        if not recipient_fingerprint:  # pragma: no cover
            raise ValueError('No recipient key fingerprint specified')
        if certifier_passphrase and not self.is_valid_passphrase(certifier_passphrase):  # pragma: no cover
            raise ValueError('Invalid passphrase')

        args = ['--local-user', certifier_fingerprint, '--quick-sign-key', recipient_fingerprint]

        result = self.result_map['sign'](self)

        f = _make_binary_stream('', self.encoding)
        self._handle_io(args, f, result, passphrase=certifier_passphrase, binary=True)
        return result

    #
    # ENCRYPTION
    #

    def encrypt_file(self,
                     fileobj_or_path,
                     recipients,
                     hidden_recipients=None,
                     sign=None,
                     always_trust=False,
                     passphrase=None,
                     armor=True,
                     output=None,
                     symmetric=False,
                     extra_args=None):
        """
        Encrypt data in a file or file-like object.

        Args:
            fileobj_or_path (str|file): A path to a file or a file-like object containing the data to be encrypted.

            recipients (str|list): A key id of a recipient of the encrypted data, or a list of such key ids.

            hidden_recipients (str|list): A key id of a hidden recipient of the encrypted data, or a list of such key ids.

            sign (str): If specified, the key id of a signer to sign the encrypted data.

            always_trust (bool): Whether to always trust keys.

            passphrase (str): The passphrase to use for a signature.

            armor (bool): Whether to ASCII-armor the output.

            output (str): A path to write the encrypted output to.

            symmetric (bool): Whether to use symmetric encryption,

            extra_args (list[str]): A list of additional arguments to pass to `gpg`.
        """
        if passphrase and not self.is_valid_passphrase(passphrase):
            raise ValueError('Invalid passphrase')
        args = ['--encrypt']
        if symmetric:
            # can't be False or None - could be True or a cipher algo value
            # such as AES256
            args = ['--symmetric']
            if symmetric is not True:
                args.extend(['--cipher-algo', no_quote(symmetric)])
            # else use the default, currently CAST5
        else:
            if not recipients and not hidden_recipients:
                raise ValueError('No recipients or hidden recipients specified with '
                                 'asymmetric encryption')
            if recipients:
                if not _is_sequence(recipients):
                    recipients = (recipients, )
                for recipient in recipients:
                    args.extend(['--recipient', no_quote(recipient)])

            if hidden_recipients:
                if not _is_sequence(hidden_recipients):
                    hidden_recipients = (hidden_recipients, )
                for hidden_recipient in hidden_recipients:
                    args.extend(['--hidden-recipient', no_quote(hidden_recipient)])
        if armor:  # create ascii-armored output - False for binary output
            args.append('--armor')
        if output:  # pragma: no cover
            # write the output to a file with the specified name
            self.set_output_without_confirmation(args, output)
        if sign is True:  # pragma: no cover
            args.append('--sign')
        elif sign:  # pragma: no cover
            args.extend(['--sign', '--default-key', no_quote(sign)])
        if always_trust:  # pragma: no cover
            args.extend(['--trust-model', 'always'])
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        result = self.result_map['crypt'](self)
        self._handle_io(args, fileobj_or_path, result, passphrase=passphrase, binary=True)
        logger.debug('encrypt result[:100]: %r', result.data[:100])
        return result

    def encrypt(self, data, recipients, **kwargs):
        """
        Encrypt the message contained in the string *data* for *recipients*. This method delegates most of the work to
        `encrypt_file()`.

        Args:
            data (str|bytes): The data to encrypt.

            recipients (str|list[str]): A key id of a recipient of the encrypted data, or a list of such key ids.

            kwargs (dict): Keyword arguments, which are passed to `encrypt_file()`:
                * sign (str): If specified, the key id of a signer to sign the encrypted data.

                * always_trust (bool): Whether to always trust keys.

                * passphrase (str): The passphrase to use for a signature.

                * armor (bool): Whether to ASCII-armor the output.

                * output (str): A path to write the encrypted output to.

                * symmetric (bool): Whether to use symmetric encryption,

                * extra_args (list[str]): A list of additional arguments to pass to `gpg`.
        """
        data = _make_binary_stream(data, self.encoding)
        result = self.encrypt_file(data, recipients, **kwargs)
        data.close()
        return result

    def decrypt(self, message, **kwargs):
        """
        Decrypt the data in *message*. This method delegates most of the work to
        `decrypt_file()`.

        Args:
            message (str|bytes): The data to decrypt. A default key will be used for decryption.

            kwargs (dict): Keyword arguments, which are passed to `decrypt_file()`:

                * always_trust: Whether to always trust keys.

                * passphrase (str): The passphrase to use.

                * output (str): If specified, the path to write the decrypted data to.

                * extra_args (list[str]): A list of extra arguments to pass to `gpg`.
        """
        data = _make_binary_stream(message, self.encoding)
        result = self.decrypt_file(data, **kwargs)
        data.close()
        return result

    def decrypt_file(self, fileobj_or_path, always_trust=False, passphrase=None, output=None, extra_args=None):
        """
        Decrypt data in a file or file-like object.

        Args:
            fileobj_or_path (str|file): A path to a file or a file-like object containing the data to be decrypted.

            always_trust: Whether to always trust keys.

            passphrase (str): The passphrase to use.

            output (str): If specified, the path to write the decrypted data to.

            extra_args (list[str]): A list of extra arguments to pass to `gpg`.
        """
        if passphrase and not self.is_valid_passphrase(passphrase):
            raise ValueError('Invalid passphrase')
        args = ['--decrypt']
        if output:  # pragma: no cover
            # write the output to a file with the specified name
            self.set_output_without_confirmation(args, output)
        if always_trust:  # pragma: no cover
            args.extend(['--trust-model', 'always'])
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        result = self.result_map['crypt'](self)
        self._handle_io(args, fileobj_or_path, result, passphrase, binary=True)
        # logger.debug('decrypt result[:100]: %r', result.data[:100])
        return result

    def get_recipients(self, message, **kwargs):
        """ Get the list of recipients for an encrypted message. This method delegates most of the work to
        `get_recipients_file()`.

        Args:
            message (str|bytes): The encrypted message.

            kwargs (dict): Keyword arguments, which are passed to `get_recipients_file()`:

                * extra_args (list[str]): A list of extra arguments to pass to `gpg`.
        """
        data = _make_binary_stream(message, self.encoding)
        result = self.get_recipients_file(data, **kwargs)
        data.close()
        return result

    def get_recipients_file(self, fileobj_or_path, extra_args=None):
        """
        Get the list of recipients for an encrypted message in a file or file-like object.

        Args:
            fileobj_or_path (str|file): A path to a file or file-like object containing the encrypted data.

            extra_args (list[str]): A list of extra arguments to pass to `gpg`.
        """
        args = ['--decrypt', '--list-only', '-v']
        if extra_args:  # pragma: no cover
            args.extend(extra_args)
        result = self.result_map['crypt'](self)
        # See issue 276: PUBLIC_KEY_RE currently relies on having a language-dependent
        # message to parse. We can try to force LANG=C in the environment just for this
        # subprocess call, and restore it later.
        old_lang = None
        old_env = self.env
        if old_env is None:
            self.env = dict(os.environ)
            self.env['LANG'] = 'C'
        else:
            old_lang = old_env.get('LANG')
            self.env['LANG'] = 'C'
        self._handle_io(args, fileobj_or_path, result, binary=True)
        # Restore environment
        if old_env is None:
            self.env = None
        else:
            if old_lang is not None:
                self.env['LANG'] = old_lang
            else:
                self.env.pop('LANG')
        ids = []
        for m in PUBLIC_KEY_RE.finditer(result.stderr):
            ids.append(m.group(1))
        return ids

    def trust_keys(self, fingerprints, trustlevel):
        """
        Set the trust level for one or more keys.

        Args:
            fingerprints (str|list[str]): A key id for which to set the trust level, or a list of such key ids.

            trustlevel (str): The trust level. This is one of the following.

                                  * ``'TRUST_EXPIRED'``
                                  * ``'TRUST_UNDEFINED'``
                                  * ``'TRUST_NEVER'``
                                  * ``'TRUST_MARGINAL'``
                                  * ``'TRUST_FULLY'``
                                  * ``'TRUST_ULTIMATE'``
        """
        levels = Verify.TRUST_LEVELS
        if trustlevel not in levels:
            poss = ', '.join(sorted(levels))
            raise ValueError('Invalid trust level: "%s" (must be one of %s)' % (trustlevel, poss))
        trustlevel = levels[trustlevel] + 1
        import tempfile
        try:
            fd, fn = tempfile.mkstemp(prefix='pygpg-')
            lines = []
            if isinstance(fingerprints, string_types):
                fingerprints = [fingerprints]
            for f in fingerprints:
                lines.append('%s:%s:' % (f, trustlevel))
            # The trailing newline is required!
            s = os.linesep.join(lines) + os.linesep
            logger.debug('writing ownertrust info: %s', s)
            os.write(fd, s.encode(self.encoding))
            os.close(fd)
            result = self.result_map['trust'](self)
            p = self._open_subprocess(['--import-ownertrust', fn])
            self._collect_output(p, result, stdin=p.stdin)
            if p.returncode != 0:
                raise ValueError('gpg returned an error - return code %d' % p.returncode)
        finally:
            os.remove(fn)
        return result
