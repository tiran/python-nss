#!/usr/bin/python

import sys
import os
import re
import subprocess
import shlex
import unittest

from nss.error import NSPRError
import nss.error as nss_error
import nss.nss as nss

#-------------------------------------------------------------------------------

verbose = False
db_name = 'sql:pki'
db_passwd = 'DB_passwd'
pk12_passwd = 'PK12_passwd'

cert_nickname = 'test_user'
pk12_filename = '%s.p12' % cert_nickname
exported_pk12_filename = 'exported_%s' % pk12_filename

#-------------------------------------------------------------------------------

class CmdError(Exception):
    def __init__(self, cmd_args, returncode, message=None, stdout=None, stderr=None):
        self.cmd_args = cmd_args
        self.returncode = returncode
        if message is None:
            self.message = 'Failed error=%s, ' % (returncode)
            if stderr:
                self.message += '"%s", ' % stderr
            self.message += 'args=%s' % (cmd_args)
        else:
            self.message = message
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        return self.message


def run_cmd(cmd_args, input=None):
    try:
        p = subprocess.Popen(cmd_args,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(input)
        returncode = p.returncode
        if returncode != 0:
            raise CmdError(cmd_args, returncode,
                           'failed %s' % (', '.join(cmd_args)),
                           stdout, stderr)
        return stdout, stderr
    except OSError as e:
        raise CmdError(cmd_args, e.errno, stderr=str(e))

#-------------------------------------------------------------------------------

def password_callback(slot, retry):
    return db_passwd


def nickname_collision_callback(old_nickname, cert):
    cancel = False
    new_nickname = cert.make_ca_nickname()
    return new_nickname, cancel


def get_cert_der_from_db(nickname):
    cmd_args = ['/usr/bin/certutil',
                '-d', db_name,
                '-L',
                '-n', nickname]

    try:
        stdout, stderr = run_cmd(cmd_args)
    except CmdError as e:
        if e.returncode == 255 and 'not found' in e.stderr:
            return None
        else:
            raise
    return stdout

def delete_cert_from_db(nickname):
    cmd_args = ['/usr/bin/certutil',
                '-d', db_name,
                '-D',
                '-n', nickname]

    run_cmd(cmd_args)

def create_pk12(nickname, filename):
    cmd_args = ['/usr/bin/pk12util',
                '-o', filename,
                '-n', nickname,
                '-d', db_name,
                '-K', db_passwd,
                '-W', pk12_passwd]
    run_cmd(cmd_args)

def list_pk12(filename):
    cmd_args = ['/usr/bin/pk12util',
                '-l', filename,
                '-W', pk12_passwd]
    stdout, stderr = run_cmd(cmd_args)
    return stdout

def strip_key_from_pk12_listing(text):
    match = re.search(r'^Certificate:$', text, re.MULTILINE)
    if not match:
        raise ValueError('Could not file Key section in pk12 listing')
    return text[match.start(0):]

def strip_salt_from_pk12_listing(text):
    return re.sub(r'\s+Salt:\s*\n.*', '', text)

#-------------------------------------------------------------------------------

def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    tests = loader.loadTestsFromNames(['test_pkcs12.TestPKCS12Decoder.test_read',
                                       'test_pkcs12.TestPKCS12Decoder.test_import',
                                       'test_pkcs12.TestPKCS12Export.test_export',
                                       ])
    suite.addTests(tests)
    return suite

#-------------------------------------------------------------------------------

class TestPKCS12Decoder(unittest.TestCase):
    def setUp(self):
        nss.nss_init_read_write(db_name)
        nss.set_password_callback(password_callback)
        nss.pkcs12_set_nickname_collision_callback(nickname_collision_callback)
        nss.pkcs12_enable_all_ciphers()
        self.cert_der = get_cert_der_from_db(cert_nickname)
        if self.cert_der is None:
            raise ValueError('cert with nickname "%s" not in database "%s"' % (cert_nickname, db_name))

    def tearDown(self):
        nss.nss_shutdown()

    def test_read(self):
        if verbose: print "test_read"
        create_pk12(cert_nickname, pk12_filename)

        slot = nss.get_internal_key_slot()
        pkcs12 = nss.PKCS12Decoder(pk12_filename, pk12_passwd, slot)

        self.assertEqual(len(pkcs12), 3)
        cert_bag_count = 0
        key_seen = None
        for bag in pkcs12:
            if bag.type == nss.SEC_OID_PKCS12_V1_CERT_BAG_ID:
                self.assertIsNone(bag.shroud_algorithm_id)
                cert_bag_count += 1
                if key_seen is None:
                    key_seen = bag.has_key
                elif key_seen is True:
                    self.assertIs(bag.has_key, False)
                elif key_seen is False:
                    self.assertIs(bag.has_key, True)
                else:
                    self.fail("unexpected has_key for bag type = %s(%d)" % (bag.has_key, nss.oid_tag_name(bag.type), bag.type))

            elif bag.type == nss.SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID:
                self.assertIsInstance(bag.shroud_algorithm_id, nss.AlgorithmID)
                self.assertIs(bag.has_key, False)
            else:
                self.fail("unexpected bag type = %s(%d)" % (nss.oid_tag_name(bag.type), bag.type))

        self.assertEqual(cert_bag_count, 2)

    def test_import(self):
        if verbose: print "test_import"
        delete_cert_from_db(cert_nickname)
        self.assertEqual(get_cert_der_from_db(cert_nickname), None)

        slot = nss.get_internal_key_slot()
        pkcs12 = nss.PKCS12Decoder(pk12_filename, pk12_passwd, slot)
        slot.authenticate()
        pkcs12.database_import()
        cert_der = get_cert_der_from_db(cert_nickname)
        self.assertEqual(cert_der, self.cert_der)

#-------------------------------------------------------------------------------

class TestPKCS12Export(unittest.TestCase):
    def setUp(self):
        nss.nss_init(db_name)
        nss.set_password_callback(password_callback)
        nss.pkcs12_enable_all_ciphers()
        self.cert_der = get_cert_der_from_db(cert_nickname)
        if self.cert_der is None:
            raise ValueError('cert with nickname "%s" not in database "%s"' % (cert_nickname, db_name))

    def tearDown(self):
        nss.nss_shutdown()

    def test_export(self):
        if verbose: print "test_export"
        pkcs12_data = nss.pkcs12_export(cert_nickname, pk12_passwd)
        with open(exported_pk12_filename, 'w') as f:
            f.write(pkcs12_data)

        pk12_listing = list_pk12(pk12_filename)
        pk12_listing = strip_key_from_pk12_listing(pk12_listing)
        pk12_listing = strip_salt_from_pk12_listing(pk12_listing)

        exported_pk12_listing = list_pk12(exported_pk12_filename)
        exported_pk12_listing = strip_key_from_pk12_listing(exported_pk12_listing)
        exported_pk12_listing = strip_salt_from_pk12_listing(exported_pk12_listing)

        self.assertEqual(pk12_listing, exported_pk12_listing)

if __name__ == '__main__':
    unittest.main()
