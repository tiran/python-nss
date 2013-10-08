#!/usr/bin/python

import sys
import os
import unittest

import nss.nss as nss
from nss.error import NSPRError

db_name = 'sql:pki'

#-------------------------------------------------------------------------------

# At the moment the OCSP tests are weak, we just test we can
# successfully call each of the functions.

class TestAPI(unittest.TestCase):
    def setUp(self):
        nss.nss_init_read_write(db_name)
        self.certdb = nss.get_default_certdb()

    def tearDown(self):
        nss.nss_shutdown()

    def test_ocsp_cache(self):
        nss.set_ocsp_cache_settings(100, 10, 20)
        nss.clear_ocsp_cache()

    def test_ocsp_timeout(self):
        with self.assertRaises(TypeError):
            nss.set_ocsp_timeout('ten')
        nss.set_ocsp_timeout(10)

    def test_ocsp_failure_mode(self):
        nss.set_ocsp_failure_mode(nss.ocspMode_FailureIsVerificationFailure)
        nss.set_ocsp_failure_mode(nss.ocspMode_FailureIsNotAVerificationFailure)
        with self.assertRaises(NSPRError):
            nss.set_ocsp_failure_mode(-1)

    def test_ocsp_default_responder(self):
        # should raise error if cert is not known
        with self.assertRaises(NSPRError):
            nss.set_ocsp_default_responder(self.certdb, "http://foo.com:80/ocsp", 'invalid')
        nss.set_ocsp_default_responder(self.certdb, "http://foo.com:80/ocsp", 'test_ca')
        nss.enable_ocsp_default_responder()
        nss.disable_ocsp_default_responder()
        nss.enable_ocsp_default_responder(self.certdb)
        nss.disable_ocsp_default_responder(self.certdb)

    def test_enable_ocsp_checking(self):
        nss.enable_ocsp_checking()
        nss.disable_ocsp_checking()
        nss.enable_ocsp_checking(self.certdb)
        nss.disable_ocsp_checking(self.certdb)

    def test_use_pkix_for_validation(self):
        # Must be boolean
        with self.assertRaises(TypeError):
            nss.set_use_pkix_for_validation('true')

        value = nss.get_use_pkix_for_validation()
        self.assertEqual(isinstance(value, bool), True)

        prev = nss.set_use_pkix_for_validation(not value)
        self.assertEqual(isinstance(prev, bool), True)
        self.assertEqual(value, prev)
        self.assertEqual(nss.get_use_pkix_for_validation(), not value)

        self.assertEqual(nss.set_use_pkix_for_validation(value), not value)


#-------------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
