from __future__ import print_function
from __future__ import absolute_import
import sys
import os
import unittest

import nss.nss as nss
import six

#-------------------------------------------------------------------------------
class TestVersion(unittest.TestCase):
    def test_version(self):

        version = nss.nss_get_version()
        self.assertEqual(nss.nss_version_check(version), True)

class TestShutdownCallback(unittest.TestCase):
    def test_shutdown_callback(self):
        int_value = 43
        str_value = u"foobar"
        count = 0
        dict_value = {'count': count}

        def shutdown_callback(nss_data, i, s, d):
            self.assertEqual(isinstance(nss_data, dict), True)

            self.assertEqual(isinstance(i, int), True)
            self.assertEqual(i, int_value)

            self.assertEqual(isinstance(s, six.string_types), True)
            self.assertEqual(s, str_value)

            self.assertEqual(isinstance(d, dict), True)
            self.assertEqual(d, dict_value)
            d['count'] += 1
            return True

        nss.nss_init_nodb()
        nss.set_shutdown_callback(shutdown_callback, int_value, str_value, dict_value)
        nss.nss_shutdown()
        self.assertEqual(dict_value['count'], count + 1)

        # Callback should not be invoked again after shutdown
        nss.nss_init_nodb()
        nss.nss_shutdown()
        self.assertEqual(dict_value['count'], count + 1)

        # Callback should not be invoked if cleared
        nss.nss_init_nodb()
        nss.set_shutdown_callback(shutdown_callback, int_value, str_value, dict_value)
        nss.set_shutdown_callback(None)
        nss.nss_shutdown()
        self.assertEqual(dict_value['count'], count + 1)

#-------------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
