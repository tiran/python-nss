#!/usr/bin/python

import unittest

from nss.error import NSPRError
import nss.error as nss_error
import nss.nss as nss

'''

This test assures we can load a CSR (Certificate Signing Request) and
properly extract it's contents. A test CSR was generated and below is
the output from OpenSSL's parsing of that CSR. We deliberately used
OpenSSL rather than NSS to dump the CSR out in text form because using
a different implementation helps assure our implementation agrees.


% openssl req -in test.pem -text
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: CN=localhost
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d5:7a:f8:57:ea:d9:4c:02:c3:ee:3c:87:c4:fb:
                    f0:03:c0:7e:ca:6c:aa:b4:51:7c:84:29:a5:89:9c:
                    82:17:ed:11:90:c0:ff:3d:d5:c3:13:88:09:bf:6b:
                    d3:59:01:42:00:eb:89:a5:8b:11:2d:4c:ac:f8:c3:
                    7b:ca:4f:11:2a:69:84:d5:98:c8:38:4e:8a:9c:17:
                    bb:e7:ab:7e:96:8b:78:4b:f5:db:50:c3:ce:e3:4b:
                    71:6c:77:10:81:96:22:26:ee:72:e0:7d:56:d6:03:
                    a5:63:35:dd:25:f8:60:18:28:37:46:85:1c:2b:ad:
                    99:df:ec:b7:b3:d9:9c:e2:ca:bc:7a:47:89:a6:cf:
                    4b:2c:45:41:12:a1:3e:fa:7e:1a:d8:aa:92:5e:a7:
                    17:89:3f:fd:8b:e3:9f:29:c4:46:42:a3:ef:3b:72:
                    eb:78:c4:30:40:af:08:51:22:79:57:3f:21:5c:1e:
                    3f:26:56:25:23:61:21:26:87:65:22:8d:9a:f2:9c:
                    72:99:19:6b:d6:82:16:14:5f:ba:31:14:02:c3:69:
                    20:5d:40:a3:f2:6a:b3:ef:17:32:39:98:b2:f2:65:
                    15:1d:58:58:96:75:39:36:a6:13:70:9d:b2:d0:dd:
                    ba:0e:aa:c8:33:9a:b3:c2:00:bc:28:4f:f5:a5:5c:
                    48:7d
                Exponent: 65537 (0x10001)
        Attributes:
            friendlyName             :Test
        Requested Extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                8B:84:44:E2:3B:21:CD:54:37:95:2D:B7:E8:D1:B1:D8:0E:96:56:10
    Signature Algorithm: sha256WithRSAEncryption
         97:1c:5f:8c:27:35:fd:78:8f:76:a0:a0:be:43:54:be:62:54:
         50:db:33:58:92:d8:5e:28:b1:59:9b:8f:2d:0a:8e:7f:63:a6:
         05:52:60:0c:7b:46:90:ef:01:a4:09:96:66:56:59:fa:15:d0:
         3e:eb:08:d6:db:0a:b7:78:c2:57:97:02:75:63:8d:19:d8:b2:
         cc:d0:0c:84:e4:c0:86:86:b4:62:11:9c:c4:48:b2:51:67:29:
         02:ab:7a:7e:e0:12:01:c1:ba:96:b3:e1:91:85:98:70:90:5f:
         57:7b:1b:23:97:c1:d7:0b:2d:1e:e4:b8:15:c0:27:63:74:8f:
         0f:2d:e1:91:a8:4f:da:f2:65:2d:7b:c8:c6:1e:43:93:7a:22:
         07:a2:71:1c:b9:d3:63:c5:bc:24:d0:7a:ab:7a:74:b1:d8:40:
         e0:2a:21:2d:42:1e:5c:6d:ae:06:11:06:6f:d1:ec:b4:e5:d7:
         74:9d:92:85:3d:0d:0a:3d:59:93:51:7d:e7:13:1e:db:48:3b:
         3a:d2:96:3d:50:f4:84:21:91:76:56:72:c5:22:ac:96:57:42:
         dc:cd:bc:a5:b4:0d:5c:95:d8:a2:a5:49:6f:ae:10:a8:f5:b0:
         ad:30:b6:03:5e:14:71:50:be:1c:61:6d:3e:5c:be:7d:a4:ae:
         b4:be:b9:3d
-----BEGIN CERTIFICATE REQUEST-----
MIICrzCCAZcCAQAwFDESMBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA1Xr4V+rZTALD7jyHxPvwA8B+ymyqtFF8hCmliZyC
F+0RkMD/PdXDE4gJv2vTWQFCAOuJpYsRLUys+MN7yk8RKmmE1ZjIOE6KnBe756t+
lot4S/XbUMPO40txbHcQgZYiJu5y4H1W1gOlYzXdJfhgGCg3RoUcK62Z3+y3s9mc
4sq8ekeJps9LLEVBEqE++n4a2KqSXqcXiT/9i+OfKcRGQqPvO3LreMQwQK8IUSJ5
Vz8hXB4/JlYlI2EhJodlIo2a8pxymRlr1oIWFF+6MRQCw2kgXUCj8mqz7xcyOZiy
8mUVHVhYlnU5NqYTcJ2y0N26DqrIM5qzwgC8KE/1pVxIfQIDAQABoFYwEwYJKoZI
hvcNAQkUMQYTBFRlc3QwPwYJKoZIhvcNAQkOMTIwMDAMBgNVHRMBAf8EAjAAMCAG
A1UdDgEBAAQWBBSLhETiOyHNVDeVLbfo0bHYDpZWEDANBgkqhkiG9w0BAQsFAAOC
AQEAlxxfjCc1/XiPdqCgvkNUvmJUUNszWJLYXiixWZuPLQqOf2OmBVJgDHtGkO8B
pAmWZlZZ+hXQPusI1tsKt3jCV5cCdWONGdiyzNAMhOTAhoa0YhGcxEiyUWcpAqt6
fuASAcG6lrPhkYWYcJBfV3sbI5fB1wstHuS4FcAnY3SPDy3hkahP2vJlLXvIxh5D
k3oiB6JxHLnTY8W8JNB6q3p0sdhA4CohLUIeXG2uBhEGb9HstOXXdJ2ShT0NCj1Z
k1F95xMe20g7OtKWPVD0hCGRdlZyxSKslldC3M28pbQNXJXYoqVJb64QqPWwrTC2
A14UcVC+HGFtPly+faSutL65PQ==
-----END CERTIFICATE REQUEST-----
'''

# The exact same PEM data from above
pem = '''
-----BEGIN NEW CERTIFICATE REQUEST-----
MIICrzCCAZcCAQAwFDESMBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA1Xr4V+rZTALD7jyHxPvwA8B+ymyqtFF8hCmliZyC
F+0RkMD/PdXDE4gJv2vTWQFCAOuJpYsRLUys+MN7yk8RKmmE1ZjIOE6KnBe756t+
lot4S/XbUMPO40txbHcQgZYiJu5y4H1W1gOlYzXdJfhgGCg3RoUcK62Z3+y3s9mc
4sq8ekeJps9LLEVBEqE++n4a2KqSXqcXiT/9i+OfKcRGQqPvO3LreMQwQK8IUSJ5
Vz8hXB4/JlYlI2EhJodlIo2a8pxymRlr1oIWFF+6MRQCw2kgXUCj8mqz7xcyOZiy
8mUVHVhYlnU5NqYTcJ2y0N26DqrIM5qzwgC8KE/1pVxIfQIDAQABoFYwEwYJKoZI
hvcNAQkUMQYTBFRlc3QwPwYJKoZIhvcNAQkOMTIwMDAMBgNVHRMBAf8EAjAAMCAG
A1UdDgEBAAQWBBSLhETiOyHNVDeVLbfo0bHYDpZWEDANBgkqhkiG9w0BAQsFAAOC
AQEAlxxfjCc1/XiPdqCgvkNUvmJUUNszWJLYXiixWZuPLQqOf2OmBVJgDHtGkO8B
pAmWZlZZ+hXQPusI1tsKt3jCV5cCdWONGdiyzNAMhOTAhoa0YhGcxEiyUWcpAqt6
fuASAcG6lrPhkYWYcJBfV3sbI5fB1wstHuS4FcAnY3SPDy3hkahP2vJlLXvIxh5D
k3oiB6JxHLnTY8W8JNB6q3p0sdhA4CohLUIeXG2uBhEGb9HstOXXdJ2ShT0NCj1Z
k1F95xMe20g7OtKWPVD0hCGRdlZyxSKslldC3M28pbQNXJXYoqVJb64QqPWwrTC2
A14UcVC+HGFtPly+faSutL65PQ==
-----END NEW CERTIFICATE REQUEST-----
'''
class TestCertRequest(unittest.TestCase):

    def setUp(self):
        nss.nss_init_nodb()
        self.csr_der = nss.base64_to_binary(pem)
        self.csr = nss.CertificateRequest(self.csr_der)

    def tearDown(self):
        nss.nss_shutdown()

    def test_csr_parse(self):
        csr = self.csr

        # Validate basic CSR information
        self.assertEqual(str(csr.subject), 'CN=localhost')
        self.assertEqual(csr.version, 0)

        # Validate the CSR Subject Public Key 
        pub_key = csr.subject_public_key_info
        pub_key_algorithm = pub_key.algorithm

        self.assertEqual(pub_key_algorithm.id_tag, nss.SEC_OID_PKCS1_RSA_ENCRYPTION)
        self.assertEqual(pub_key.public_key.rsa.exponent.get_integer(), 65537)

        # Validate the extensions, the number of extensions should
        # match, the order of extensions should match, and the
        # contents of each extension should match.
        #
        # Note, extensions are contained in an attribute, in essence
        # the extensions are a special case of one attribute.
        extensions = csr.extensions
        self.assertEqual(len(extensions), 2)

        extension = extensions[0]
        self.assertIsInstance(extension, nss.CertificateExtension)
        self.assertEqual(extension.oid_tag, nss.SEC_OID_X509_BASIC_CONSTRAINTS)
        bc = nss.BasicConstraints(extension.value)
        self.assertEqual(bc.is_ca, False)
        self.assertEqual(bc.path_len, 0)


        extension = extensions[1]
        self.assertIsInstance(extension, nss.CertificateExtension)
        self.assertEqual(extension.oid_tag, nss.SEC_OID_X509_SUBJECT_KEY_ID)
        self.assertEqual(extension.value.der_to_hex().upper(),
                         '8B:84:44:E2:3B:21:CD:54:37:95:2D:B7:E8:D1:B1:D8:0E:96:56:10')

        # Validate the attributes, the number of attributes should
        # match and the order of the attributes should match. Each
        # attribute has a type and a set of values. Confirm each
        # attribute has the correct number of values and each value is
        # what we expect.
        #
        # Note, one of the attributes is a set of extension requests,
        # this should be identical to CertificateRequest.extensions
        # property. The extenions property is just a shorthand for
        # accessing the attribute containing extensions.
        #
        # NSS has an odd behavior with attributes that is heavily
        # weighted toward extensions. If the attribute contains
        # extensions then the attribute values are
        # CertificateExtension's, otherwise they are SecItem's
        # and need to be interpreted according to the attribute.type.
        attributes = csr.attributes
        self.assertEqual(len(attributes), 2)

        attribute = attributes[0]
        self.assertIsInstance(attribute, nss.CertAttribute)
        self.assertEqual(attribute.type_tag, nss.SEC_OID_PKCS9_FRIENDLY_NAME)

        attribute_values = attribute.values
        self.assertEqual(len(attribute_values), 1)

        attribute_value = attribute.values[0]
        self.assertIsInstance(attribute_value, nss.SecItem)
        self.assertEqual(str(attribute_value), 'Test')

        attribute = attributes[1]
        self.assertIsInstance(attribute, nss.CertAttribute)
        self.assertEqual(attribute.type_tag, nss.SEC_OID_PKCS9_EXTENSION_REQUEST)

        attribute_values = attribute.values
        self.assertEqual(len(attribute_values), 2)

        attribute_value = attribute.values[0]
        self.assertIsInstance(attribute_value, nss.CertificateExtension)
        self.assertEqual(attribute_value.oid_tag, nss.SEC_OID_X509_BASIC_CONSTRAINTS)

        attribute_value = attribute.values[1]
        self.assertIsInstance(attribute_value, nss.CertificateExtension)
        self.assertEqual(attribute_value.oid_tag, nss.SEC_OID_X509_SUBJECT_KEY_ID)

if __name__ == '__main__':
    unittest.main()
