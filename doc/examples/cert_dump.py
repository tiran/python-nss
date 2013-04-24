#!/usr/bin/python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

'''
This example will pretty print the contents of a certificate loaded from a
file. This is not the easiest or best way to print a certificate, the nss
module has internal code to do that, all you need to invoke the str()
method of the certificate, or it's format, or format_lines()
method. Something as simple as the following will work:

print cert
print "Certificate is %s" % cert

What this example really aims to do is illustrate how to access the various
components of a cert.
'''

import os
import sys
import getopt
import getpass

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss

# -----------------------------------------------------------------------------
def print_extension(level, extension):
    print nss.indented_format([(level, 'Name: %s' % extension.name),
                               (level, 'Critical: %s' % extension.critical)])

    oid_tag = extension.oid_tag

    if   oid_tag == nss.SEC_OID_PKCS12_KEY_USAGE:
        print nss.indented_format([(level, 'Usages:')])
        print nss.indented_format(nss.make_line_fmt_tuples(level+1, nss.x509_key_usage(extension.value)))

    elif oid_tag == nss.SEC_OID_NS_CERT_EXT_CERT_TYPE:
        print nss.indented_format([(level, 'Types:')])
        print nss.indented_format(nss.make_line_fmt_tuples(level+1, nss.x509_cert_type(extension.value)))

    elif oid_tag == nss.SEC_OID_X509_SUBJECT_KEY_ID:
        print nss.indented_format([(level, 'Data:')])
        print nss.indented_format(nss.make_line_fmt_tuples(level+1,
              extension.value.der_to_hex(nss.OCTETS_PER_LINE_DEFAULT)))

    elif oid_tag == nss.SEC_OID_X509_CRL_DIST_POINTS:
        pts = nss.CRLDistributionPts(extension.value)
        print nss.indented_format([(level, 'CRL Distribution Points: [%d total]' % len(pts))])
        for i, pt in enumerate(pts):
            print nss.indented_format([(level+1, 'Point[%d]:' % i)])
            names = pt.get_general_names()
            print nss.indented_format([(level+2, 'General Names: [%d total]' % len(names))])
            for name in names:
                print nss.indented_format([(level+3, '%s:' % name)])
            print nss.indented_format([(level+2, 'Reasons: %s' % (pt.get_reasons(),))])
            print nss.indented_format([(level+2, 'Issuer: %s' % pt.issuer)])

    elif oid_tag == nss.SEC_OID_X509_AUTH_INFO_ACCESS:
        aias = nss.AuthorityInfoAccesses(extension.value)
        print nss.indented_format([(level, 'Authority Information Access: [%d total]' % len(aias))])
        for i, aia in enumerate(aias):
            print nss.indented_format([(level+1, 'Info[%d]:' % i)])
            print nss.indented_format([(level+2, 'Method: %s' % (aia.method_str,))])
            print nss.indented_format([(level+2, 'Location: (%s) %s' % (aia.location.type_string, aia.location.name))])

    elif oid_tag == nss.SEC_OID_X509_AUTH_KEY_ID:
        auth_key_id = nss.AuthKeyID(extension.value)
        print nss.indented_format([(level+1, 'Key ID:')])
        print nss.indented_format(nss.make_line_fmt_tuples(level+2,
              auth_key_id.key_id.to_hex(nss.OCTETS_PER_LINE_DEFAULT)))
        print nss.indented_format([(level+1, 'Serial Number: %s' % (auth_key_id.serial_number))])
        print nss.indented_format([(level+1, 'Issuer:' % auth_key_id.get_general_names())])

    elif oid_tag == nss.SEC_OID_X509_BASIC_CONSTRAINTS:
        bc = nss.BasicConstraints(extension.value)
        print nss.indented_format([(level, '%s' % str(bc))])

    elif oid_tag == nss.SEC_OID_X509_EXT_KEY_USAGE:
        print nss.indented_format([(level, 'Usages:')])
        print nss.indented_format(nss.make_line_fmt_tuples(level+1, nss.x509_ext_key_usage(extension.value)))

    elif oid_tag in (nss.SEC_OID_X509_SUBJECT_ALT_NAME, nss.SEC_OID_X509_ISSUER_ALT_NAME):
        names = nss.x509_alt_name(extension.value)
        print nss.indented_format([(level+2, 'Alternate Names: [%d total]' % len(names))])
        for name in names:
            print nss.indented_format([(level+3, '%s:' % name)])

    print

# -----------------------------------------------------------------------------

usage_str = '''
-p --pem        read the certifcate in PEM ascii format (default)
-d --der        read the certifcate in DER binary format
-P --print-cert print the cert using the internal rendering code
'''

def usage():
    print usage_str

try:
    opts, args = getopt.getopt(sys.argv[1:], "hpdP",
                               ["help", "pem", "der", "print-cert"])
except getopt.GetoptError:
    # print help information and exit:
    usage()
    sys.exit(2)


filename = 'cert.der'
is_pem_format = True
print_cert = False

for o, a in opts:
    if o in ("-H", "--help"):
        usage()
        sys.exit()
    elif o in ("-p", "--pem"):
        is_pem_format = True
    elif o in ("-d", "--der"):
        is_pem_format = False
    elif o in ("-P", "--print-cert"):
        print_cert = True


filename = sys.argv[1]

# Perform basic configuration and setup
nss.nss_init_nodb()

if len(args):
    filename = args[0]

print "certificate filename=%s" % (filename)

# Read the certificate as DER encoded data
si = nss.read_der_from_file(filename, is_pem_format)
# Parse the DER encoded data returning a Certificate object
cert = nss.Certificate(si)

# Useful for comparing the internal cert rendering to what this script generates.
if print_cert:
    print cert

# Get the extension list from the certificate
extensions = cert.extensions

print nss.indented_format([(0, 'Certificate:'),
                           (1, 'Data:')])
print nss.indented_format([(2, 'Version: %d (%#x)' % (cert.version+1, cert.version))])
print nss.indented_format([(2, 'Serial Number: %d (%#x)' % (cert.serial_number, cert.serial_number))])
print nss.indented_format([(2, 'Signature Algorithm:')])
print nss.indented_format(cert.signature_algorithm.format_lines(3))
print nss.indented_format([(2, 'Issuer: "%s"' % cert.issuer)])
print nss.indented_format([(2, 'Validity:'),
                           (3, 'Not Before: %s' % cert.valid_not_before_str),
                           (3, 'Not After:  %s' % cert.valid_not_after_str)])
print nss.indented_format([(2, 'Subject: "%s"' % cert.subject)])
print nss.indented_format([(2, 'Subject Public Key Info:')])
print nss.indented_format(cert.subject_public_key_info.format_lines(3))

if len(extensions) > 0:
    print nss.indented_format([(1, 'Signed Extensions: (%d)' % len(extensions))])
    for extension in extensions:
        print_extension(2, extension)

print nss.indented_format(cert.signed_data.format_lines(1))

print nss.indented_format([(1, 'Fingerprint (MD5):')])
print nss.indented_format(nss.make_line_fmt_tuples(2,
                                                   nss.data_to_hex(nss.md5_digest(cert.der_data),
                                                                   nss.OCTETS_PER_LINE_DEFAULT)))

print nss.indented_format([(1, 'Fingerprint (SHA1):')])
print nss.indented_format(nss.make_line_fmt_tuples(2,
                                                   nss.data_to_hex(nss.sha1_digest(cert.der_data),
                                                                   nss.OCTETS_PER_LINE_DEFAULT)))
