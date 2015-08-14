from __future__ import absolute_import
from __future__ import print_function

import argparse
import sys
import nss.nss as nss
import nss.error as nss_error

# Sample program that illustrates how to access certificate trust and/or
# modify a certificates trust setting.

def password_callback(slot, retry):
    return options.db_passwd

def illustrate_ssl_trust(cert):
    # Get list of ssl trusts as names
    trust_flags = cert.ssl_trust_flags
    if trust_flags is None:
        print("cert has no SSL trust flags")
        return

    # Get list of trusts as friendly description
    trust_list = nss.Certificate.trust_flags(trust_flags, nss.AsEnumDescription)
    print("trust flags (asString): %#x = %s" % (trust_flags, trust_list))

    # Get list of trusts as the names of the enumerated constants
    trust_list = nss.Certificate.trust_flags(trust_flags, nss.AsEnumName)
    print("trust flags (asEnumName): %#x = %s" % (trust_flags, trust_list))

    # Get list of trusts as enumeration constants
    trust_list = nss.Certificate.trust_flags(trust_flags, nss.AsEnum)
    print("trust flags (asEnum): %#x = %s" % (trust_flags, trust_list))

    # test for membership in list of enumeration constants
    if nss.CERTDB_TRUSTED_CA in trust_list:
        print("using trust list; cert is trusted CA")

    # test via bitmask
    if trust_flags & nss.CERTDB_TRUSTED_CA:
        print("using trust bitmask; cert is trusted CA")


#-------------------------------------------------------------------------------

def main():
    global options

    parser = argparse.ArgumentParser(description='certificate trust example')

    # === NSS Database Group ===
    group = parser.add_argument_group('NSS Database',
                                      'Specify & control the NSS Database')
    group.add_argument('-d', '--db-name',
                       help='NSS database name (e.g. "sql:pki")')

    group.add_argument('-P', '--db-passwd',
                       help='NSS database password')

    # === Certificate Group ===
    group = parser.add_argument_group('Certificate',
                                      'Specify how the certificate is loaded')

    group.add_argument('-f', '--file', dest='cert_filename',
                       help='read cert from file')

    group.add_argument('-F', '--input-format', choices=['pem', 'der'],
                       help='format of input cert')

    group.add_argument('-n', '--nickname', dest='cert_nickname',
                       help='load cert from NSS database by looking it up under this nickname')

    group.add_argument('-t', '--trust', dest='cert_trust',
                       help='set the cert trust flags, see certutil for format')

    group.add_argument('-i', '--install-cert', action='store_true', dest='cert_perm',
                           help='check signature')
    group.add_argument('-p', '--print-cert', action='store_true', dest='print_cert',
                       help='print the certificate in a friendly fashion')

    parser.set_defaults(db_name = 'sql:pki',
                        db_passwd = 'db_passwd',
                        input_format = 'pem',
                        install_cert = False,
                        print_cert = False,
                        )

    options = parser.parse_args()

    # Process the command line arguments

    if options.cert_perm:
        if not options.cert_filename:
            print("You must specify a cert filename to install a cert in the database", file=sys.stderr)
            return 1

        if not options.cert_nickname:
            print("You must specify a cert nickname to install a cert in the database", file=sys.stderr)
            return 1
    else:
        if options.cert_filename and options.cert_nickname:
            print("You may not specify both a cert filename and a nickname, only one or the other", file=sys.stderr)
            return 1

        if not options.cert_filename and not options.cert_nickname:
            print("You must specify either a cert filename or a nickname to load", file=sys.stderr)
            return 1


    # Initialize NSS.
    print('NSS Database: %s' % (options.db_name))
    print()
    # Initialize the database as read/write, otherwise we would not
    # be able to import a cert
    nss.nss_init_read_write(options.db_name)
    certdb = nss.get_default_certdb()

    # Since we may update the cert make sure we're using the key slot
    # and not just the internal slot
    slot = nss.get_internal_key_slot()

    # If we're importing or modifying a cert we'll need to authenticate
    # to the database, the password callback supplies the password during
    # authentication.
    nss.set_password_callback(password_callback)

    # Load the cert
    if options.cert_filename:
        # Read the certificate as DER encoded data then initialize a Certificate from the DER data
        filename = options.cert_filename
        si = nss.read_der_from_file(filename, options.input_format.lower() == 'pem')
        # Parse the DER encoded data returning a Certificate object.
        #
        # If we've been asked to install the cert in the database the
        # options.cert_perm flag will be True and we'll need to supply
        # the nickname (which is used to locate the cert in the database).
        cert = nss.Certificate(si, certdb,
                               options.cert_perm, options.cert_nickname)
    else:
        try:
            cert = nss.find_cert_from_nickname(options.cert_nickname)
        except Exception as e:
            print(e)
            print('Unable to load cert nickname "%s" from database "%s"' % \
                (options.cert_nickname, options.db_name), file=sys.stderr)
            return 1

    # Dump the cert if the user wants to see it
    if options.print_cert:
        print(cert)
    else:
        print('cert subject: %s' % (cert.subject))
    print()

    # Change the cert trust if specified
    if options.cert_trust:
        cert.set_trust_attributes(options.cert_trust, certdb, slot)

    illustrate_ssl_trust(cert)

    return 0

#-------------------------------------------------------------------------------
if __name__ == "__main__":
    sys.exit(main())
    nss.nss_shutdown()
