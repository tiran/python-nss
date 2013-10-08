#!/usr/bin/python

import argparse
import sys

import nss.nss as nss
import nss.error as nss_error

'''
This example illustrates how one can use NSS to verify (validate) a
certificate. Certificate validation starts with an intended usage for
the certificate and returns a set of flags for which the certificate
is actually valid for. When a cert fails validation it can be
useful to obtain diagnostic information as to why. One of the
verification methods includes returning the diagnostic information in
what is called a log. A cert can also be checked to see if it
qualifies as a CA cert.

The actual code to verify the cert is simple and straight forward. The
complexity in this example derives mainly from handling all the
options necessary to make the example flexible.

* The certificate may either be read from a file or loaded by nickname
  from a NSS database.

* You can optionally print the details the cert.

* You can specify a set of intened cert usages (each -u option adds an
  other usage to the set).

* You can enable/disable checking the cert signature.

* You can enable/disable using the log variant.

* You can enable/disable verifying the cert's CA status.

* The results are pretty printed.

'''

#-------------------------------------------------------------------------------
cert_usage_map = {
    'CheckAllUsages'        : nss.certificateUsageCheckAllUsages,
    'SSLClient'             : nss.certificateUsageSSLClient,
    'SSLServer'             : nss.certificateUsageSSLServer,
    'SSLServerWithStepUp'   : nss.certificateUsageSSLServerWithStepUp,
    'SSLCA'                 : nss.certificateUsageSSLCA,
    'EmailSigner'           : nss.certificateUsageEmailSigner,
    'EmailRecipient'        : nss.certificateUsageEmailRecipient,
    'ObjectSigner'          : nss.certificateUsageObjectSigner,
    'UserCertImport'        : nss.certificateUsageUserCertImport,
    'VerifyCA'              : nss.certificateUsageVerifyCA,
    'ProtectedObjectSigner' : nss.certificateUsageProtectedObjectSigner,
    'StatusResponder'       : nss.certificateUsageStatusResponder,
    'AnyCA'                 : nss.certificateUsageAnyCA,
}

#-------------------------------------------------------------------------------

def password_callback(slot, retry, password):
    return options.db_passwd

def indented_output(msg, l, level=0):
    msg = '%s:' % msg
    lines = []
    if not l:
        l = ['--']
    lines.extend(nss.make_line_fmt_tuples(level, msg))
    lines.extend(nss.make_line_fmt_tuples(level+1, l))
    return nss.indented_format(lines)

def indented_obj(msg, obj, level=0):
    msg = '%s:' % msg
    lines = []
    lines.extend(nss.make_line_fmt_tuples(level, msg))
    lines.extend(obj.format_lines(level+1))
    return nss.indented_format(lines)


#-------------------------------------------------------------------------------

def main():
    global options

    parser = argparse.ArgumentParser(description='certificate validation example')

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

    # === Validation Group ===
    group = parser.add_argument_group('Validation',
                                      'Control the validation')

    group.add_argument('-u', '--usage', dest='cert_usage', action='append', choices=cert_usage_map.keys(),
                           help='certificate usage flags, may be specified multiple times')
    group.add_argument('-c', '--check-sig', action='store_true', dest='check_sig',
                           help='check signature')
    group.add_argument('-C', '--no-check-sig', action='store_false', dest='check_sig',
                           help='do not check signature')
    group.add_argument('-l', '--log', action='store_true', dest='with_log',
                           help='use verify log')
    group.add_argument('-L', '--no-log', action='store_false', dest='with_log',
                           help='do not use verify log')
    group.add_argument('-a', '--check-ca', action='store_true', dest='check_ca',
                           help='check if cert is CA')
    group.add_argument('-A', '--no-check-ca', action='store_false', dest='check_ca',
                           help='do not check if cert is CA')

    # === Miscellaneous Group ===
    group = parser.add_argument_group('Miscellaneous',
                                      'Miscellaneous options')

    group.add_argument('-p', '--print-cert', action='store_true', dest='print_cert',
                       help='print the certificate in a friendly fashion')


    parser.set_defaults(db_name = 'sql:pki',
                        db_passwd = 'db_passwd',
                        input_format = 'pem',
                        check_sig = True,
                        with_log = True,
                        check_ca = True,
                        print_cert = False,
                        )

    options = parser.parse_args()

    # Process the command line arguments

    # Get usage bitmask
    if options.cert_usage:
        intended_usage = 0
        for usage in options.cert_usage:
            try:
                flag = cert_usage_map[usage]
            except KeyError:
                print "Unknown usage '%s', valid values: %s" % (usage, ', '.join(sorted(cert_usage_map.keys())))
                return 1
            else:
                intended_usage |= flag
    else:
        # We can't use nss.certificateUsageCheckAllUsages here because
        # it's a special value of zero instead of being the bitwise OR
        # of all the certificateUsage* flags (go figure!)
        intended_usage = 0
        for usage in cert_usage_map.values():
            intended_usage |= usage

    if options.cert_filename and options.cert_nickname:
        print >>sys.stderr, "You may not specify both a cert filename and a nickname, only one or the other"
        return 1

    if not options.cert_filename and not options.cert_nickname:
        print >>sys.stderr, "You must specify either a cert filename or a nickname to load"
        return 1

    # Initialize NSS.
    print indented_output('NSS Database', options.db_name)
    print
    nss.nss_init(options.db_name)
    certdb = nss.get_default_certdb()
    nss.set_password_callback(password_callback)

    # Load the cert
    if options.cert_filename:
        # Read the certificate as DER encoded data then initialize a Certificate from the DER data
        filename = options.cert_filename
        si = nss.read_der_from_file(filename, options.input_format.lower() == 'pem')
        # Parse the DER encoded data returning a Certificate object
        cert = nss.Certificate(si)
    else:
        try:
            cert = nss.find_cert_from_nickname(options.cert_nickname)
        except Exception, e:
            print e
            print >>sys.stderr, 'Unable to load cert nickname "%s" from database "%s"' % \
                (options.cert_nickname, options.db_name)
            return 1

    # Dump the cert if the user wants to see it
    if options.print_cert:
        print cert
    else:
        print indented_output('cert subject', cert.subject)
    print

    # Dump the usages attached to the cert
    print indented_output('cert has these usages', nss.cert_type_flags(cert.cert_type))

    # Should we check if the cert is a CA cert?
    if options.check_ca:
        # CA Cert?
        is_ca, cert_type = cert.is_ca_cert(True)
        print
        print indented_output('is CA cert boolean', is_ca)
        print indented_output('is CA cert returned usages', nss.cert_type_flags(cert_type))

    print
    print indented_output('verifying usages for', nss.cert_usage_flags(intended_usage))
    print

    # Use the log or non-log variant to verify the cert
    #
    # Note: Anytime a NSPR or NSS function returns an error in python-nss it
    # raises a NSPRError exception. When an exception is raised the normal
    # return values are discarded because the flow of control continues at
    # the first except block prepared to catch the exception. Normally this
    # is what is desired because the return values would be invalid due to
    # the error. However the certificate verification functions are an
    # exception (no pun intended). An error might be returned indicating the
    # cert failed verification but you may still need access to the returned
    # usage bitmask and the log (if using the log variant). To handle this a
    # special error exception `CertVerifyError` (derived from `NSPRError`)
    # is defined which in addition to the normal NSPRError fields will also
    # contain the returned usages and optionally the CertVerifyLog
    # object. If no exception is raised these are returned as normal return
    # values.

    approved_usage = 0
    if options.with_log:
        try:
            approved_usage, log = cert.verify_with_log(certdb, options.check_sig, intended_usage, None)
        except nss_error.CertVerifyError, e:
            # approved_usage and log available in CertVerifyError exception on failure.
            print e
            print
            print indented_obj('log', e.log)
            print
            print indented_output('approved usages from exception', nss.cert_usage_flags(e.usages))
            approved_usage = e.usages # Get the returned usage bitmask from the exception
        except Exception, e:
            print e
        else:
            print indented_output('approved usages', nss.cert_usage_flags(approved_usage))
            if log.count:
                print
                print indented_obj('log', log)
    else:
        try:
            approved_usage = cert.verify(certdb, options.check_sig, intended_usage, None)
        except nss_error.CertVerifyError, e:
            # approved_usage available in CertVerifyError exception on failure.
            print e
            print indented_output('approved usages from exception', nss.cert_usage_flags(e.usages))
            approved_usage = e.usages # Get the returned usage bitmask from the exception
        except Exception, e:
            print e
        else:
            print indented_output('approved usages', nss.cert_usage_flags(approved_usage))

    # The cert is valid if all the intended usages are in the approved usages
    valid = (intended_usage & approved_usage) == intended_usage

    print
    if valid:
        print indented_output('SUCCESS: cert is approved for', nss.cert_usage_flags(intended_usage))
        return 0
    else:
        print indented_output('FAIL: cert not approved for', nss.cert_usage_flags(intended_usage ^ approved_usage))
        return 1

#-------------------------------------------------------------------------------
if __name__ == "__main__":
    sys.exit(main())
