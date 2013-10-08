#!/usr/bin/python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import getpass
import os
import sys

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl

# -----------------------------------------------------------------------------

timeout_secs = 3

request = '''\
GET /index.html HTTP/1.0

'''
# -----------------------------------------------------------------------------
# Callback Functions
# -----------------------------------------------------------------------------

def handshake_callback(sock):
    print "handshake complete, peer = %s" % (sock.get_peer_name())

def auth_certificate_callback(sock, check_sig, is_server, certdb):
    print "auth_certificate_callback: check_sig=%s is_server=%s" % (check_sig, is_server)
    cert_is_valid = False

    cert = sock.get_peer_certificate()
    pin_args = sock.get_pkcs11_pin_arg()
    if pin_args is None:
        pin_args = ()

    print "cert:\n%s" % cert

    # Define how the cert is being used based upon the is_server flag.  This may
    # seem backwards, but isn't. If we're a server we're trying to validate a
    # client cert. If we're a client we're trying to validate a server cert.
    if is_server:
        intended_usage = nss.certificateUsageSSLClient
    else:
        intended_usage = nss.certificateUsageSSLServer

    try:
        # If the cert fails validation it will raise an exception, the errno attribute
        # will be set to the error code matching the reason why the validation failed
        # and the strerror attribute will contain a string describing the reason.
        approved_usage = cert.verify_now(certdb, check_sig, intended_usage, *pin_args)
    except Exception, e:
        print e.strerror
        cert_is_valid = False
        print "Returning cert_is_valid = %s" % cert_is_valid
        return cert_is_valid

    print "approved_usage = %s" % nss.cert_usage_flags(approved_usage)

    # Is the intended usage a proper subset of the approved usage
    if approved_usage & intended_usage:
        cert_is_valid = True
    else:
        cert_is_valid = False

    # If this is a server, we're finished
    if is_server or not cert_is_valid:
        print "Returning cert_is_valid = %s" % cert_is_valid
        return cert_is_valid

    # Certificate is OK.  Since this is the client side of an SSL
    # connection, we need to verify that the name field in the cert
    # matches the desired hostname.  This is our defense against
    # man-in-the-middle attacks.

    hostname = sock.get_hostname()
    print "verifying socket hostname (%s) matches cert subject (%s)" % (hostname, cert.subject)
    try:
        # If the cert fails validation it will raise an exception
        cert_is_valid = cert.verify_hostname(hostname)
    except Exception, e:
        print e.strerror
        cert_is_valid = False
        print "Returning cert_is_valid = %s" % cert_is_valid
        return cert_is_valid

    print "Returning cert_is_valid = %s" % cert_is_valid
    return cert_is_valid

# -----------------------------------------------------------------------------
# Client Implementation
# -----------------------------------------------------------------------------

def client():
    valid_addr = False
    # Get the IP Address of our server
    try:
        addr_info = io.AddrInfo(options.hostname)
    except:
        print "ERROR: could not resolve hostname \"%s\"" % options.hostname
        return

    for net_addr in addr_info:
        net_addr.port = options.port
        sock = ssl.SSLSocket(net_addr.family)
        # Set client SSL socket options
        sock.set_ssl_option(ssl.SSL_SECURITY, True)
        sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        sock.set_hostname(options.hostname)

        # Provide a callback which notifies us when the SSL handshake is
        # complete
        sock.set_handshake_callback(handshake_callback)

        # Provide a callback to verify the servers certificate
        sock.set_auth_certificate_callback(auth_certificate_callback,
                                           nss.get_default_certdb())

        try:
            print "try connecting to: %s" % (net_addr)
            sock.connect(net_addr, timeout=io.seconds_to_interval(timeout_secs))
            print "connected to: %s" % (net_addr)
            valid_addr = True
            break
        except:
            continue

    if not valid_addr:
        print "ERROR: could not connect to \"%s\"" % options.hostname
        return

    try:
        # Talk to the server
        n_received = 0
        sock.send(request)
        while True:
            buf = sock.recv(1024)
            n_received += len(buf)
            if not buf:
                print "\nclient lost connection, received %d bytes" % (n_received)
                break
    except Exception, e:
        print e.strerror
        sock.shutdown()
        return

    sock.shutdown()
    return

# -----------------------------------------------------------------------------

parser = argparse.ArgumentParser(description='certificate verification example',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-d', '--db-name',
                    help='NSS database name (e.g. "sql:pki")')

parser.add_argument('-H', '--hostname',
                    help='host to connect to')

parser.add_argument('-p', '--port', type=int,
                    help='host port')

parser.set_defaults(db_name = 'sql:pki',
                    hostname = 'www.verisign.com',
                    port = 443,
                    )

options = parser.parse_args()

# Perform basic configuration and setup
try:
    nss.nss_init(options.db_name)
    ssl.set_domestic_policy()
except Exception, e:
    print >>sys.stderr, e.strerror
    sys.exit(1)

client()
