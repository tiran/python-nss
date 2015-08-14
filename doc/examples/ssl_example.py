from __future__ import absolute_import
from __future__ import print_function

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import warnings
warnings.simplefilter( "always", DeprecationWarning)

import argparse
import getpass
import os
import sys

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl

# -----------------------------------------------------------------------------
NO_CLIENT_CERT             = 0
REQUEST_CLIENT_CERT_ONCE   = 1
REQUIRE_CLIENT_CERT_ONCE   = 2
REQUEST_CLIENT_CERT_ALWAYS = 3
REQUIRE_CLIENT_CERT_ALWAYS = 4

timeout_secs = 3

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Callback Functions
# -----------------------------------------------------------------------------

def password_callback(slot, retry, password):
    if password: return password
    return getpass.getpass("Enter password: ");

def handshake_callback(sock):
    print("-- handshake complete --")
    print("peer: %s" % (sock.get_peer_name()))
    print("negotiated host: %s" % (sock.get_negotiated_host()))
    print()
    print(sock.connection_info_str())
    print("-- handshake complete --")
    print()

def auth_certificate_callback(sock, check_sig, is_server, certdb):
    print("auth_certificate_callback: check_sig=%s is_server=%s" % (check_sig, is_server))
    cert_is_valid = False

    cert = sock.get_peer_certificate()
    pin_args = sock.get_pkcs11_pin_arg()
    if pin_args is None:
        pin_args = ()

    print("peer cert:\n%s" % cert)

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
    except Exception as e:
        print(e)
        cert_is_valid = False
        print("Returning cert_is_valid = %s" % cert_is_valid)
        return cert_is_valid

    print("approved_usage = %s" % ', '.join(nss.cert_usage_flags(approved_usage)))

    # Is the intended usage a proper subset of the approved usage
    if approved_usage & intended_usage:
        cert_is_valid = True
    else:
        cert_is_valid = False

    # If this is a server, we're finished
    if is_server or not cert_is_valid:
        print("Returning cert_is_valid = %s" % cert_is_valid)
        return cert_is_valid

    # Certificate is OK.  Since this is the client side of an SSL
    # connection, we need to verify that the name field in the cert
    # matches the desired hostname.  This is our defense against
    # man-in-the-middle attacks.

    hostname = sock.get_hostname()
    print("verifying socket hostname (%s) matches cert subject (%s)" % (hostname, cert.subject))
    try:
        # If the cert fails validation it will raise an exception
        cert_is_valid = cert.verify_hostname(hostname)
    except Exception as e:
        print(e)
        cert_is_valid = False
        print("Returning cert_is_valid = %s" % cert_is_valid)
        return cert_is_valid

    print("Returning cert_is_valid = %s" % cert_is_valid)
    return cert_is_valid

def client_auth_data_callback(ca_names, chosen_nickname, password, certdb):
    cert = None
    if chosen_nickname:
        try:
            cert = nss.find_cert_from_nickname(chosen_nickname, password)
            priv_key = nss.find_key_by_any_cert(cert, password)
            print("client cert:\n%s" % cert)
            return cert, priv_key
        except NSPRError as e:
            print(e)
            return False
    else:
        nicknames = nss.get_cert_nicknames(certdb, cert.SEC_CERT_NICKNAMES_USER)
        for nickname in nicknames:
            try:
                cert = nss.find_cert_from_nickname(nickname, password)
                print("client cert:\n%s" % cert)
                if cert.check_valid_times():
                    if cert.has_signer_in_ca_names(ca_names):
                        priv_key = nss.find_key_by_any_cert(cert, password)
                        return cert, priv_key
            except NSPRError as e:
                print(e)
        return False

# -----------------------------------------------------------------------------
# Client Implementation
# -----------------------------------------------------------------------------

def Client():
    valid_addr = False
    # Get the IP Address of our server
    try:
        addr_info = io.AddrInfo(options.hostname)
    except Exception as e:
        print("could not resolve host address \"%s\"" % options.hostname)
        return

    for net_addr in addr_info:
        if options.family != io.PR_AF_UNSPEC:
            if net_addr.family != options.family:
                continue
        net_addr.port = options.port

        if options.use_ssl:
            sock = ssl.SSLSocket(net_addr.family)

            # Set client SSL socket options
            sock.set_ssl_option(ssl.SSL_SECURITY, True)
            sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
            sock.set_hostname(options.hostname)

            # Provide a callback which notifies us when the SSL handshake is complete
            sock.set_handshake_callback(handshake_callback)

            # Provide a callback to supply our client certificate info
            sock.set_client_auth_data_callback(client_auth_data_callback, options.client_nickname,
                                               options.password, nss.get_default_certdb())

            # Provide a callback to verify the servers certificate
            sock.set_auth_certificate_callback(auth_certificate_callback,
                                               nss.get_default_certdb())
        else:
            sock = io.Socket(net_addr.family)

        try:
            print("client trying connection to: %s" % (net_addr))
            sock.connect(net_addr, timeout=io.seconds_to_interval(timeout_secs))
            print("client connected to: %s" % (net_addr))
            valid_addr = True
            break
        except Exception as e:
            sock.close()
            print("client connection to: %s failed (%s)" % (net_addr, e))

    if not valid_addr:
        print("Could not establish valid address for \"%s\" in family %s" % \
        (options.hostname, io.addr_family_name(options.family)))
        return

    # Talk to the server
    try:
        data = 'Hello' + '\n' # newline is protocol record separator
        sock.send(data.encode('utf-8'))
        buf = sock.readline()
        if not buf:
            print("client lost connection")
            sock.close()
            return
        buf = buf.decode('utf-8')
        buf = buf.rstrip()        # remove newline record separator
        print("client received: %s" % (buf))
    except Exception as e:
        print(e.strerror)
        try:
            sock.close()
        except:
            pass
        return

    # End of (simple) protocol session?
    if buf == 'Goodbye':
        try:
            sock.shutdown()
        except:
            pass

    try:
        sock.close()
        if options.use_ssl:
            ssl.clear_session_cache()
    except Exception as e:
        print(e)

# -----------------------------------------------------------------------------
# Server Implementation
# -----------------------------------------------------------------------------

def Server():
    # Setup an IP Address to listen on any of our interfaces
    if options.family == io.PR_AF_UNSPEC:
        options.family = io.PR_AF_INET
    net_addr = io.NetworkAddress(io.PR_IpAddrAny, options.port, options.family)

    if options.use_ssl:
        # Perform basic SSL server configuration
        ssl.set_default_cipher_pref(ssl.SSL_RSA_WITH_NULL_MD5, True)
        ssl.config_server_session_id_cache()

        # Get our certificate and private key
        server_cert = nss.find_cert_from_nickname(options.server_nickname, options.password)
        priv_key = nss.find_key_by_any_cert(server_cert, options.password)
        server_cert_kea = server_cert.find_kea_type();

        print("server cert:\n%s" % server_cert)

        sock = ssl.SSLSocket(net_addr.family)

        # Set server SSL socket options
        sock.set_pkcs11_pin_arg(options.password)
        sock.set_ssl_option(ssl.SSL_SECURITY, True)
        sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_SERVER, True)

        # If we're doing client authentication then set it up
        if options.client_cert_action >= REQUEST_CLIENT_CERT_ONCE:
            sock.set_ssl_option(ssl.SSL_REQUEST_CERTIFICATE, True)
        if options.client_cert_action == REQUIRE_CLIENT_CERT_ONCE:
            sock.set_ssl_option(ssl.SSL_REQUIRE_CERTIFICATE, True)
        sock.set_auth_certificate_callback(auth_certificate_callback, nss.get_default_certdb())

        # Configure the server SSL socket
        sock.config_secure_server(server_cert, priv_key, server_cert_kea)

    else:
        sock = io.Socket(net_addr.family)

    # Bind to our network address and listen for clients
    sock.bind(net_addr)
    print("listening on: %s" % (net_addr))
    sock.listen()

    while True:
        # Accept a connection from a client
        client_sock, client_addr = sock.accept()
        if options.use_ssl:
            client_sock.set_handshake_callback(handshake_callback)

        print("client connect from: %s" % (client_addr))

        while True:
            try:
                # Handle the client connection
                buf = client_sock.readline()
                if not buf:
                    print("server lost lost connection to %s" % (client_addr))
                    break

                buf = buf.decode('utf-8')
                buf = buf.rstrip()                 # remove newline record separator
                print("server received: %s" % (buf))

                data ='Goodbye' + '\n' # newline is protocol record separator
                client_sock.send(data.encode('utf-8'))
                try:
                    client_sock.shutdown(io.PR_SHUTDOWN_RCV)
                    client_sock.close()
                except:
                    pass
                break
            except Exception as e:
                print(e.strerror)
                break
        break

    try:
        sock.shutdown()
        sock.close()
        if options.use_ssl:
            ssl.shutdown_server_session_id_cache()
    except Exception as e:
        print(e)
        pass

# -----------------------------------------------------------------------------

class FamilyArgAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        value = values[0]
        if value == "inet":
            family = io.PR_AF_INET
        elif value == "inet6":
            family = io.PR_AF_INET6
        elif value == "unspec":
            family = io.PR_AF_UNSPEC
        else:
            raise argparse.ArgumentError(self, "unknown address family (%s)" % (value))
        setattr(namespace, self.dest, family)

parser = argparse.ArgumentParser(description='SSL example')

parser.add_argument('-C', '--client', action='store_true',
                    help='run as the client')

parser.add_argument('-S', '--server', action='store_true',
                    help='run as the server')

parser.add_argument('-d', '--db-name',
                    help='NSS database name (e.g. "sql:pki")')

parser.add_argument('-H', '--hostname',
                    help='host to connect to')

parser.add_argument('-f', '--family',
                    choices=['unspec', 'inet', 'inet6'],
                    dest='family', action=FamilyArgAction, nargs=1,
                    help='''
                      If unspec client tries all addresses returned by AddrInfo,
                      server binds to IPv4 "any" wildcard address.

                      If inet client tries IPv4 addresses returned by AddrInfo,
                      server binds to IPv4 "any" wildcard address.

                      If inet6 client tries IPv6 addresses returned by AddrInfo,
                      server binds to IPv6 "any" wildcard address''')

parser.add_argument('-4', '--inet',
                    dest='family', action='store_const', const=io.PR_AF_INET,
                    help='set family to inet (see family)')

parser.add_argument('-6', '--inet6',
                    dest='family', action='store_const', const=io.PR_AF_INET6,
                    help='set family to inet6 (see family)')

parser.add_argument('-n', '--server-nickname',
                    help='server certificate nickname')

parser.add_argument('-N', '--client-nickname',
                    help='client certificate nickname')

parser.add_argument('-w', '--password',
                    help='certificate database password')

parser.add_argument('-p', '--port', type=int,
                    help='host port')

parser.add_argument('-e', '--encrypt', dest='use_ssl', action='store_true',
                    help='use SSL connection')

parser.add_argument('-E', '--no-encrypt', dest='use_ssl', action='store_false',
                    help='do not use SSL connection')

parser.add_argument('--require-cert-once', dest='client_cert_action',
                    action='store_const', const=REQUIRE_CLIENT_CERT_ONCE)

parser.add_argument('--require-cert-always', dest='client_cert_action',
                    action='store_const', const=REQUIRE_CLIENT_CERT_ALWAYS)

parser.add_argument('--request-cert-once', dest='client_cert_action',
                    action='store_const', const=REQUEST_CLIENT_CERT_ONCE)

parser.add_argument('--request-cert-always', dest='client_cert_action',
                    action='store_const', const=REQUEST_CLIENT_CERT_ALWAYS)

parser.add_argument('--min-ssl-version',
                    help='minimum SSL version')

parser.add_argument('--max-ssl-version',
                    help='minimum SSL version')

parser.set_defaults(client = False,
                    server = False,
                    db_name = 'sql:pki',
                    hostname = os.uname()[1],
                    family = io.PR_AF_UNSPEC,
                    server_nickname = 'test_server',
                    client_nickname = 'test_user',
                    password = 'DB_passwd',
                    port = 1234,
                    use_ssl = True,
                    client_cert_action = NO_CLIENT_CERT,
                   )

options = parser.parse_args()

if options.client and options.server:
    print("can't be both client and server")
    sys.exit(1)
if not (options.client or options.server):
    print("must be one of client or server")
    sys.exit(1)

# Perform basic configuration and setup
if options.use_ssl:
    nss.nss_init(options.db_name)
else:
    nss.nss_init_nodb()

ssl.set_domestic_policy()
nss.set_password_callback(password_callback)

min_ssl_version, max_ssl_version = \
    ssl.get_supported_ssl_version_range(repr_kind=nss.AsString)
print("Supported SSL version range: min=%s, max=%s" % \
    (min_ssl_version, max_ssl_version))

min_ssl_version, max_ssl_version = \
    ssl.get_default_ssl_version_range(repr_kind=nss.AsString)
print("Default SSL version range: min=%s, max=%s" % \
    (min_ssl_version, max_ssl_version))

if options.min_ssl_version is not None or \
   options.max_ssl_version is not None:

    if options.min_ssl_version is not None:
        min_ssl_version  = options.min_ssl_version
    if options.max_ssl_version is not None:
        max_ssl_version  = options.max_ssl_version

    print("Setting default SSL version range: min=%s, max=%s" % \
        (min_ssl_version, max_ssl_version))
    ssl.set_default_ssl_version_range(min_ssl_version, max_ssl_version)

    min_ssl_version, max_ssl_version = \
        ssl.get_default_ssl_version_range(repr_kind=nss.AsString)
    print("Default SSL version range now: min=%s, max=%s" % \
        (min_ssl_version, max_ssl_version))

# Run as a client or as a serveri
if options.client:
    print("starting as client")
    Client()

if options.server:
    print("starting as server")
    Server()

try:
    nss.nss_shutdown()
except Exception as e:
    print(e)
