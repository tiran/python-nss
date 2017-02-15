from __future__ import absolute_import
from __future__ import print_function

import argparse
import sys

from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl

#-------------------------------------------------------------------------------

TIMEOUT_SECS = 3

REQUEST = '''\
GET /index.html HTTP/1.0

'''
#-------------------------------------------------------------------------------

def print_suite_info(suite):
    print("Suite:")
    print("------")

    if not options.use_properties:
        print(suite)
    else:
        print("cipher_suite_name:     %s"  % (suite.cipher_suite_name))
        print("cipher_suite:          %#x" % (suite.cipher_suite))
        print("auth_algorithm_name:   %s"  % (suite.auth_algorithm_name))
        print("auth_algorithm:        %#x" % (suite.auth_algorithm))
        print("kea_type_name:         %s"  % (suite.kea_type_name))
        print("kea_type:              %#x" % (suite.kea_type))
        print("symmetric_cipher_name: %s"  % (suite.symmetric_cipher_name))
        print("symmetric_cipher:      %#x" % (suite.symmetric_cipher))
        print("symmetric_key_bits:    %s"  % (suite.symmetric_key_bits))
        print("symmetric_key_space:   %s"  % (suite.symmetric_key_space))
        print("effective_key_bits:    %s"  % (suite.effective_key_bits))
        print("mac_algorithm_name:    %s"  % (suite.mac_algorithm_name))
        print("mac_algorithm:         %#x" % (suite.mac_algorithm))
        print("mac_bits:              %s"  % (suite.mac_bits))
        print("is_fips:               %s"  % (suite.is_fips))
        print("is_exportable:         %s"  % (suite.is_exportable))
        print("is_nonstandard:        %s"  % (suite.is_nonstandard))

def print_channel_info(channel):
    print("Channel:")
    print("--------")

    if not options.use_properties:
        print(channel)
    else:
        print("protocol_version:        %#x" % (channel.protocol_version))
        print("protocol_version string: %s"  % (channel.protocol_version_str))
        print("protocol_version enum:   %#x" % (channel.protocol_version_enum))
        print("major_protocol_version:  %s"  % (channel.major_protocol_version))
        print("minor_protocol_version:  %s"  % (channel.minor_protocol_version))
        print("cipher_suite:            %#x" % (channel.cipher_suite))
        print("auth_key_bits:           %d"  % (channel.auth_key_bits))
        print("kea_key_bits:            %d"  % (channel.kea_key_bits))
        print("creation_time:           %s"  % (channel.creation_time))
        print("last_access_time:        %s"  % (channel.last_access_time))
        print("expiration_time:         %s"  % (channel.expiration_time))
        print("creation_time_utc:       %s"  % (channel.creation_time_utc))
        print("last_access_time_utc:    %s"  % (channel.last_access_time_utc))
        print("expiration_time_utc:     %s"  % (channel.expiration_time_utc))
        print("compression_method:      %#x" % (channel.compression_method))
        print("compression_method_name: %s"  % (channel.compression_method_name))
        print("session_id:              %s"  % (channel.session_id))

def handshake_callback(sock):

    print("handshake complete, peer = %s, negotiated host = %s" %
          (sock.get_peer_name(), sock.get_negotiated_host()))
    print("Connection Info:")
    print(sock.connection_info_str())
    print()

    channel = sock.get_ssl_channel_info()
    print_channel_info(channel)
    print()

    suite = ssl.get_cipher_suite_info(channel.cipher_suite)
    print_suite_info(suite)

def ssl_connect():
    print("SSL connect to: %s" % options.hostname)

    valid_addr = False
    # Get the IP Address of our server
    try:
        addr_info = io.AddrInfo(options.hostname)
    except:
        print("ERROR: could not resolve hostname \"%s\"" % options.hostname)
        return

    for net_addr in addr_info:
        net_addr.port = options.port
        sock = ssl.SSLSocket(net_addr.family)
        # Set client SSL socket options
        sock.set_ssl_option(ssl.SSL_SECURITY, True)
        sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        sock.set_hostname(options.hostname)
        try:
            sock.set_ssl_version_range("tls1.0", "tls1.3")
        except NSPRError as e:
            print("Cannot enable TLS 1.3, {}".format(e))

        # Provide a callback which notifies us when the SSL handshake is
        # complete
        sock.set_handshake_callback(handshake_callback)

        try:
            print("try connecting to: %s" % (net_addr))
            sock.connect(net_addr, timeout=io.seconds_to_interval(TIMEOUT_SECS))
            print("connected to: %s" % (net_addr))
            valid_addr = True
            break
        except:
            continue

    if not valid_addr:
        print("ERROR: could not connect to \"%s\"" % options.hostname)
        return

    try:
        # Talk to the server
        n_received = 0
        sock.send(REQUEST.encode('utf-8'))
        while True:
            buf = sock.recv(1024)
            n_received += len(buf)
            if not buf:
                break
    except Exception as e:
        print(e)
        sock.shutdown()
        return

    sock.shutdown()
    return


# -----------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description='Example showing how to enumerate cipher suites and '
    'get their properties as well as how to get SSL channel information '
    'after connecting including the cipher suite in use',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-d', '--db-name',
                    help='NSS database name (e.g. "sql:pki")')

parser.add_argument('-H', '--hostname',
                    help='host to connect to')

parser.add_argument('-p', '--port', type=int,
                    help='host port')

parser.add_argument('-E', '--no-enumerate-cipher-suites',
                    dest='enumerate_cipher_suites',
                    action='store_false',
                    help='do not enumerate cipher suites')

parser.add_argument('-S', '--no-ssl-connect',
                    dest='ssl_connect',
                    action='store_false',
                    help='do not perform SSL connection')

parser.add_argument('-P', '--use-properties',
                    dest='use_properties',
                    action='store_true',
                    help='print using object properties')

parser.set_defaults(db_name='sql:pki',
                    hostname='www.verisign.com',
                    port=443,
                    enumerate_cipher_suites=True,
                    ssl_connect=True,
                    use_properties=False)

options = parser.parse_args()

# Perform basic configuration and setup
try:
    nss.nss_init(options.db_name)
    ssl.set_domestic_policy()

except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)


if options.enumerate_cipher_suites:
    suite_info = ssl.get_cipher_suite_info(ssl.ssl_implemented_ciphers[0])

    print("There are %d implemented ciphers" %
          (len(ssl.ssl_implemented_ciphers)))

    for cipher in ssl.ssl_implemented_ciphers:
        suite_info = ssl.get_cipher_suite_info(cipher)
        print(suite_info)
        print()

if options.ssl_connect:
    ssl_connect()
