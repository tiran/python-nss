#!/usr/bin/python

'''
In NSS 3.14 the SSL Version Range API was added. This was needed
to better control the negotiation of SSL and TLS protocols between
clients and servers. Properly configuring the min and max protocols is
especially important to prevent protocol downgrade attacks such as
POODLE. The SSL Version Range API is documented in the nss.ssl module
documentation as well as the individual functions and methods in
nss.ssl.

This example program illustrates how to query the current and default
protocol values, how one can get string versions of the protocol
values to present to a user or use in logging, and how to set the
protocol values given either a string name or it's matching
enumeration.

This example does not illustrate the proper selection of protocol
values nor actual SSL/TLS communication.
'''


from nss.error import NSPRError
import nss.io as io
import nss.nss as nss
import nss.ssl as ssl


# Query and print supported SSL Library Versions

print "supported ssl version (asString): %s" % \
    (ssl.get_supported_ssl_version_range(repr_kind=nss.AsString),)
print "supported ssl version (asEnumName): %s" % \
    (ssl.get_supported_ssl_version_range(repr_kind=nss.AsEnumName),)
print "supported ssl version (asEnum): %s" % \
    (ssl.get_supported_ssl_version_range(),)

# Query and print default SSL Library Versions

print
print "default ssl version (asString): %s" % \
    (ssl.get_default_ssl_version_range(repr_kind=nss.AsString),)
print "default ssl version (asEnumName): %s" % \
    (ssl.get_default_ssl_version_range(repr_kind=nss.AsEnumName),)
print "default ssl version (asEnum): %s" % \
    (ssl.get_default_ssl_version_range(),)

# Equivalent calls on a SSL Socket

sock = ssl.SSLSocket()
sock.set_ssl_option(ssl.SSL_SECURITY, True)

print
print "Initial Socket version range"
print "socket ssl version (asString): %s" % \
    (sock.get_ssl_version_range(repr_kind=nss.AsString),)
print "socket ssl version (asEnumName): %s" % \
    (sock.get_ssl_version_range(repr_kind=nss.AsEnumName),)
print "socket ssl version (asEnum): %s" % \
    (sock.get_ssl_version_range(),)


# Note, setting the version range can be done either with an
# enumeration constant (e.g. ssl.SSL_LIBRARY_VERSION_TLS_1_1)
# or with a friendly name (e.g. 'tls1.1')

# Set with enumeration constants
sock.set_ssl_version_range(ssl.SSL_LIBRARY_VERSION_TLS_1_1,
                           ssl.SSL_LIBRARY_VERSION_TLS_1_2)


print
print "Socket version range after seting"
print "socket ssl version (asString): %s" % \
    (sock.get_ssl_version_range(repr_kind=nss.AsString),)
print "socket ssl version (asEnumName): %s" % \
    (sock.get_ssl_version_range(repr_kind=nss.AsEnumName),)
print "socket ssl version (asEnum): %s" % \
    (sock.get_ssl_version_range(),)

# Set with friendly names
ssl.set_default_ssl_version_range('tls1.1', 'tls1.2')

print
print "default ssl version after resetting (asString): %s" % \
    (ssl.get_default_ssl_version_range(repr_kind=nss.AsString),)
print "default ssl version after resetting (asEnumName): %s" % \
    (ssl.get_default_ssl_version_range(repr_kind=nss.AsEnumName),)
print "default ssl version after resetting (asEnum): %s" % \
    (ssl.get_default_ssl_version_range(),)

# Illustrate mapping between version names and enumerations.
# Note, the repr_kind parameter to the get library version functions
# will also give you the option as to whether an enumerated constant
# or a name is returned.

names = [
    'ssl2', 'ssl3',
    'tls1.0', 'tls1.1', 'tls1.2', 'tls1.3',
    'SSL_LIBRARY_VERSION_2',
    'SSL_LIBRARY_VERSION_3_0',
    'SSL_LIBRARY_VERSION_TLS_1_0',
    'SSL_LIBRARY_VERSION_TLS_1_1',
    'SSL_LIBRARY_VERSION_TLS_1_2',
    'SSL_LIBRARY_VERSION_TLS_1_3',
    ]

print
print "Convert to enum name"
for name in names:
    enum = ssl.ssl_library_version_from_name(name)
    enum_name = ssl.ssl_library_version_name(enum)
    print "name='%s' -> %s (%#06x)" % (name, enum_name, enum)

print
print "Convert to friendly name"
for name in names:
    enum = ssl.ssl_library_version_from_name(name)
    enum_name = ssl.ssl_library_version_name(enum, nss.AsString)
    print "name='%s' -> %s (%#06x)" % (name, enum_name, enum)


