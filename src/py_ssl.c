/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// FIXME: sometimes in the API dist_name is used and sometimes ca_name, make consistent.
// FIXME: PyIntObjects represent their value as a long, but in many places we declared their C representation as
//        as int, we should change it to long, and at the same time match the parameters used in the NSPR/NSS API

#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "structmember.h"

#include "py_nspr_common.h"
#include "py_nspr_io.h"
#define NSS_SSL_MODULE
#include "py_ssl.h"
#include "py_nss.h"
#include "py_shared_doc.h"
#include "py_nspr_error.h"

#include "sslproto.h"           /* for cipher constants */

static PyObject *empty_tuple = NULL;

static PyObject *py_ssl_implemented_ciphers = NULL;

static PyObject *cipher_suite_name_to_value = NULL;
static PyObject *cipher_suite_value_to_name = NULL;

static PyObject *ssl_library_version_name_to_value = NULL;
static PyObject *ssl_library_version_value_to_name = NULL;

static PyObject *ssl_library_version_alias_to_value = NULL;
static PyObject *ssl_library_version_value_to_alias = NULL;

static PyObject *
ssl_version_to_repr_kind(unsigned int major, unsigned int minor,
                         RepresentationKind repr_kind);

static PyObject *
ssl_library_version_to_repr_kind(unsigned long version_enum,
                                 RepresentationKind repr_kind);

static PyObject *
ssl_library_version_to_py_enum_name(unsigned long ssl_library_version);

static PyObject *
ssl_library_version_to_py_string(unsigned long ssl_library_version);

static SECStatus
ssl_library_version_from_name(PyObject *py_name, unsigned long *version_enum);

static SECStatus
ssl_library_version_from_pyobject(PyObject *py_value, const char *bound, unsigned long *version_enum);

static PyObject *
SSLChannelInformation_new_from_SSLChannelInfo(SSLChannelInfo *info);


static PyObject *
cipher_suite_to_name(unsigned long cipher_suite)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyLong_FromLong(cipher_suite)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create object");
        return NULL;
    }

    if ((py_name = PyDict_GetItem(cipher_suite_value_to_name, py_value)) == NULL) {
        Py_DECREF(py_value);
	PyErr_Format(PyExc_KeyError, "cipher suite name not found: %lu", cipher_suite);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}


static SECStatus
cipher_suite_from_name(PyObject *py_name, unsigned long *suite)
{
    PyObject *py_lower_name;
    PyObject *py_value;

    if (!PyBaseString_Check(py_name)) {
        PyErr_Format(PyExc_TypeError, "cipher suite name must be a string, not %.200s",
                     Py_TYPE(py_name)->tp_name);

        return SECFailure;
    }

    if ((py_lower_name = PyUnicode_Lower(py_name)) == NULL) {
        return SECFailure;
    }

    if ((py_value = PyDict_GetItem(cipher_suite_name_to_value, py_lower_name)) == NULL) {
        PyObject *py_name_utf8 = PyBaseString_UTF8(py_name, "name");
        PyErr_Format(PyExc_KeyError, "cipher suite name not found: %s", PyBytes_AsString(py_name_utf8));
        Py_DECREF(py_lower_name);
        Py_XDECREF(py_name_utf8);
        return SECFailure;
    }

    Py_DECREF(py_lower_name);

    *suite = PyLong_AsUnsignedLong(py_value);

    return SECSuccess;
}

static PyObject *
SSLSocket_new_from_PRFileDesc(PRFileDesc *pr_socket, int family)
{
    SSLSocket *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (SSLSocket *) SSLSocketType.tp_new(&SSLSocketType, NULL, NULL)) == NULL) {
        return NULL;
    }

    Socket_init_from_PRFileDesc((Socket *)self, pr_socket, family);

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ============================= SSLSocket Class ============================ */
/* ========================================================================== */

#if 0
static SECStatus
tuple_to_SSLVersionRange(PyObject *tuple, SSLVersionRange *range)
{
    PyObject *py_min, *py_max;
    unsigned long min, max;

    TraceMethodEnter(self);

    if (!PyTuple_Check(tuple)) {
        PyErr_Format(PyExc_TypeError, "ssl_version_range must be a tuple, not %.200s",
                     Py_TYPE(tuple)->tp_name);
        return SECFailure;
    }

    if (PyTuple_Size(tuple) != 2) {
        PyErr_Format(PyExc_TypeError, "ssl_version_range must be a tuple with 2 values, not %zd values",
                     PyTuple_Size(tuple));
        return SECFailure;
    }

    py_min = PyTuple_GetItem(tuple, 0);
    if (ssl_library_version_from_pyobject(py_min, "min", &min) != SECSuccess) {
        return SECFailure;
    }

    py_max = PyTuple_GetItem(tuple, 1);
    if (ssl_library_version_from_pyobject(py_max, "max", &max) != SECSuccess) {
        return SECFailure;
    }

    range->min = min;
    range->max = max;

    return SECSuccess;

}
#endif

static PyObject *
ssl_version_to_repr_kind(unsigned int major, unsigned int minor,
                         RepresentationKind repr_kind)
{
    unsigned long version_enum;

    switch(major) {
    case 3:
        switch(minor) {
        case 0:
            version_enum = SSL_LIBRARY_VERSION_3_0;
            break;
        case 1:
            version_enum = SSL_LIBRARY_VERSION_TLS_1_0;
            break;
        case 2:
            version_enum = SSL_LIBRARY_VERSION_TLS_1_1;
            break;
        case 3:
            version_enum = SSL_LIBRARY_VERSION_TLS_1_2;
            break;
        case 4:
            version_enum = SSL_LIBRARY_VERSION_TLS_1_3;
            break;
        default:
            PyErr_Format(PyExc_ValueError,
                         "Verson %d.%d has unkown minor version",
                         major, minor);
            return NULL;
        }
        break;
    default:
        PyErr_Format(PyExc_ValueError,
                     "Verson %d.%d has unkown major version",
                     major, minor);
        return NULL;
    }

    switch(repr_kind) {
    case AsEnum:
        return PyLong_FromLong(version_enum);
    case AsEnumName: {
        return ssl_library_version_to_py_enum_name(version_enum);
    } break;
    case AsString: {
        return ssl_library_version_to_py_string(version_enum);
    } break;
    default:
        PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind);
        return NULL;
    }
}

static PyObject *
ssl_library_version_to_repr_kind(unsigned long version_enum,
                                 RepresentationKind repr_kind)
{
    switch(repr_kind) {
    case AsEnum:
        return PyLong_FromLong(version_enum);
    case AsEnumName: {
        return ssl_library_version_to_py_enum_name(version_enum);
    } break;
    case AsString: {
        return ssl_library_version_to_py_string(version_enum);
    } break;
    default:
        PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind);
        return NULL;
    }
}

static PyObject *
SSLVersionRange_to_tuple(SSLVersionRange *range, RepresentationKind repr_kind)
{
    PyObject *tuple = NULL;
    PyObject *py_min = NULL;
    PyObject *py_max = NULL;

    if ((tuple = PyTuple_New(2)) == NULL) {
        return NULL;
    }

    if ((py_min = ssl_library_version_to_repr_kind(range->min, repr_kind)) == NULL) {
        Py_DECREF(tuple);
        return NULL;
    }

    if ((py_max = ssl_library_version_to_repr_kind(range->max, repr_kind)) == NULL) {
        Py_DECREF(tuple);
        return NULL;
    }

    PyTuple_SetItem(tuple, 0, py_min);
    PyTuple_SetItem(tuple, 1, py_max);

    return tuple;
}

/* ============================ Attribute Access ============================ */

static PyGetSetDef
SSLSocket_getseters[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef
SSLSocket_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(SSLSocket_set_ssl_option_doc,
"set_ssl_option(option, value)\n\
\n\
Sets a single configuration parameter on this socket. Call once for\n\
each parameter you want to change. The configuration parameters are\n\
listed below.\n\
\n\
SSL_SECURITY (default=True)\n\
    Enables use of security protocol. *WARNING: If you turn this option\n\
    off, the session will not be an SSL session and will not have\n\
    certificate-based authentication, tamper detection, or encryption.*\n\
SSL_REQUEST_CERTIFICATE: (default=False)\n\
    Is a server option that requests a client to authenticate itself.\n\
SSL_REQUIRE_CERTIFICATE: (default=SSL_REQUIRE_FIRST_HANDSHAKE)\n\
    Is a server option that requires a client to authenticate itself (only\n\
    if SSL_REQUEST_CERTIFICATE is also on). If client does not provide\n\
    certificate, the connection terminates.\n\
SSL_HANDSHAKE_AS_CLIENT: (default=False)\n\
    Controls the behavior of `SSLSocket.accept()`,. If this option is off,\n\
    the `SSLSocket.accept()` configures the SSL socket to handshake as a\n\
    server. If it is on, then `SSLSocket.accept()` configures the SSL socket\n\
    to handshake as a client, even though it accepted the connection as a\n\
    TCP server.\n\
SSL_HANDSHAKE_AS_SERVER: (default=False)\n\
    Controls the behavior of `SSLSocket.connect()`. If this option is off,\n\
    then `SSLSocket.connect()` configures the SSL socket to handshake as a\n\
    client. If it is on, then `SSLSocket.connect()` configures the SSL\n\
    socket to handshake as a server, even though it connected as a TCP\n\
    client.\n\
SSL_ENABLE_FDX: (default=False)\n\
    Tells the SSL library whether the application will have two threads,\n\
    one reading and one writing, or just one thread doing reads and writes\n\
    alternately. The factory setting for this option (which is the\n\
    default, unless the application changes the default) is off, which\n\
    means that the application will not do simultaneous reads and\n\
    writes. An application that needs to do simultaneous reads and writes\n\
    should set this to True.\n\
\n\
    In NSS 2.8, the SSL_ENABLE_FDX option only affects the behavior of\n\
    nonblocking SSL sockets. See the description below for more\n\
    information on this option.\n\
SSL_ENABLE_SSL3: (default=True)\n\
    Enables the application to communicate with SSL v3. If you turn this\n\
    option off, an attempt to establish a connection with a peer that\n\
    understands only SSL v3 will fail. [1]_\n\
SSL_ENABLE_SSL2: (default=True)\n\
    Enables the application to communicate with SSL v2. If you turn this\n\
    option off, an attempt to establish a connection with a peer that\n\
    understands only SSL v2 will fail. [1]_\n\
SSL_ENABLE_TLS: (default=True)\n\
    Is a peer of the SSL_ENABLE_SSL2 and SSL_ENABLE_SSL3 options. The IETF\n\
    standard Transport Layer Security (TLS) protocol, RFC 2246, is a\n\
    modified version of SSL3. It uses the SSL version number 3.1,\n\
    appearing to be a 'minor' revision of SSL3.0. NSS 2.8 supports TLS in\n\
    addition to SSL2 and SSL3. You can think of it as 'SSL_ENABLE_SSL3.1.'\n\
    See the description below for more information about this option. [1]_\n\
SSL_V2_COMPATIBLE_HELLO: (default=True)\n\
    Tells the SSL library whether or not to send SSL3 client hello\n\
    messages in SSL2-compatible format. If set to True, it will;\n\
    otherwise, it will not. See the description below for more information\n\
    on this option.\n\
SSL_NO_CACHE: (default=False)\n\
    Disallows use of the session cache. Factory setting is off. If you\n\
    turn this option on, this socket will be unable to resume a session\n\
    begun by another socket. When this socket's session is finished, no\n\
    other socket will be able to resume the session begun by this socket.\n\
SSL_ROLLBACK_DETECTION: (default=True)\n\
    Disables detection of a rollback attack. Factory setting is on. You\n\
    must turn this option off to interoperate with TLS clients ( such as\n\
    certain versions of Microsoft Internet Explorer) that do not conform\n\
    to the TLS specification regarding rollback attacks. Important:\n\
    turning this option off means that your code will not comply with the\n\
    TLS 3.1 and SSL 3.0 specifications regarding rollback attack and will\n\
    therefore be vulnerable to this form of attack.\n\
    \n\
Keep the following in mind when deciding on the operating parameters\n\
you want to use with a particular socket.\n\
\n\
Turning on SSL_REQUIRE_CERTIFICATE will have no effect unless\n\
SSL_REQUEST_CERTIFICATE is also turned on. If you enable\n\
SSL_REQUEST_CERTIFICATE, then you should explicitly enable or disable\n\
SSL_REQUIRE_CERTIFICATE rather than allowing it to default. Enabling\n\
the SSL_REQUIRE_CERTIFICATE option is not recommended. If the client\n\
has no certificate and this option is enabled, the client's connection\n\
terminates with an error. The user is likely to think something is\n\
wrong with either the client or the server, and is unlikely to realize\n\
that the problem is the lack of a certificate. It is better to allow\n\
the SSL handshake to complete and then return an error message to the\n\
client that informs the user of the need for a certificate.\n\
\n\
The SSL protocol is defined to be able to handle simultaneous two-way\n\
communication between applications at each end of an SSL\n\
connection. Two-way simultaneous communication is also known as'Full\n\
Duplex', abbreviated FDX. However, most application protocols that use\n\
SSL are not two-way simultaneous, but two-way alternate, also known as\n\
'Half Dupled'; that is, each end takes turns sending, and each end is\n\
either sending, or receiving, but not both at the same time. For an\n\
application to do full duplex, it would have two threads sharing the\n\
socket; one doing all the reading and the other doing all the writing.\n\
\n\
The SSL_ENABLE_FDX option tells the SSL library whether the\n\
application will have two threads, one reading and one writing, or\n\
just one thread doing reads and writes alternately.\n\
\n\
If an SSL3 client hello message is sent to a server that only\n\
understands SSL2 and not SSL3, then the server will interpret the SSL3\n\
client hello as a very large message, and the connection will usually\n\
seem to 'hang' while the SSL2 server expects more data that will never\n\
arrive. For this reason, the SSL3 spec allows SSL3 client hellos to be\n\
sent in SSL2 format, and it recommends that SSL3 servers all accept\n\
SSL3 client hellos in SSL2 format. When an SSL2-only server receives\n\
an SSL3 client hello in SSL2 format, it can (and probably will)\n\
negotiate the protocol version correctly, not causing a 'hang'.\n\
\n\
Some applications may wish to force SSL3 client hellos to be sent in\n\
SSL3 format, not in SSL2-compatible format. They might wish to do this\n\
if they knew, somehow, that the server does not understand\n\
SSL2-compatible client hello messages.\n\
\n\
SSL_V2_COMPATIBLE_HELLO tells the SSL library whether or not to send\n\
SSL3 client hello messages in SSL2-compatible format. Note that\n\
calling `SSLSocket.set_ssl_option()` to set SSL_V2_COMPATIBLE_HELLO to\n\
False implicitly also sets the SSL_ENABLE_SSL2 option to False for\n\
that SSL socket. Calling SSL_EnableDefault to change the application\n\
default setting for SSL_V2_COMPATIBLE_HELLO to False implicitly also\n\
sets the default value for SSL_ENABLE_SSL2 option to False for that\n\
application.\n\
\n\
The options SSL_ENABLE_SSL2, SSL_ENABLE_SSL3, and SSL_ENABLE_TLS can\n\
each be set to True or False independently of each other. NSS 2.8 and\n\
later versions will negotiate the highest protocol version with the\n\
peer application from among the set of protocols that are commonly\n\
enabled in both applications. [1]_\n\
\n\
Note that SSL3 and TLS share the same set of cipher suites. When both\n\
SSL3 and TLS are enabled, all SSL3/TLS cipher suites that are enabled\n\
are enabled for both SSL3 and TLS.\n\
\n\
When an application imports a socket into SSL after the TCP connection\n\
on that socket has already been established, it must call\n\
`SSLSocket.reset_handshake()` to indicate whether the socket is for a\n\
client or server. At first glance this may seem unnecessary, since\n\
`SSLSocket.set_ssl_option()` can set SSL_HANDSHAKE_AS_CLIENT or\n\
SSL_HANDSHAKE_AS_SERVER. However, these settings control the behavior\n\
of `SSLSocket.connect()` and `SSLSocket.accept()` only; if you don't call\n\
one of those functions after importing a non-SSL socket with\n\
SSL_Import (as in the case of an already established TCP connection),\n\
SSL still needs to know whether the application is functioning as a\n\
client or server.\n\
\n\
If a socket file descriptor is imported as an SSL socket before it is\n\
connected, it is implicitly configured to handshake as a client or\n\
handshake as a server when the connection is made. If the application\n\
calls `SSLSocket.connect()` (connecting as a TCP client), then the SSL\n\
socket is (by default) configured to handshake as an SSL client. If\n\
the application calls `SSLSocket.accept()` (connecting the socket as a\n\
TCP server) then the SSL socket is (by default) configured to\n\
handshake as an SSL server. SSL_HANDSHAKE_AS_CLIENT and\n\
SSL_HANDSHAKE_AS_SERVER control this implicit configuration. Both\n\
SSL_HANDSHAKE_AS_CLIENT and SSL_HANDSHAKE_AS_SERVER are initially set\n\
to off--that is, the process default for both values is False when the\n\
process begins. The process default can be changed from the initial\n\
values by using SSL_EnableDefault, and the value for a particular\n\
socket can be changed by using `SSLSocket.set_ssl_option()`.\n\
\n\
If a socket that is already connected gets imported into SSL after it\n\
has been connected (that is, after `SSLSocket.accept()` or\n\
`SSLSocket.connect()` has returned), then no implicit SSL handshake\n\
configuration as a client or server will have been done by\n\
`SSLSocket.connect()` or `SSLSocket.accept()` on that socket. In this\n\
case, a call to `SSLSocket.reset_handshake()` is required to explicitly\n\
configure the socket to handshake as a client or as a server. If\n\
`SSLSocket.reset_handshake()` is not called to explicitly configure the\n\
socket handshake, a crash is likely to occur when the first I/O\n\
operation is done on the socket after it is imported into SSL.\n\
\n\
.. [1] See the \"SSL Version Range API\" section in the module\n\
       documentation for updated recomendations on protocol selection.\n\
");

static PyObject *
SSLSocket_set_ssl_option(SSLSocket *self, PyObject *args)
{
    int option;
    int value;

    TraceMethodEnter(self);

    /*
     * Note, although most of the options are booleans, at least one
     * isn't, SSL_REQUIRE_CERTIFICATE, so we can't use Python Booleans
     * and must use integers instead.
     */

    if (!PyArg_ParseTuple(args, "ii:set_ssl_option", &option, &value)) {
        return NULL;
    }

    if (SSL_OptionSet(self->pr_socket, option, value) != SECSuccess) {
        return set_nspr_error(NULL);
    }
    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_get_ssl_option_doc,
"get_ssl_option(value) -> value\n\
\n\
:Parameters:\n\
    value : integer\n\
        a constant value identifying which option to query\n\
\n\
Retrieves the value of a specified SSL option. Refer to the\n\
documentation for `SSLSocket.set_ssl_option()` for an explanation of the\n\
possible values.\n\
");

static PyObject *
SSLSocket_get_ssl_option(SSLSocket *self, PyObject *args)
{
    int option;
    int value;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:get_ssl_option", &option)) {
        return NULL;
    }

    if (SSL_OptionGet(self->pr_socket, option, &value) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return PyLong_FromLong(value);
}

PyDoc_STRVAR(SSLSocket_accept_doc,
"accept(timeout=PR_INTERVAL_NO_TIMEOUT) -> (Socket, NetworkAddress)\n\
\n\
:Parameters:\n\
    timeout : integer\n\
        optional timeout value expressed as a NSPR interval\n\
\n\
The socket is a rendezvous socket that has been bound to an address\n\
with Socket.bind() and is listening for connections after a call to\n\
Socket.listen(). Socket.accept() accepts the first connection from the\n\
queue of pending connections and creates a new socket for the newly\n\
accepted connection. The rendezvous socket can still be used to accept\n\
more connections.\n\
\n\
Socket.accept() blocks the calling thread until either a new\n\
connection is successfully accepted or an error occurs. If the timeout\n\
parameter is not PR_INTERVAL_NO_TIMEOUT and no pending connection can\n\
be accepted before the time limit, Socket.accept() raises a\n\
nss.error.NSPRError exception with the error code PR_IO_TIMEOUT_ERROR.\n\
\n\
Socket.accept() returns a tuple containing a new Socket object and\n\
Networkaddress object for the peer.\n\
");

static PyObject *
SSLSocket_accept(SSLSocket *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"timeout", NULL};
    unsigned int timeout = PR_INTERVAL_NO_TIMEOUT;
    PRNetAddr pr_netaddr;
    PyObject *py_ssl_socket = NULL;
    PyObject *py_netaddr = NULL;
    PRFileDesc *pr_socket = NULL;
    PyObject *return_value = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|I:accept", kwlist,
                                     &timeout))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    if ((pr_socket = PR_Accept(self->pr_socket, &pr_netaddr, timeout)) == NULL) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    if ((py_netaddr = NetworkAddress_new_from_PRNetAddr(&pr_netaddr)) == NULL) {
        goto error;
    }

    if ((py_ssl_socket = SSLSocket_new_from_PRFileDesc(pr_socket, self->family)) == NULL) {
        goto error;
    }

    if ((return_value = Py_BuildValue("NN", py_ssl_socket, py_netaddr)) == NULL) {
        goto error;
    }

    return return_value;

 error:
    Py_XDECREF(py_ssl_socket);
    Py_XDECREF(py_netaddr);
    return NULL;
}

static SECStatus
ssl_auth_certificate(void *arg, PRFileDesc *pr_socket, PRBool check_sig, PRBool is_server)
{
    PyGILState_STATE gstate;
    Py_ssize_t n_base_args = 3;
    SSLSocket *self = arg;
    PyObject *py_ssl_socket = NULL;
    PyObject *result = NULL;
    PyObject *args = NULL;
    PyObject *item;
    Py_ssize_t argc;
    int i, j;
    SECStatus sec_status = SECFailure;

    gstate = PyGILState_Ensure();

    argc = n_base_args;
    if (self->py_auth_certificate_callback_data)
        argc += PyTuple_Size(self->py_auth_certificate_callback_data);

    if ((args = PyTuple_New(argc)) == NULL) {
        PySys_WriteStderr("SSLSocket.auth_certificate_func: out of memory\n");
	goto exit;
    }

    if ((py_ssl_socket = SSLSocket_new_from_PRFileDesc(pr_socket, self->family)) == NULL) { /* FIXME: cached? what is family? */
        PySys_WriteStderr("SSLSocket.auth_certificate_func: cannot create socket object\n");
	goto exit;
    }

    PyTuple_SetItem(args, 0, py_ssl_socket);
    PyTuple_SetItem(args, 1, PyBool_FromLong(check_sig));
    PyTuple_SetItem(args, 2, PyBool_FromLong(is_server));

    for (i = n_base_args, j = 0; i < argc; i++, j++) {
        item = PyTuple_GetItem(self->py_auth_certificate_callback_data, j);
        Py_INCREF(item);
        PyTuple_SetItem(args, i, item);
    }

    if ((result = PyObject_CallObject(self->py_auth_certificate_callback, args)) == NULL) {
        PySys_WriteStderr("exception in SSLSocket.auth_certificate_func\n");
        PyErr_Print();  /* this also clears the error */
	goto exit;
    }

    sec_status = PyObject_IsTrue(result) ? SECSuccess : SECFailure;

 exit:
    Py_XDECREF(args);
    Py_XDECREF(result);

    PyGILState_Release(gstate);

    return sec_status;
}

PyDoc_STRVAR(SSLSocket_set_auth_certificate_callback_doc,
"set_auth_certificate_callback(callback, [user_data1, ...])\n\
\n\
:Parameters:\n\
    callback : function pointer\n\
        callback to invoke\n\
    user_dataN:\n\
        zero or more caller supplied parameters which will be passed to the callback\n\
\n\
The callback has the following signature::\n\
    \n\
    callback(socket, check_sig, is_server, [user_data1, ...]) -> bool\n\
\n\
socket\n\
    the SSLSocket object\n\
check_sig\n\
    boolean, True means signatures are to be checked and the\n\
    certificate chain is to be validated. False means they are not\n\
    to be checked. (The value is normally True.)\n\
is_server\n\
    boolean, True means the callback function should evaluate the\n\
    certificate as a server does, treating the remote end as a\n\
    client. False means the callback function should evaluate the\n\
    certificate as a client does, treating the remote end as a server.\n\
user_dataN\n\
     zero or more caller supplied optional parameters\n\
\n\
The callback function should return True if authentication is\n\
successful, False otherwise. If authentication is not successful the\n\
callback should indicate the reason for the failure (if possible) by\n\
calling nss.set_error() with the appropriate error code.\n\
\n\
The callback function obtains the certificate to be authenticated by\n\
calling ssl.get_peer_certificate(). If is_server is false, the\n\
callback should also check that the domain name in the remote server's\n\
certificate matches the desired domain name specified in a previous\n\
call to ssl.set_hostname(). To obtain that domain name, the callback calls\n\
ssl.get_hostname(). \n\
\n\
The callback may need to call one or more PK11 functions to obtain the\n\
services of a PKCS 11 module. Some of the PK11 functions require a\n\
PIN argument (see ssl.set_pkcs11_pin_arg() for details). To obtain the\n\
value that was set with ssl.set_pkcs11_pin_arg(), the callback calls\n\
ssl.get_pkcs11_pin_arg().\n\
\n\
If the callback returns False, the SSL connection is terminated\n\
immediately unless the application has supplied a bad-certificate\n\
callback function by having previously called\n\
ssl.set_bad_cert_callback(). A bad-certificate callback function gives\n\
the application the opportunity to choose to accept the certificate as\n\
authentic and authorized even though it failed the check performed by\n\
the certificate authentication callback function.\n\
\n\
Example::\n\
    \n\
    def auth_certificate_callback(sock, check_sig, is_server, certdb):\n\
        cert_is_valid = False\n\
\n\
        cert = sock.get_peer_certificate()\n\
        pin_args = sock.get_pkcs11_pin_arg()\n\
        if pin_args is None:\n\
            pin_args = ()\n\
\n\
        # Define how the cert is being used based upon the is_server flag.  This may\n\
        # seem backwards, but isn't. If we're a server we're trying to validate a\n\
        # client cert. If we're a client we're trying to validate a server cert.\n\
        if is_server:\n\
            intended_usage = nss.certificateUsageSSLClient\n\
        else:\n\
            intended_usage = nss.certificateUsageSSLServer\n\
\n\
        try:\n\
            # If the cert fails validation it will raise an exception, the errno attribute\n\
            # will be set to the error code matching the reason why the validation failed\n\
            # and the strerror attribute will contain a string describing the reason.\n\
            approved_usage = cert.verify_now(certdb, check_sig, intended_usage, *pin_args)\n\
        except Exception, e:\n\
            cert_is_valid = False\n\
            return cert_is_valid\n\
\n\
        # Is the intended usage a proper subset of the approved usage\n\
        if approved_usage & intended_usage:\n\
            cert_is_valid = True\n\
        else:\n\
            cert_is_valid = False\n\
\n\
        # If this is a server, we're finished\n\
        if is_server or not cert_is_valid:\n\
            return cert_is_valid\n\
\n\
        # Certificate is OK.  Since this is the client side of an SSL\n\
        # connection, we need to verify that the name field in the cert\n\
        # matches the desired hostname.  This is our defense against\n\
        # man-in-the-middle attacks.\n\
\n\
        hostname = sock.get_hostname()\n\
        try:\n\
            # If the cert fails validation it will raise an exception\n\
            cert_is_valid = cert.verify_hostname(hostname)\n\
        except Exception, e:\n\
            cert_is_valid = False\n\
            return cert_is_valid\n\
\n\
        return cert_is_valid\n\
\n\
");

static PyObject *
SSLSocket_set_auth_certificate_callback(SSLSocket *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *callback;
    PyObject *callback_args = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);

    if ((callback = PyTuple_GetItem(args, 0)) == NULL) {
        PyErr_SetString(PyExc_TypeError, "set_auth_certificate_callback: missing callback argument");
        return NULL;
    }

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }

    callback_args = PyTuple_GetSlice(args, n_base_args, argc);

    ASSIGN_REF(self->py_auth_certificate_callback, callback);
    ASSIGN_NEW_REF(self->py_auth_certificate_callback_data, callback_args);

    if (SSL_AuthCertificateHook(self->pr_socket, ssl_auth_certificate, self) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}


static SECStatus
get_client_auth_data(void *arg, PRFileDesc *fd, CERTDistNames *caNames, CERTCertificate **pRetCert, SECKEYPrivateKey **pRetKey)
{
    PyGILState_STATE gstate;
    Py_ssize_t n_base_args = 1;
    SSLSocket *self = arg;
    PyObject *return_args = NULL;
    PyObject *args = NULL;
    PyObject *item;
    Py_ssize_t argc, return_argc;
    int i, j;
    PyObject *py_cert_dist_names = NULL;
    PyObject *py_cert = NULL;
    PyObject *py_priv_key = NULL;

    gstate = PyGILState_Ensure();

    argc = n_base_args;
    if (self->py_client_auth_data_callback_data) {
        argc += PyTuple_Size(self->py_client_auth_data_callback_data);
    }

    if ((args = PyTuple_New(argc)) == NULL) {
        PySys_WriteStderr("SSLSocket.client_auth_data_callback: out of memory\n");
	goto fail;
    }

    if ((py_cert_dist_names = cert_distnames_new_from_CERTDistNames(caNames)) == NULL) {
        PySys_WriteStderr("SSLSocket.client_auth_data_callback: out of memory\n");
        goto fail;
    }

    PyTuple_SetItem(args, 0, (PyObject *)py_cert_dist_names);

    for (i = n_base_args, j = 0; i < argc; i++, j++) {
        item = PyTuple_GetItem(self->py_client_auth_data_callback_data, j);
        Py_INCREF(item);
        PyTuple_SetItem(args, i, item);
    }

    if ((return_args = PyObject_CallObject(self->py_client_auth_data_callback, args)) == NULL) {
        PySys_WriteStderr("exception in SSLSocket.client_auth_data_callback\n");
        PyErr_Print();
        goto fail;
    }

    if (PyBool_Check(return_args)) {
        if (return_args == Py_False) {
            goto fail;          // callback returned failure, boolean == false
        } else {
            goto bad_return;    // unexpected return value, boolean == true
        }
    }

    if (!PyTuple_Check(return_args)) {
        goto bad_return;        // unexpected return value, wasn't boolean or tuple
    }

    return_argc = PyTuple_Size(return_args);

    if (return_argc > 2) {
        goto bad_return;
    }

    py_cert = PyTuple_GetItem(return_args, 0);
    if (py_cert == Py_None) {
        goto fail;              // callback returned failure, tuple = (None ...)
    }

    if (!PyCertificate_Check(py_cert)) {
        PySys_WriteStderr("SSLSocket.client_auth_data_callback: 1st return value must be %s or None\n", CertificateType.tp_name);
        PyErr_Print();
        goto fail;
    }

    if (return_argc < 2) {
        PySys_WriteStderr("SSLSocket.client_auth_data_callback: expected 2nd return value\n");
        PyErr_Print();
        goto fail;
    }

    py_priv_key = PyTuple_GetItem(return_args, 1);
    if (py_priv_key == Py_None) {
        goto fail;              // callback returned failure, tuple = (cert, None ...)
    }

    if (!PyPrivateKey_Check(py_priv_key)) {
        PySys_WriteStderr("SSLSocket.client_auth_data_callback: 2nd return value must be %s or None\n", PrivateKeyType.tp_name);
        PyErr_Print();
        goto fail;
    }

    Py_DECREF(args);
    /*
     * NSS WART
     * There is no way to track the lifetime of the two returned objects.
     *
     * What should we do with the ref count for the certificate & private key?
     * we can't let them be destroyed while the NSS API is using them
     * but when will we get a chance after this callback returns to destroy them?
     *
     * Our bad solution is to bump the ref count and accept the memory leak :-(
     */
    Py_INCREF(py_cert);
    Py_INCREF(py_priv_key);
    Py_DECREF(return_args);

    *pRetCert = ((Certificate *)py_cert)->cert;
    *pRetKey = ((PrivateKey *)py_priv_key)->private_key;

    PyGILState_Release(gstate);

    return SECSuccess;

 bad_return:
    PySys_WriteStderr("SSLSocket.client_auth_data_callback: unexpected return value, must be False or the tuple (None) or the tuple (cert, priv_key)\n");
    PyErr_Print();

 fail:
    Py_XDECREF(args);
    Py_XDECREF(return_args);

    PyGILState_Release(gstate);

    return SECFailure;
}

PyDoc_STRVAR(SSLSocket_set_client_auth_data_callback_doc,
"set_client_auth_data_callback(callback, [user_data1, ...])\n\
\n\
:Parameters:\n\
    callback : function pointer\n\
        callback to invoke\n\
    user_dataN:\n\
        zero or more caller supplied parameters which will be passed to the callback\n\
\n\
The callback has the following signature::\n\
    \n\
    callback(ca_names, [user_data1, ...]) -> (Certificate, PrivateKey)\n\
\n\
ca_names\n\
    Sequence of CA distinguished names that the server accepts. Each\n\
    item in the sequence must be a SecItem object containing a\n\
    distinguished name.\n\
user_dataN\n\
    zero or more caller supplied optional parameters\n\
\n\
The callback returns Certificate and PrivateKey if successful,\n\
or None if the callback failed.\n\
\n\
Defines a callback function for SSL to use in a client application\n\
when a server asks for client authentication information. This\n\
callback function is required if your client application is going to\n\
support client authentication.\n\
\n\
The callback function set with `SSLSocket.set_client_auth_data_callback()`\n\
is used to get information from a client application when\n\
authentication is requested by the server. The callback function\n\
retrieves the client's private key and certificate. SSL provides an\n\
implementation of this callback function; see NSS_GetClientAuthData\n\
for details. Unlike SSL_AuthCertificate, NSS_GetClientAuthData is not\n\
a default callback function. You must set it explicitly with\n\
`SSLSocket.set_client_auth_data_callback()` if you want to use it.\n\
\n\
Example::\n\
    \n\
    def client_auth_data_callback(ca_names, chosen_nickname, password, certdb):\n\
        cert = None\n\
        if chosen_nickname:\n\
            try:\n\
                cert = nss.find_cert_from_nickname(chosen_nickname, password)\n\
                priv_key = nss.find_key_by_any_cert(cert, password)\n\
                return cert, priv_key\n\
            except NSPRError, e:\n\
                return False\n\
        else:\n\
            nicknames = nss.get_cert_nicknames(certdb, nss.SEC_CERT_NICKNAMES_USER)\n\
            for nickname in nicknames:\n\
                try:\n\
                    cert = nss.find_cert_from_nickname(nickname, password)\n\
                    if cert.check_valid_times():\n\
                        if cert.has_signer_in_ca_names(ca_names):\n\
                            priv_key = nss.find_key_by_any_cert(cert, password)\n\
                            return cert, priv_key\n\
                except NSPRError, e:\n\
                    pass\n\
            return False\n\
    \n\
    sock = ssl.SSLSocket(net_addr.family)\n\
    sock.set_client_auth_data_callback(client_auth_data_callback, nickname, password, nss.get_default_certdb())\n\
\n\
");

static PyObject *
SSLSocket_set_client_auth_data_callback(SSLSocket *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *callback;
    PyObject *callback_args = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);

    if ((callback = PyTuple_GetItem(args, 0)) == NULL) {
        PyErr_SetString(PyExc_TypeError, "set_client_auth_data_callback: missing callback argument");
        return NULL;
    }

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }

    callback_args = PyTuple_GetSlice(args, n_base_args, argc);

    ASSIGN_REF(self->py_client_auth_data_callback, callback);
    ASSIGN_NEW_REF(self->py_client_auth_data_callback_data, callback_args);

    if (SSL_GetClientAuthDataHook(self->pr_socket, get_client_auth_data, self) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

static void
ssl_handshake_callback(PRFileDesc *fd, void *arg)
{
    PyGILState_STATE gstate;
    Py_ssize_t n_base_args = 1;
    SSLSocket *py_sslsocket = arg;
    PyObject *result = NULL;
    PyObject *args = NULL;
    PyObject *item;
    Py_ssize_t argc;
    int i, j;

    gstate = PyGILState_Ensure();

    argc = n_base_args;
    if (py_sslsocket->py_handshake_callback_data)
        argc += PyTuple_Size(py_sslsocket->py_handshake_callback_data);

    if ((args = PyTuple_New(argc)) == NULL) {
        PySys_WriteStderr("SSLSocket.handshake_callback: out of memory\n");
	goto exit;
    }

    Py_INCREF(py_sslsocket);
    PyTuple_SetItem(args, 0, (PyObject *)py_sslsocket);

    for (i = n_base_args, j = 0; i < argc; i++, j++) {
        item = PyTuple_GetItem(py_sslsocket->py_handshake_callback_data, j);
        Py_INCREF(item);
        PyTuple_SetItem(args, i, item);
    }

    if ((result = PyObject_CallObject(py_sslsocket->py_handshake_callback, args)) == NULL) {
        PySys_WriteStderr("exception in SSLSocket.handshake_callback\n");
        PyErr_Print();  /* this also clears the error */
        Py_DECREF(args);
	goto exit;
    }

    Py_DECREF(args);
    Py_DECREF(result);

 exit:
    PyGILState_Release(gstate);
}

PyDoc_STRVAR(SSLSocket_set_handshake_callback_doc,
"set_handshake_callback(callback, [user_data1, ...])\n\
\n\
:Parameters:\n\
    callback : function pointer\n\
        callback to invoke\n\
    user_dataN:\n\
        zero or more caller supplied parameters which will be passed to the callback\n\
\n\
The callback has the following signature::\n\
    \n\
    callback(socket, [user_data1, ...])\n\
\n\
socket\n\
    the SSL socket the handshake has completed on\n\
user_dataN\n\
    zero or more caller supplied optional parameters\n\
\n\
Sets up a callback function used by SSL to inform either a client\n\
application or a server application when the handshake is completed.\n\
\n\
Example::\n\
    \n\
    def handshake_callback(sock):\n\
        print 'handshake complete, peer = %s' % (sock.get_peer_name())\n\
    \n\
    sock = ssl.SSLSocket(net_addr.family)\n\
    sock.set_handshake_callback(handshake_callback)\n\
\n\
");

static PyObject *
SSLSocket_set_handshake_callback(SSLSocket *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *callback;
    PyObject *callback_args = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);

    if ((callback = PyTuple_GetItem(args, 0)) == NULL) {
        PyErr_SetString(PyExc_TypeError, "set_handshake_callback: missing callback argument");
        return NULL;
    }

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }

    callback_args = PyTuple_GetSlice(args, n_base_args, argc);

    ASSIGN_REF(self->py_handshake_callback, callback);
    ASSIGN_NEW_REF(self->py_handshake_callback_data, callback_args);

    if (SSL_HandshakeCallback(self->pr_socket, ssl_handshake_callback, self) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}


PyDoc_STRVAR(SSLSocket_set_pkcs11_pin_arg_doc,
"set_pkcs11_pin_arg([user_dataN, ...])\n\
\n\
:Parameters:\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will be passed\n\
        to the pk11.password_callback()\n\
");

static PyObject *
SSLSocket_set_pkcs11_pin_arg(SSLSocket *self, PyObject *args)
{
    TraceMethodEnter(self);

    ASSIGN_REF(self->py_pk11_pin_args, args);

    if (SSL_SetPKCS11PinArg(self->pr_socket, args) != SECSuccess) {
        Py_CLEAR(self->py_pk11_pin_args);
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_get_pkcs11_pin_arg_doc,
"get_pkcs11_pin_arg()\n\
\n\
Returns a tuple of arguments or None if not previously set with\n\
`SSLSocket.set_pkcs11_pin_arg()`\n\
");

static PyObject *
SSLSocket_get_pkcs11_pin_arg(SSLSocket *self, PyObject *args)
{
    PyObject *pk11_pin_args = NULL;

    TraceMethodEnter(self);

    pk11_pin_args = SSL_RevealPinArg(self->pr_socket);

    assert(pk11_pin_args == self->py_pk11_pin_args);

    if (pk11_pin_args == NULL) {
        Py_RETURN_NONE;
    }

    Py_INCREF(pk11_pin_args);
    return pk11_pin_args;
}

PyDoc_STRVAR(SSLSocket_config_secure_server_doc,
"config_secure_server(cert, key, kea)\n\
\n\
:Parameters:\n\
    cert : Certificate object\n\
        Server's certificate as a Certificate object\n\
    key : PrivateKey object\n\
        Server's private key as a PrivateKey object\n\
    kea : integer\n\
        Key exchange type (e.g. ssl_kea_rsa, ssl_kea_dh, etc.)\n\
\n\
Configures a listen socket with the information needed to handshake as\n\
an SSL server. `SSLSocket.config_secure_server()` requires the\n\
certificate for the server and the server's private key.\n\
");

static PyObject *
SSLSocket_config_secure_server(SSLSocket *self, PyObject *args)
{
    Certificate *py_cert = NULL;
    PrivateKey *py_priv_key = NULL;
    int kea = 0;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O!O!i:config_secure_server",
                          &CertificateType, &py_cert,
                          &PrivateKeyType, &py_priv_key,
                          &kea))
        return NULL;

    if (SSL_ConfigSecureServer(self->pr_socket, py_cert->cert, py_priv_key->private_key, kea) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;

}

PyDoc_STRVAR(SSLSocket_get_peer_certificate_doc,
"get_peer_certificate() -> Certficate\n\
\n\
`SSLSocket.get_peer_certificate()` is used by certificate\n\
authentication and bad-certificate callback functions to obtain the\n\
certificate under scrutiny. If the client calls\n\
`SSLSocket.get_peer_certificate()`, it always returns the server's\n\
certificate. If the server calls `SSLSocket.get_peer_certificate()`, it\n\
may return None if client authentication is not enabled or if the\n\
client had no certificate when asked.\n\
");

static PyObject *
SSLSocket_get_peer_certificate(SSLSocket *self, PyObject *args)
{
    CERTCertificate *cert = NULL;
    PyObject *py_cert = NULL;

    TraceMethodEnter(self);

    cert = SSL_PeerCertificate(self->pr_socket);
    if (cert == NULL) {
        Py_RETURN_NONE;
    }

    if ((py_cert = Certificate_new_from_CERTCertificate(cert, false)) == NULL) {
        return NULL;
    }

    return py_cert;
}

PyDoc_STRVAR(SSLSocket_get_certificate_doc,
"get_certificate() -> Certficate\n\
\n\
Returns the certificate associated with the socket or\n\
None if not previously set.\n\
");

static PyObject *
SSLSocket_get_certificate(SSLSocket *self, PyObject *args)
{
    CERTCertificate *cert = NULL;
    PyObject *py_cert = NULL;

    TraceMethodEnter(self);

    cert = SSL_RevealCert(self->pr_socket);
    if (cert == NULL) {
        Py_RETURN_NONE;
    }

    if ((py_cert = Certificate_new_from_CERTCertificate(cert, false)) == NULL) {
        return NULL;
    }

    return py_cert;
}

PyDoc_STRVAR(SSLSocket_invalidate_session_doc,
"invalidate_session()\n\
\n\
After you call SSLSSocket.invalidate_session(), the existing\n\
connection using the session can continue, but no new connections can\n\
resume this SSL session.\n\
"
);

static PyObject *
SSLSocket_invalidate_session(SSLSocket *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (SSL_InvalidateSession(self->pr_socket) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_data_pending_doc,
"data_pending()\n\
\n\
Returns the number of bytes waiting in internal SSL buffers to be read\n\
by the local application from the SSL socket.\n\
\n\
If SSL_SECURITY has not been enabled with a call to\n\
`ssl.set_ssl_default_option()` or `SSLSocket.set_ssl_option()`, the\n\
function returns zero.\n\
"
);

static PyObject *
SSLSocket_data_pending(SSLSocket *self, PyObject *args)
{
    int data_pending = 0;

    TraceMethodEnter(self);

    data_pending = SSL_DataPending(self->pr_socket);
    return PyLong_FromLong(data_pending);
}

PyDoc_STRVAR(SSLSocket_get_security_status_doc,
"get_security_status() -> on, cipher, key_size, secret_key_size, issuer, subject\n\
\n\
Gets information about the security parameters of the current connection.\n\
Returns the tuple (on, cipher, key_size, secret_key_size, issuer, subject)\n\
\n\
The interpretation of each value is:\n\
    on\n\
        An integer, will be one of these values:\n\
            - SSL_SECURITY_STATUS_OFF\n\
            - SSL_SECURITY_STATUS_ON_HIGH\n\
            - SSL_SECURITY_STATUS_ON_LOW\n\
    cipher\n\
        A string specifying the name of the cipher.\n\
            - For SSL v2, the string is one of the following:\n\
                - RC4\n\
                - RC4-Export\n\
                - RC2-CBC\n\
                - RC2-CBC-Export\n\
                - DES-CBC,\n\
                - DES-EDE3-CBC\n\
            - For SSL v3, the string is one of the following:\n\
                - RC4\n\
                - RC4-40\n\
                - RC2-CBC\n\
                - RC2-CBC-40\n\
                - DES-CBC\n\
                - 3DES-EDE-CBC\n\
                - DES-CBC-40\n\
    keySize\n\
        An integer, the session key size used, in bits.\n\
    secret_key_size\n\
        An integer. indicates the size, in bits, of the secret portion of\n\
        the session key used (also known as the 'effective key size'). The\n\
        secret key size is never greater than the session key size.\n\
    issuer\n\
        A string specifying the DN of the issuer of the certificate at\n\
        the other end of the connection, in RFC1485 format. If no\n\
        certificate is supplied, the string is 'no certificate'\n\
    subject\n\
        A string specifying the distinguished name of the certificate at\n\
        the other end of the connection, in RFC1485 format. If no\n\
        certificate is supplied, the string is 'no certificate'\n\
\n\
");

static PyObject *
SSLSocket_get_security_status(SSLSocket *self, PyObject *args)
{
    int on;
    char *cipher = NULL;
    int key_size;
    int secret_key_size;
    char *issuer = NULL;
    char *subject = NULL;
    PyObject *return_value = NULL;

    TraceMethodEnter(self);

    if (SSL_SecurityStatus(self->pr_socket, &on, &cipher, &key_size,
                           &secret_key_size, &issuer, &subject) != SECSuccess) {
        set_nspr_error(NULL);
        goto exit;
    }

    return_value = Py_BuildValue("isiiss", on, cipher, key_size,
                                 secret_key_size, issuer, subject);

 exit:
    if (cipher)  PR_Free(cipher);
    if (issuer)  PR_Free(issuer);
    if (subject) PR_Free(subject);

    return return_value;
}

PyDoc_STRVAR(SSLSocket_get_session_id_doc,
"get_session_id() -> id\n\
\n\
Returns the SSL session ID as a SecItem.\n\
"
);

static PyObject *
SSLSocket_get_session_id(SSLSocket *self, PyObject *args)
{
    SECItem *sec_item = NULL;
    PyObject *return_value = NULL;

    TraceMethodEnter(self);

    if ((sec_item = SSL_GetSessionID(self->pr_socket)) == NULL) {
        return set_nspr_error(NULL);
    }

    return_value = SecItem_new_from_SECItem(sec_item, SECITEM_session_id);

    SECITEM_FreeItem(sec_item, PR_TRUE);

    return return_value;
}

PyDoc_STRVAR(SSLSocket_set_sock_peer_id_doc,
"set_sock_peer_id(id)\n\
\n\
:Parameters:\n\
    id : integer\n\
        An ID number assigned by the application to keep track of the SSL\n\
        session associated with the peer.\n\
\n\
Associates a peer ID with a socket to facilitate looking up the SSL\n\
session when it is tunneling through a proxy.\n\
\n\
SSL peers frequently reconnect after a relatively short time has\n\
passed. To avoid the overhead of repeating the full SSL handshake in\n\
situations like this, the SSL protocol supports the use of a session\n\
cache, which retains information about each connection for some\n\
predetermined length of time.\n\
\n\
For example, a client session cache includes the hostname and port\n\
number of each server the client connects with, plus additional\n\
information such as the master secret generated during the SSL\n\
handshake. For a direct connection with a server, the hostname and\n\
port number are sufficient for the client to identify the server as\n\
one for which it has an entry in its session cache. However, the\n\
situation is more complicated if the client is on an intranet and is\n\
connecting to a server on the Internet through a proxy. In this case,\n\
the client first connects to the proxy, and the client and proxy\n\
exchange messages specified by the proxy protocol that allow the\n\
proxy, in turn, to connect to the requested server on behalf of the\n\
client. This arrangement is known as SSL tunneling.\n\
\n\
Client session cache entries for SSL connections that tunnel through a\n\
particular proxy all have the same hostname and port number--that is,\n\
the hostname and port number of the proxy. To determine whether a\n\
particular server with which the client is attempting to connect has\n\
an entry in the session cache, the session cache needs some additional\n\
information that identifies that server. This additional identifying\n\
information is known as a peer ID. The peer ID is associated with a\n\
socket, and must be set before the SSL handshake occurs--that is,\n\
before the SSL handshake is initiated by a call to a function such as\n\
`SSLSocket.read()` or `SSLSocket.force_handshake()`. To set the peer ID,\n\
you use `SSLSocket.set_sock_peer_id()`.\n\
\n\
In summary, SSL uses three pieces of information to identify a\n\
server's entry in the client session cache: the hostname, port number,\n\
and peer ID. In the case of a client that is tunneling through a\n\
proxy, the hostname and port number identify the proxy, and the peer\n\
ID identifies the desired server. It is recommended that the client\n\
set the peer ID to a string that consists of the server's hostname and\n\
port number, like this:'www.hostname.com:387'. This convention\n\
guarantees that each server has a unique entry in the client session\n\
cache.\n\
");

static PyObject *
SSLSocket_set_sock_peer_id(SSLSocket *self, PyObject *args)
{
    char *id = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "s:set_sock_peer_id"))
        return NULL;

    if (SSL_SetSockPeerID(self->pr_socket, id) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_set_cipher_pref_doc,
"set_cipher_pref(cipher, enabled)\n\
\n\
:Parameters:\n\
    cipher : integer\n\
        The cipher suite enumeration (e.g. SSL_RSA_WITH_NULL_MD5, etc.)\n\
    enabled : bool or int\n\
        True enables, False disables\n\
\n\
Sets preference for the specified SSL2, SSL3, or TLS cipher on the\n\
socket. A cipher suite is used only if the policy allows it and the\n\
preference for it is set to True.\n\
\n\
This function must be called once for each cipher you want to enable\n\
or disable by default.\n\
\n\
Note, which cipher suites are permitted or disallowed are modified by\n\
previous calls to one or more of the SSL Export Policy Functions.\n\
");

static PyObject *
SSLSocket_set_cipher_pref(SSLSocket *self, PyObject *args)
{
    int cipher;
    int enabled;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "ii:set_cipher_pref", &cipher, &enabled))
        return NULL;

    if (SSL_CipherPrefSet(self->pr_socket, cipher, enabled) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_get_cipher_pref_doc,
"get_cipher_pref(cipher) -> enabled\n\
\n\
:Parameters:\n\
    cipher : integer\n\
        The cipher suite enumeration (e.g. SSL_RSA_WITH_NULL_MD5, etc.)\n\
\n\
Returns the preference for the specified SSL2, SSL3, or TLS cipher on\n\
the socket.\n\
");

static PyObject *
SSLSocket_get_cipher_pref(SSLSocket *self, PyObject *args)
{
    int cipher;
    int enabled;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:get_cipher_pref", &cipher))
        return NULL;

    if (SSL_CipherPrefGet(self->pr_socket, cipher, &enabled) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    if (enabled)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

PyDoc_STRVAR(SSLSocket_set_hostname_doc,
"set_hostname(url)\n\
\n\
:Parameters:\n\
    url : string\n\
        A string specifying the desired server's domain name.\n\
\n\
The client application's certificate authentication callback function\n\
needs to compare the domain name in the server's certificate against\n\
the domain name of the server the client was attempting to\n\
contact. This step is vital because it is the client's only protection\n\
against a man-in-the-middle attack. The client application uses\n\
`SSLSocket.set_hostname()` to set the domain name of the desired server\n\
before performing the first SSL handshake. The client application's\n\
certificate authentication callback function gets this string by\n\
calling `SSLSocket.get_hostname()`.\n\
");

static PyObject *
SSLSocket_set_hostname(SSLSocket *self, PyObject *args)
{
    char *url = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "et:set_hostname",
                          "idna", &url))
        return NULL;

    if (SSL_SetURL(self->pr_socket, url) != SECSuccess) {
        PyMem_Free(url);
        return set_nspr_error(NULL);
    }

    PyMem_Free(url);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_get_hostname_doc,
"get_hostname()\n\
\n\
`SSLSocket.get_hostname()` is used by certificate authentication callback\n\
function to obtain the domain name of the desired SSL server for the\n\
purpose of comparing it with the domain name in the certificate\n\
presented by the server actually contacted.\n\
");

static PyObject *
SSLSocket_get_hostname(SSLSocket *self, PyObject *args)
{
    char *url = NULL;
    PyObject *py_hostname = NULL;

    TraceMethodEnter(self);

    if ((url = SSL_RevealURL(self->pr_socket)) == NULL) {
        return set_nspr_error(NULL);
    }

    py_hostname = PyUnicode_Decode(url, strlen(url), "idna", NULL);
    PR_Free(url);
    return py_hostname;
}

PyDoc_STRVAR(SSLSocket_set_certificate_db_doc,
"set_certificate_db(certdb)\n\
\n\
:Parameters:\n\
    certdb : CertDB object\n\
        The certification database as a CertDB object\n\
\n\
Sets the Certificate Database on a specific SSLSocket.\n\
"
);

static PyObject *
SSLSocket_set_certificate_db(SSLSocket *self, PyObject *args)
{
    CertDB *py_certdb = NULL;

    if (!PyArg_ParseTuple(args, "O!:set_certificate_db", &CertDBType, &py_certdb))
        return NULL;

    if (SSL_CertDBHandleSet(self->pr_socket, py_certdb->handle) != SECSuccess) {
        return set_nspr_error(NULL);
    }


    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_reset_handshake_doc,
"reset_handshake(as_server)\n\
\n\
:Parameters:\n\
    as_server : bool\n\
        - True means the socket will attempt\n\
          to handshake as a server the next time it tries, and\n\
        - False means the socket will attempt to handshake as\n\
          a client the next time it tries.\n\
\n\
Calling `SSLSocket.reset_handshake()` causes the SSL handshake protocol\n\
to start from the beginning on the next I/O operation. That is, the\n\
handshake starts with no cipher suite already in use, just as it does\n\
on the first handshake on a new socket. When an application imports a\n\
socket into SSL after the TCP connection on that socket has already\n\
been established, it must call `SSLSocket.reset_handshake()` to\n\
determine whether SSL should behave like an SSL client or an SSL\n\
server. Note that this step would not be necessary if the socket\n\
weren't already connected. For an SSL socket that is configured before\n\
it is connected, SSL figures this out when the application calls\n\
`SSLSocket.connect()` or `SSLSocket.accept()`. If the socket is already\n\
connected before SSL gets involved, you must provide this extra hint.\n\
");

static PyObject *
SSLSocket_reset_handshake(SSLSocket *self, PyObject *args)
{
    int as_server = 0;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:reset_handshake", &as_server))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    if (SSL_ResetHandshake(self->pr_socket, as_server) != SECSuccess) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;

}

PyDoc_STRVAR(SSLSocket_force_handshake_doc,
"force_handshake()\n\
\n\
Drives a handshake for a specified SSLSocket to completion on a\n\
socket that has already been prepared to do a handshake or is in the\n\
middle of doing a handshake.\n\
\n\
When you are forcing the initial handshake on a blocking socket, this\n\
function returns when the handshake is complete. For subsequent\n\
handshakes, the function can return either because the handshake is\n\
complete, or because application data has been received on the\n\
connection that must be processed (that is, the application must read\n\
it) before the handshake can continue. You can use\n\
`SSLSocket.force_handshake()` when a handshake is desired but neither\n\
end has anything to say immediately. This occurs, for example, when an\n\
HTTPS server has received a request and determines that before it can\n\
answer the request, it needs to request an authentication certificate\n\
from the client. At the HTTP protocol level, nothing more is being\n\
said (that is, no HTTP request or response is being sent), so the\n\
server uses `SSLSocket.force_handshake()` to make the handshake\n\
occur. `SSLSocket.force_handshake()` does not prepare a socket to do a\n\
handshake by itself. The following functions prepare a socket to do a\n\
handshake:\n\
\n\
    * `SSLSocket.connect()`\n\
    * `SSLSocket.accept()`\n\
    * `SSLSocket.rehandshake()`\n\
      (after the first handshake is finished)\n\
    * SSLSocket.reset_handshake\n\
      (for sockets that were connected or accepted prior to being imported)\n\
\n\
A call to `SSLSocket.force_handshake()` will almost always be preceded\n\
by one of those functions. In versions prior to NSS 1.2, you cannot\n\
force a subsequent handshake. If you use this function after the\n\
initial handshake, it returns immediately without forcing a handshake.\n\
"
);

static PyObject *
SSLSocket_force_handshake(SSLSocket *self, PyObject *args)
{

    TraceMethodEnter(self);

    Py_BEGIN_ALLOW_THREADS
    if (SSL_ForceHandshake(self->pr_socket) != SECSuccess) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_force_handshake_timeout_doc,
"force_handshake_timeout(timeout)\n\
\n\
:Parameters:\n\
    timeout : integer\n\
        timeout value expressed as a NSPR interval\n\
\n\
See the documentation for `SSLSocket.force_handshake()`. This function\n\
adds a timeout interval.\n\
");

static PyObject *
SSLSocket_force_handshake_timeout(SSLSocket *self, PyObject *args)
{
    unsigned int timeout = PR_INTERVAL_NO_TIMEOUT;

    if (!PyArg_ParseTuple(args, "I:force_handshake_timeout", &timeout))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    if (SSL_ForceHandshakeWithTimeout(self->pr_socket, timeout) != SECSuccess) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_rehandshake_doc,
"rehandshake(flush_cache)\n\
\n\
:Parameters:\n\
    flush_cache : bool\n\
         - If flush_cache is True, the SSL3 cache entry will be flushed\n\
           first, ensuring that a full SSL handshake from scratch will\n\
           occur.\n\
         - If flush_cache is False, and an SSL connection is established, it\n\
           will do the much faster session restart handshake. This will\n\
           regenerate the symmetric session keys without doing another\n\
           private key operation.\n\
         \n\
\n\
Causes SSL to begin a new SSL 3.0 handshake on a connection that has\n\
already completed one handshake.\n\
\n\
If flush_cache is True, the `SSLSocket.rehandshake()` function\n\
invalidates the current SSL session associated with the specified\n\
SSLSocket from the session cache and starts another full SSL 3.0\n\
handshake. It is for use with SSL 3.0 only. You can call this function\n\
to redo the handshake if you have changed one of the socket's\n\
configuration parameters (for example, if you are going to request\n\
client authentication). Setting flush_cache to False can be useful,\n\
for example, if you are using export ciphers and want to keep changing\n\
the symmetric keys to foil potential\n\
attackers. `SSLSocket.rehandshake()` only initiates the new handshake by\n\
sending the first message of that handshake. To drive the new\n\
handshake to completion, you must either call\n\
`SSLSocket.force_handshake()` or do another I/O operation (read or\n\
write) on the socket. A call to `SSLSocket.rehandshake()` is typically\n\
followed by a call to `SSLSocket.force_handshake()`.\n\
");

static PyObject *
SSLSocket_rehandshake(SSLSocket *self, PyObject *args)
{
    int flush_cache;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:rehandshake", &flush_cache))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    if (SSL_ReHandshake(self->pr_socket, flush_cache) != SECSuccess) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_rehandshake_timeout_doc,
"rehandshake_timeout(flush_cache, timeout)\n\
\n\
:Parameters:\n\
    flush_cache : bool\n\
        cache flush flag\n\
    timeout : integer\n\
        timeout value expressed as a NSPR interval\n\
\n\
See the documentation for `SSLSocket.rehandshake()`. This function\n\
adds a timeout interval.\n\
");

static PyObject *
SSLSocket_rehandshake_timeout(SSLSocket *self, PyObject *args)
{
    int flush_cache;
    unsigned int timeout = PR_INTERVAL_NO_TIMEOUT;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "iI:rehandshake_timeout", &flush_cache, &timeout))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    if (SSL_ReHandshakeWithTimeout(self->pr_socket, flush_cache, timeout) != SECSuccess) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_import_tcp_socket_doc,
"import_tcp_socket(osfd) -> Socket\n\
:Parameters:\n\
    osfd : integer\n\
        file descriptor of the SOCK_STREAM socket to import\n\
\n\
Returns a Socket object that uses the specified socket file descriptor for\n\
communication.\n\
");

static PyObject *
SSLSocket_import_tcp_socket(Socket *self, PyObject *args)
{
    int osfd;
    PRFileDesc *sock0, *sock;
    PRNetAddr addr;
    PyObject *return_value = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:import_tcp_socket", &osfd))
	return NULL;

    sock0 = PR_ImportTCPSocket(osfd);
    if (sock0 == NULL) {
	return set_nspr_error(NULL);
    }
    sock = SSL_ImportFD(NULL, sock0);
    if (sock == NULL) {
	set_nspr_error(NULL);
	PR_Close(sock0);
	return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if (PR_GetSockName(sock, &addr) != PR_SUCCESS) {
        Py_BLOCK_THREADS
	set_nspr_error(NULL);
	goto error;
    }
    Py_END_ALLOW_THREADS

    if ((return_value = SSLSocket_new_from_PRFileDesc(sock,
						      PR_NetAddrFamily(&addr)))
	== NULL) {
	goto error;
    }

    return return_value;

 error:
    PR_Close(sock);
    return NULL;
}

PyDoc_STRVAR(SSLSocket_set_ssl_version_range_doc,
"set_ssl_version_range(min_version, max_version)\n\
\n\
:Parameters:\n\
    min_version : int or string\n\
        Either a SSL_LIBRARY_VERSION_* enumerated constant or it's\n\
        string equivalent, see `ssl_library_version_from_name()`\n\
    max_version : int or string\n\
        Either a SSL_LIBRARY_VERSION_* enumerated constant or it's\n\
        string equivalent, see `ssl_library_version_from_name()`\n\
\n\
Sets the range of enabled SSL3/TLS versions for this socket.\n\
");

static PyObject *
SSLSocket_set_ssl_version_range(SSLSocket *self, PyObject *args)
{
    PyObject *py_min = NULL;
    PyObject *py_max = NULL;
    unsigned long min_version;
    unsigned long max_version;
    SSLVersionRange range;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "OO:set_ssl_version_range",
                          &py_min, &py_max))
        return NULL;

    if (ssl_library_version_from_pyobject(py_min, "min", &min_version)
        != SECSuccess) {
        return NULL;
    }

    if (ssl_library_version_from_pyobject(py_max, "max", &max_version)
        != SECSuccess) {
        return NULL;
    }

    range.min = min_version;
    range.max = max_version;

    if (SSL_VersionRangeSet(self->pr_socket, &range) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSLSocket_get_ssl_version_range_doc,
"get_ssl_version_range(repr_kind=AsEnum) -> (min_version, max_version)\n\
:Parameters:\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what format the contents of the returned tuple will be in.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsString\n\
            A short friendly name for the enumerated constant.\n\
\n\
Returns the range of SSL3/TLS versions enabled for the socket.\n\
The result is a tuple whose contents are dictated by repr_kind.\n\
");

static PyObject *
SSLSocket_get_ssl_version_range(SSLSocket *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"repr_kind", NULL};
    RepresentationKind repr_kind = AsEnum;
    SSLVersionRange range;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:get_ssl_version_range", kwlist,
                                     &repr_kind))
        return NULL;


    if (SSL_VersionRangeGet(self->pr_socket, &range) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return SSLVersionRange_to_tuple(&range, repr_kind);
}

PyDoc_STRVAR(SSLSocket_get_ssl_channel_info_doc,
"get_ssl_channel_info() -> SSLChannelInfo\n\
Returns a `ssl.SSLChannelInfo` describing the parameters of the connection.\n\
");

static PyObject *
SSLSocket_get_ssl_channel_info(SSLSocket *self, PyObject *args)
{
    SSLChannelInfo info;

    TraceMethodEnter(self);

    if (SSL_GetChannelInfo(self->pr_socket, &info, sizeof(info)) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return SSLChannelInformation_new_from_SSLChannelInfo(&info);
}


PyDoc_STRVAR(SSLSocket_get_negotiated_host_doc,
"get_negotiated_host() -> string\n\
Returns SNI negotiated host name.\n\
");

static PyObject *
SSLSocket_get_negotiated_host(SSLSocket *self, PyObject *args)
{
    SECItem *host = NULL;
    Py_ssize_t size;
    PyObject *py_host = NULL;

    TraceMethodEnter(self);

    if ((host = SSL_GetNegotiatedHostInfo(self->pr_socket)) == NULL) {
        Py_RETURN_NONE;
    }

    size = host->len;

    if ((py_host = PyUnicode_Decode((const char *)host->data, size, "idna", NULL)) == NULL) {
        SECITEM_FreeItem(host, PR_TRUE);
        return NULL;
    }

    SECITEM_FreeItem(host, PR_TRUE);
    return py_host;
}


static PyObject *
SSLSocket_connection_info_format_lines(SSLSocket *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    SSLChannelInfo channel;
    SSLCipherSuiteInfo suite;
    unsigned int major, minor;
    PyObject *obj1 = NULL;
    PyObject *obj2 = NULL;
    PyObject *obj3 = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if (SSL_GetChannelInfo(self->pr_socket, &channel, sizeof(channel))
        != SECSuccess) {
        return set_nspr_error(NULL);
    }

    if (SSL_GetCipherSuiteInfo(channel.cipherSuite, &suite, sizeof(suite))
        != SECSuccess) {
        return set_nspr_error(NULL);
    }

    major = channel.protocolVersion >> 8;
    minor = channel.protocolVersion & 0xff;
    if ((obj2 = ssl_version_to_repr_kind(major, minor, AsString)) == NULL) {
        goto fail;
    }
    if ((obj3 = PyBaseString_UTF8(obj2, "ssl_version_to_repr_kind")) == NULL) {
        goto fail;
    }
    if ((obj1 = PyUnicode_FromFormat("%d.%d (%s)",
                                     channel.protocolVersion >> 8,
                                     channel.protocolVersion & 0xff,
                                     PyBytes_AsString(obj3))) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("SSL Protocol Version"), obj1, level, fail);
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);
    Py_CLEAR(obj3);

    if ((obj1 = PyUnicode_FromFormat("%d-bit %s",
                                     suite.effectiveKeyBits,
                                     suite.symCipherName)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Cipher"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyUnicode_FromFormat("%d-bit %s",
                                     suite.macBits,
                                     suite.macAlgorithmName)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("MAC"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyUnicode_FromFormat("%d-bit %s",
                                     channel.authKeyBits,
                                     suite.authAlgorithmName)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Auth"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyUnicode_FromFormat("%d-bit %s",
                                     channel.keaKeyBits,
                                     suite.keaTypeName)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Key Exchange"), obj1, level, fail);
    Py_CLEAR(obj1);

    obj1 = PyUnicode_FromString(channel.compressionMethodName);
    FMT_OBJ_AND_APPEND(lines, _("Compression"), obj1, level, fail);
    Py_CLEAR(obj1);

    return lines;

 fail:
    Py_XDECREF(obj1);
    Py_XDECREF(obj2);
    Py_XDECREF(obj3);
    Py_XDECREF(lines);
    return NULL;
}


static PyObject *
SSLSocket_connection_info_format(SSLSocket *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)SSLSocket_connection_info_format_lines, (PyObject *)self, args, kwds);
}

PyDoc_STRVAR(SSLSocket_connection_info_str_doc,
"connection_info_str() -> str\n\
Returns a string describing the properties of the SSL connection.\n\
");

static PyObject *
SSLSocket_connection_info_str(SSLSocket *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  SSLSocket_connection_info_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef SSLSocket_methods[] = {
    {"set_ssl_option",                (PyCFunction)SSLSocket_set_ssl_option,                METH_VARARGS,               SSLSocket_set_ssl_option_doc},
    {"get_ssl_option",                (PyCFunction)SSLSocket_get_ssl_option,                METH_VARARGS,               SSLSocket_get_ssl_option_doc},
    {"accept",                        (PyCFunction)SSLSocket_accept,                        METH_VARARGS|METH_KEYWORDS, SSLSocket_accept_doc},
    {"set_auth_certificate_callback", (PyCFunction)SSLSocket_set_auth_certificate_callback, METH_VARARGS,               SSLSocket_set_auth_certificate_callback_doc},
    {"set_client_auth_data_callback", (PyCFunction)SSLSocket_set_client_auth_data_callback, METH_VARARGS,               SSLSocket_set_client_auth_data_callback_doc},
    {"set_handshake_callback",        (PyCFunction)SSLSocket_set_handshake_callback,        METH_VARARGS,               SSLSocket_set_handshake_callback_doc},
    {"set_pkcs11_pin_arg",            (PyCFunction)SSLSocket_set_pkcs11_pin_arg,            METH_VARARGS,               SSLSocket_set_pkcs11_pin_arg_doc},
    {"get_pkcs11_pin_arg",            (PyCFunction)SSLSocket_get_pkcs11_pin_arg,            METH_NOARGS,                SSLSocket_get_pkcs11_pin_arg_doc},
    {"config_secure_server",          (PyCFunction)SSLSocket_config_secure_server,          METH_VARARGS,               SSLSocket_config_secure_server_doc},
    {"get_peer_certificate",          (PyCFunction)SSLSocket_get_peer_certificate,          METH_VARARGS,               SSLSocket_get_peer_certificate_doc},
    {"get_certificate",               (PyCFunction)SSLSocket_get_certificate,               METH_VARARGS,               SSLSocket_get_certificate_doc},
    {"invalidate_session",            (PyCFunction)SSLSocket_invalidate_session,            METH_NOARGS,                SSLSocket_invalidate_session_doc},
    {"data_pending",                  (PyCFunction)SSLSocket_data_pending,                  METH_NOARGS,                SSLSocket_data_pending_doc},
    {"get_security_status",           (PyCFunction)SSLSocket_get_security_status,           METH_NOARGS,                SSLSocket_get_security_status_doc},
    {"get_session_id",                (PyCFunction)SSLSocket_get_session_id,                METH_NOARGS,                SSLSocket_get_session_id_doc},
    {"set_sock_peer_id",              (PyCFunction)SSLSocket_set_sock_peer_id,              METH_VARARGS,               SSLSocket_set_sock_peer_id_doc},
    {"set_cipher_pref",               (PyCFunction)SSLSocket_set_cipher_pref,               METH_VARARGS,               SSLSocket_set_cipher_pref_doc},
    {"get_cipher_pref",               (PyCFunction)SSLSocket_get_cipher_pref,               METH_VARARGS,               SSLSocket_get_cipher_pref_doc},
    {"set_hostname",                  (PyCFunction)SSLSocket_set_hostname,                  METH_VARARGS,               SSLSocket_set_hostname_doc},
    {"get_hostname",                  (PyCFunction)SSLSocket_get_hostname,                  METH_NOARGS,                SSLSocket_get_hostname_doc},
    {"set_certificate_db",            (PyCFunction)SSLSocket_set_certificate_db,            METH_VARARGS,               SSLSocket_set_certificate_db_doc},
    {"reset_handshake",               (PyCFunction)SSLSocket_reset_handshake,               METH_VARARGS,               SSLSocket_reset_handshake_doc},
    {"force_handshake",               (PyCFunction)SSLSocket_force_handshake,               METH_NOARGS,                SSLSocket_force_handshake_doc},
    {"force_handshake_timeout",       (PyCFunction)SSLSocket_force_handshake_timeout,       METH_VARARGS,               SSLSocket_force_handshake_timeout_doc},
    {"rehandshake",                   (PyCFunction)SSLSocket_rehandshake,                   METH_VARARGS,               SSLSocket_rehandshake_doc},
    {"rehandshake_timeout",           (PyCFunction)SSLSocket_rehandshake_timeout,           METH_VARARGS,               SSLSocket_rehandshake_timeout_doc},
    {"import_tcp_socket",             (PyCFunction)SSLSocket_import_tcp_socket,             METH_VARARGS|METH_STATIC,   SSLSocket_import_tcp_socket_doc},
    {"set_ssl_version_range",         (PyCFunction)SSLSocket_set_ssl_version_range,         METH_VARARGS,               SSLSocket_set_ssl_version_range_doc},
    {"get_ssl_version_range",         (PyCFunction)SSLSocket_get_ssl_version_range,         METH_VARARGS|METH_KEYWORDS, SSLSocket_get_ssl_version_range_doc},
    {"get_ssl_channel_info",          (PyCFunction)SSLSocket_get_ssl_channel_info,          METH_NOARGS,                SSLSocket_get_ssl_channel_info_doc},
    {"get_negotiated_host",           (PyCFunction)SSLSocket_get_negotiated_host,           METH_NOARGS,                SSLSocket_get_negotiated_host_doc},

    {"connection_info_format_lines",  (PyCFunction)SSLSocket_connection_info_format_lines,  METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"connection_info_format",        (PyCFunction)SSLSocket_connection_info_format,        METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {"connection_info_str",           (PyCFunction)SSLSocket_connection_info_str,           METH_NOARGS,                SSLSocket_connection_info_str_doc},
    {NULL, NULL}  /* Sentinel */
};


/* =========================== Class Construction =========================== */

static PyObject *
SSLSocket_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    SSLSocket *self;

    TraceObjNewEnter(type);

    if ((self = (SSLSocket *)SocketType.tp_new(type, args, kwds)) == NULL) {
        return NULL;
    }

    self->py_auth_certificate_callback = NULL;
    self->py_auth_certificate_callback_data = NULL;
    self->py_pk11_pin_args = NULL;
    self->py_handshake_callback = NULL;
    self->py_handshake_callback_data = NULL;
    self->py_client_auth_data_callback = NULL;
    self->py_client_auth_data_callback_data = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
SSLSocket_traverse(SSLSocket *self, visitproc visit, void *arg)
{
    TraceMethodEnter(self);

    Py_VISIT(self->py_auth_certificate_callback);
    Py_VISIT(self->py_auth_certificate_callback_data);
    Py_VISIT(self->py_pk11_pin_args);
    Py_VISIT(self->py_handshake_callback);
    Py_VISIT(self->py_handshake_callback_data);
    Py_VISIT(self->py_client_auth_data_callback);
    Py_VISIT(self->py_client_auth_data_callback_data);

    return Py_TYPE(self)->tp_base->tp_traverse((PyObject *)self, visit, arg);
}

static int
SSLSocket_clear(SSLSocket* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_auth_certificate_callback);
    Py_CLEAR(self->py_auth_certificate_callback_data);
    Py_CLEAR(self->py_pk11_pin_args);
    Py_CLEAR(self->py_handshake_callback);
    Py_CLEAR(self->py_handshake_callback_data);
    Py_CLEAR(self->py_client_auth_data_callback);
    Py_CLEAR(self->py_client_auth_data_callback_data);

    return Py_TYPE(self)->tp_base->tp_clear((PyObject *)self);

}

static void
SSLSocket_dealloc(SSLSocket* self)
{

    TraceMethodEnter(self);

    SSLSocket_clear(self);
    return Py_TYPE(self)->tp_base->tp_dealloc((PyObject *)self);
}

PyDoc_STRVAR(SSLSocket_doc,
"SSLSocket(family=PR_AF_INET, type=PR_DESC_SOCKET_TCP)\n\
\n\
\n\
:Parameters:\n\
    family : integer\n\
        one of:\n\
            - PR_AF_INET\n\
            - PR_AF_INET6\n\
            - PR_AF_LOCAL\n\
    type : integer\n\
        one of:\n\
            - PR_DESC_SOCKET_TCP\n\
            - PR_DESC_SOCKET_UDP\n\
\n\
Create a new NSPR SSL socket:\n\
\n\
");

static int
SSLSocket_init(SSLSocket *self, PyObject *args, PyObject *kwds)
{
    PRFileDesc *ssl_socket = NULL;

    TraceMethodEnter(self);

    if (SocketType.tp_init((PyObject *)self, args, kwds) < 0)
        return -1;

    if ((ssl_socket = SSL_ImportFD(NULL, self->pr_socket)) == NULL) {
        set_nspr_error(NULL);
        return -1;
    }

    assert(self->pr_socket == ssl_socket);
    TraceMethodLeave(self);
    return 0;
}

static PyTypeObject SSLSocketType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "nss.ssl.SSLSocket",			/* tp_name */
    sizeof(SSLSocket),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)SSLSocket_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    0,						/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    SSLSocket_doc,				/* tp_doc */
    (traverseproc)SSLSocket_traverse,		/* tp_traverse */
    (inquiry)SSLSocket_clear,			/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    SSLSocket_methods,				/* tp_methods */
    SSLSocket_members,				/* tp_members */
    SSLSocket_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)SSLSocket_init,			/* tp_init */
    0,						/* tp_alloc */
    SSLSocket_new,				/* tp_new */
};

/* ========================================================================== */
/* ==================== SSLCipherSuiteInformation Class ===================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
SSLCipherSuiteInformation_get_cipher_suite(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.cipherSuite);
}

static PyObject *
SSLCipherSuiteInformation_get_cipher_suite_name(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyUnicode_FromString(self->info.cipherSuiteName);
}

static PyObject *
SSLCipherSuiteInformation_get_auth_algorithm(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.authAlgorithm);
}

static PyObject *
SSLCipherSuiteInformation_get_auth_algorithm_name(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyUnicode_FromString(self->info.authAlgorithmName);
}

static PyObject *
SSLCipherSuiteInformation_get_kea_type(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.keaType);
}

static PyObject *
SSLCipherSuiteInformation_get_kea_type_name(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyUnicode_FromString(self->info.keaTypeName);
}

static PyObject *
SSLCipherSuiteInformation_get_symmetric_cipher(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.symCipher);
}

static PyObject *
SSLCipherSuiteInformation_get_symmetric_cipher_name(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyUnicode_FromString(self->info.symCipherName);
}

static PyObject *
SSLCipherSuiteInformation_get_symmetric_key_bits(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.symKeyBits);
}

static PyObject *
SSLCipherSuiteInformation_get_symmetric_key_space(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.symKeySpace);
}

static PyObject *
SSLCipherSuiteInformation_get_effective_key_bits(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.effectiveKeyBits);
}

static PyObject *
SSLCipherSuiteInformation_get_mac_algorithm(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.macAlgorithm);
}

static PyObject *
SSLCipherSuiteInformation_get_mac_algorithm_name(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyUnicode_FromString(self->info.macAlgorithmName);
}

static PyObject *
SSLCipherSuiteInformation_get_mac_bits(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.macBits);
}

static PyObject *
SSLCipherSuiteInformation_get_is_fips(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->info.isFIPS) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *
SSLCipherSuiteInformation_get_is_exportable(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->info.isExportable) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *
SSLCipherSuiteInformation_get_is_nonstandard(SSLCipherSuiteInformation *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->info.nonStandard) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static
PyGetSetDef SSLCipherSuiteInformation_getseters[] = {
    {"cipher_suite",          (getter)SSLCipherSuiteInformation_get_cipher_suite,           NULL, "Returns the cipher suite enum", NULL},
    {"cipher_suite_name",     (getter)SSLCipherSuiteInformation_get_cipher_suite_name,      NULL, "Returns the cipher suite name", NULL},
    {"auth_algorithm",        (getter)SSLCipherSuiteInformation_get_auth_algorithm,         NULL, "Returns the auth algorithm enum", NULL},
    {"auth_algorithm_name",   (getter)SSLCipherSuiteInformation_get_auth_algorithm_name,    NULL, "Returns the auth algorithm name", NULL},
    {"kea_type",              (getter)SSLCipherSuiteInformation_get_kea_type,               NULL, "Returns the kea type enum", NULL},
    {"kea_type_name",         (getter)SSLCipherSuiteInformation_get_kea_type_name,          NULL, "Returns the kea type name", NULL},
    {"symmetric_cipher",      (getter)SSLCipherSuiteInformation_get_symmetric_cipher,       NULL, "Returns the symmetric cipher enum", NULL},
    {"symmetric_cipher_name", (getter)SSLCipherSuiteInformation_get_symmetric_cipher_name,  NULL, "Returns the symmetric cipher name", NULL},
    {"symmetric_key_bits",    (getter)SSLCipherSuiteInformation_get_symmetric_key_bits,     NULL, "Returns the symmetric key bits", NULL},
    {"symmetric_key_space",   (getter)SSLCipherSuiteInformation_get_symmetric_key_space,    NULL, "Returns the symmetric key space", NULL},
    {"effective_key_bits",    (getter)SSLCipherSuiteInformation_get_effective_key_bits,     NULL, "Returns the effective key bits", NULL},
    {"mac_algorithm",         (getter)SSLCipherSuiteInformation_get_mac_algorithm,          NULL, "Returns the mac algorithm enum", NULL},
    {"mac_algorithm_name",    (getter)SSLCipherSuiteInformation_get_mac_algorithm_name,     NULL, "Returns the mac algorithm name", NULL},
    {"mac_bits",              (getter)SSLCipherSuiteInformation_get_mac_bits,               NULL, "Returns the mac bits", NULL},
    {"is_fips",               (getter)SSLCipherSuiteInformation_get_is_fips,                NULL, "Returns True if FIPS, False otherwise", NULL},
    {"is_exportable",         (getter)SSLCipherSuiteInformation_get_is_exportable,          NULL, "Returns True if exportable, False otherwise", NULL},
    {"is_nonstandard",        (getter)SSLCipherSuiteInformation_get_is_nonstandard,         NULL, "Returns True if nonstandard, False otherwise", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef SSLCipherSuiteInformation_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
SSLCipherSuiteInformation_format_lines(SSLCipherSuiteInformation *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj1 = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }


    if ((obj1 = PyUnicode_FromFormat("%s (0x%x)",
                                     self->info.cipherSuiteName,
                                     self->info.cipherSuite)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Cipher Suite"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyUnicode_FromFormat("%s (0x%x)",
                                     self->info.authAlgorithmName,
                                     self->info.authAlgorithm)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Auth Algorithm"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyUnicode_FromFormat("%s (0x%x)",
                                     self->info.keaTypeName,
                                     self->info.keaType)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Key Exchange Type"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyUnicode_FromFormat("%s (0x%x)",
                                     self->info.symCipherName,
                                     self->info.symCipher)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Symmetric Cipher"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    obj1 = PyLong_FromLong(self->info.symKeyBits);
    FMT_OBJ_AND_APPEND(lines, _("Symmetric Key Bits"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    obj1 = PyLong_FromLong(self->info.effectiveKeyBits);
    FMT_OBJ_AND_APPEND(lines, _("Effective Symmetric Key Bits"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    obj1 = PyLong_FromLong(self->info.symKeySpace);
    FMT_OBJ_AND_APPEND(lines, _("Symmetric Key Space"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyUnicode_FromFormat("%s (0x%x)",
                                     self->info.macAlgorithmName,
                                     self->info.macAlgorithm)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("MAC Algorithm"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    obj1 = PyLong_FromLong(self->info.macBits);
    FMT_OBJ_AND_APPEND(lines, _("MAC Bits"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    obj1 = PyUnicode_FromString(self->info.isFIPS ? "True" : "False");
    FMT_OBJ_AND_APPEND(lines, _("FIPS"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    obj1 = PyUnicode_FromString(self->info.isExportable ? "True" : "False");
    FMT_OBJ_AND_APPEND(lines, _("Exportable"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    obj1 = PyUnicode_FromString(self->info.nonStandard ? "True" : "False");
    FMT_OBJ_AND_APPEND(lines, _("Nonstandard"), obj1, level+1, fail);
    Py_CLEAR(obj1);

    return lines;
 fail:
    Py_XDECREF(obj1);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
SSLCipherSuiteInformation_format(SSLCipherSuiteInformation *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)SSLCipherSuiteInformation_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
SSLCipherSuiteInformation_str(SSLCipherSuiteInformation *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  SSLCipherSuiteInformation_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef SSLCipherSuiteInformation_methods[] = {
    {"format_lines", (PyCFunction)SSLCipherSuiteInformation_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)SSLCipherSuiteInformation_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};



/* =========================== Class Construction =========================== */

static PyObject *
SSLCipherSuiteInformation_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    SSLCipherSuiteInformation *self;

    TraceObjNewEnter(type);

    if ((self = (SSLCipherSuiteInformation *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
SSLCipherSuiteInformation_dealloc(SSLCipherSuiteInformation* self)
{
    TraceMethodEnter(self);

    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(SSLCipherSuiteInformation_doc,
"SSLCipherSuiteInformation(obj)\n\
\n\
An object representing SSLCipherSuiteInformation.\n\
");

static int
SSLCipherSuiteInformation_init(SSLCipherSuiteInformation *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"arg", NULL};
    PyObject *arg;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:SSLCipherSuiteInformation", kwlist,
                                     &arg))
        return -1;

    return 0;
}

static PyTypeObject SSLCipherSuiteInformationType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "nss.ssl.SSLCipherSuiteInfo",		/* tp_name */
    sizeof(SSLCipherSuiteInformation),		/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)SSLCipherSuiteInformation_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)SSLCipherSuiteInformation_str,	/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    SSLCipherSuiteInformation_doc,		/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    SSLCipherSuiteInformation_methods,		/* tp_methods */
    SSLCipherSuiteInformation_members,		/* tp_members */
    SSLCipherSuiteInformation_getseters,	/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)SSLCipherSuiteInformation_init,	/* tp_init */
    0,						/* tp_alloc */
    SSLCipherSuiteInformation_new,		/* tp_new */
};

static PyObject *
SSLCipherSuiteInformation_new_from_SSLCipherSuiteInfo(SSLCipherSuiteInfo *info)
{
    SSLCipherSuiteInformation *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (SSLCipherSuiteInformation *) SSLCipherSuiteInformationType.tp_new(&SSLCipherSuiteInformationType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->info = *info;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ==================== SSLChannelInformation Class ===================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
SSLChannelInformation_get_protocol_version(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.protocolVersion);
}

static PyObject *
SSLChannelInformation_get_protocol_version_str(SSLChannelInformation *self, void *closure)
{
    unsigned int major, minor;

    TraceMethodEnter(self);

    major = self->info.protocolVersion >> 8;
    minor = self->info.protocolVersion & 0xff;
    return ssl_version_to_repr_kind(major, minor, AsString);
}

static PyObject *
SSLChannelInformation_get_protocol_version_enum(SSLChannelInformation *self, void *closure)
{
    unsigned int major, minor;

    TraceMethodEnter(self);

    major = self->info.protocolVersion >> 8;
    minor = self->info.protocolVersion & 0xff;
    return ssl_version_to_repr_kind(major, minor, AsEnum);
}

static PyObject *
SSLChannelInformation_get_major_protocol_version(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.protocolVersion >> 8);
}

static PyObject *
SSLChannelInformation_get_minor_protocol_version(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.protocolVersion & 0xff);
}

static PyObject *
SSLChannelInformation_get_cipher_suite(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.cipherSuite);
}

static PyObject *
SSLChannelInformation_get_auth_key_bits(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.authKeyBits);
}

static PyObject *
SSLChannelInformation_get_kea_key_bits(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.keaKeyBits);
}

static PyObject *
SSLChannelInformation_get_creation_time(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return timestamp_to_DateTime(self->info.creationTime, false);
}

static PyObject *
SSLChannelInformation_get_creation_time_utc(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return timestamp_to_DateTime(self->info.creationTime, true);
}

static PyObject *
SSLChannelInformation_get_last_access_time(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return timestamp_to_DateTime(self->info.lastAccessTime, false);
}

static PyObject *
SSLChannelInformation_get_last_access_time_utc(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return timestamp_to_DateTime(self->info.lastAccessTime, true);
}

static PyObject *
SSLChannelInformation_get_expiration_time(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return timestamp_to_DateTime(self->info.creationTime, false);
}

static PyObject *
SSLChannelInformation_get_expiration_time_utc(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return timestamp_to_DateTime(self->info.creationTime, true);
}

static PyObject *
SSLChannelInformation_get_compression_method(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(self->info.compressionMethod);
}

static PyObject *
SSLChannelInformation_get_compression_method_name(SSLChannelInformation *self, void *closure)
{
    TraceMethodEnter(self);

    return PyUnicode_FromString(self->info.compressionMethodName);
}

static PyObject *
SSLChannelInformation_get_session_id(SSLChannelInformation *self, void *closure)
{
    SECItem item;
    TraceMethodEnter(self);

    item.data = self->info.sessionID;
    item.len = self->info.sessionIDLength;
    return SecItem_new_from_SECItem(&item, SECITEM_buffer);
}

static
PyGetSetDef SSLChannelInformation_getseters[] = {
    {"protocol_version",        (getter)SSLChannelInformation_get_protocol_version,        NULL, "Returns the protocol version, major in octet[1], minor in octet[0] ", NULL},
    {"protocol_version_str",    (getter)SSLChannelInformation_get_protocol_version_str,    NULL, "Returns the protocol version as a descriptive string", NULL},
    {"protocol_version_enum",   (getter)SSLChannelInformation_get_protocol_version_enum,   NULL, "Returns the protocol version as an enumerated constant", NULL},
    {"major_protocol_version",  (getter)SSLChannelInformation_get_major_protocol_version,  NULL, "Returns the major protocol version", NULL},
    {"minor_protocol_version",  (getter)SSLChannelInformation_get_minor_protocol_version,  NULL, "Returns the minor protocol version", NULL},
    {"cipher_suite",            (getter)SSLChannelInformation_get_cipher_suite,            NULL, "Returns the cipher suite enum", NULL},
    {"auth_key_bits",           (getter)SSLChannelInformation_get_auth_key_bits,           NULL, "Returns the auth key bits", NULL},
    {"kea_key_bits",            (getter)SSLChannelInformation_get_kea_key_bits,            NULL, "Returns the kea key bits", NULL},
    {"creation_time",           (getter)SSLChannelInformation_get_creation_time,           NULL, "Returns creation time as a DateTime object in local time zone", NULL},
    {"creation_time_utc",       (getter)SSLChannelInformation_get_creation_time_utc,       NULL, "Returns creation time as a DateTime object in UTC time zone", NULL},
    {"last_access_time",        (getter)SSLChannelInformation_get_last_access_time,        NULL, "Returns last access time as a DateTime object in local time zone", NULL},
    {"last_access_time_utc",    (getter)SSLChannelInformation_get_last_access_time_utc,    NULL, "Returns last access time as a DateTime object in UTC time zone", NULL},
    {"expiration_time",         (getter)SSLChannelInformation_get_expiration_time,         NULL, "Returns expiration time as a DateTime object in local time zone", NULL},
    {"expiration_time_utc",     (getter)SSLChannelInformation_get_expiration_time_utc,     NULL, "Returns expiration time as a DateTime object in UTC time zone", NULL},
    {"compression_method",      (getter)SSLChannelInformation_get_compression_method,      NULL, "Returns the compression method enum", NULL},
    {"compression_method_name", (getter)SSLChannelInformation_get_compression_method_name, NULL, "Returns the compression method name", NULL},
    {"session_id",              (getter)SSLChannelInformation_get_session_id,              NULL, "Returns the session ID as a SecItem object", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef SSLChannelInformation_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
SSLChannelInformation_format_lines(SSLChannelInformation *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj1 = NULL;
    PyObject *obj2 = NULL;
    PyObject *obj3 = NULL;
    unsigned int major, minor;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist,
                                     &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }


    major = self->info.protocolVersion >> 8;
    minor = self->info.protocolVersion & 0xff;
    if ((obj2 = ssl_version_to_repr_kind(major, minor, AsString)) == NULL) {
        goto fail;
    }
    if ((obj3 = PyBaseString_UTF8(obj2, "ssl_version_to_repr_kind")) == NULL) {
        goto fail;
    }
    if ((obj1 = PyUnicode_FromFormat("%d.%d (%s)",
                                     self->info.protocolVersion >> 8,
                                     self->info.protocolVersion & 0xff,
                                     PyBytes_AsString(obj3))) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Protocol Version"), obj1, level, fail);
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);
    Py_CLEAR(obj3);

    if ((obj2 = cipher_suite_to_name(self->info.cipherSuite)) == NULL) {
        goto fail;
    }
    if ((obj3 = PyBaseString_UTF8(obj2, "cipher_suite_to_name")) == NULL) {
        goto fail;
    }
    if ((obj1 = PyUnicode_FromFormat("%s (0x%x)",
                                     PyBytes_AsString(obj3),
                                     self->info.cipherSuite)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Cipher Suite"), obj1, level, fail);
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);
    Py_CLEAR(obj3);

    obj1 = PyLong_FromLong(self->info.authKeyBits);
    FMT_OBJ_AND_APPEND(lines, _("Auth Key Bits"), obj1, level, fail);
    Py_CLEAR(obj1);

    obj1 = PyLong_FromLong(self->info.keaKeyBits);
    FMT_OBJ_AND_APPEND(lines, _("Key Exchange Key Bits"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = timestamp_to_DateTime(self->info.creationTime, false)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Creation Time"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = timestamp_to_DateTime(self->info.lastAccessTime, false)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Last Access Time"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = timestamp_to_DateTime(self->info.expirationTime, false)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Expiration Time"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyUnicode_FromFormat("%s (0x%x)",
                                     self->info.compressionMethodName,
                                     self->info.compressionMethod)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Compression Method"), obj1, level, fail);
    Py_CLEAR(obj1);


    if ((obj1 = raw_data_to_hex(self->info.sessionID,
                                self->info.sessionIDLength,
                                OCTETS_PER_LINE_DEFAULT,
                                HEX_SEPARATOR_DEFAULT)) == NULL) {
        goto fail;
    }
    FMT_LABEL_AND_APPEND(lines, _("Session ID"), level, fail);
    APPEND_LINES_AND_CLEAR(lines, obj1, level+1, fail);


    return lines;
 fail:
    Py_XDECREF(obj1);
    Py_XDECREF(obj2);
    Py_XDECREF(obj3);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
SSLChannelInformation_format(SSLChannelInformation *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)SSLChannelInformation_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
SSLChannelInformation_str(SSLChannelInformation *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  SSLChannelInformation_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef SSLChannelInformation_methods[] = {
    {"format_lines", (PyCFunction)SSLChannelInformation_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)SSLChannelInformation_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};



/* =========================== Class Construction =========================== */

static PyObject *
SSLChannelInformation_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    SSLChannelInformation *self;

    TraceObjNewEnter(type);

    if ((self = (SSLChannelInformation *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
SSLChannelInformation_dealloc(SSLChannelInformation* self)
{
    TraceMethodEnter(self);

    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(SSLChannelInformation_doc,
"SSLChannelInformation(obj)\n\
\n\
An object representing SSLChannelInformation.\n\
");

static int
SSLChannelInformation_init(SSLChannelInformation *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"arg", NULL};
    PyObject *arg;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:SSLChannelInformation", kwlist,
                                     &arg))
        return -1;

    return 0;
}

static PyTypeObject SSLChannelInformationType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "nss.ssl.SSLChannelInfo",			/* tp_name */
    sizeof(SSLChannelInformation),		/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)SSLChannelInformation_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)SSLChannelInformation_str,	/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    SSLChannelInformation_doc,			/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    SSLChannelInformation_methods,		/* tp_methods */
    SSLChannelInformation_members,		/* tp_members */
    SSLChannelInformation_getseters,		/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)SSLChannelInformation_init,	/* tp_init */
    0,						/* tp_alloc */
    SSLChannelInformation_new,			/* tp_new */
};

static PyObject *
SSLChannelInformation_new_from_SSLChannelInfo(SSLChannelInfo *info)
{
    SSLChannelInformation *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (SSLChannelInformation *) SSLChannelInformationType.tp_new(&SSLChannelInformationType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->info = *info;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ================================= Module ================================= */
/* ========================================================================== */

/* ============================== Module Methods ============================= */


PyDoc_STRVAR(SSL_set_ssl_default_option_doc,
"set_ssl_default_option(option, value)\n\
\n\
Changes the default value of a specified SSL option for all\n\
subsequently opened sockets as long as the current application program\n\
is running. Refer to the documentation for `SSLSocket.set_ssl_option()`\n\
for an explanation of the possible values.\n\
");

static PyObject *
SSL_set_ssl_default_option(PyObject *self, PyObject *args)
{
    int option;
    int value;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "ii:set_ssl_default_option", &option, &value)) {
        return NULL;
    }

    if (SSL_OptionSetDefault(option, value) != SECSuccess) {
        return set_nspr_error(NULL);
    }
    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSL_get_ssl_default_option_doc,
"get_ssl_default_option(value)\n\
\n\
Gets the default value of a specified SSL option for all\n\
subsequently opened sockets as long as the current application program\n\
is running. Refer to the documentation for `SSLSocket.set_ssl_option()`\n\
for an explanation of the possible values.\n\
");

static PyObject *
SSL_get_ssl_default_option(PyObject *self, PyObject *args)
{
    int option;
    int value;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:get_ssl_default_option", &option)) {
        return NULL;
    }

    if (SSL_OptionGetDefault(option, &value) != SECSuccess) {
        return set_nspr_error(NULL);
    }
    return PyLong_FromLong(value);
}

PyDoc_STRVAR(SSL_set_default_cipher_pref_doc,
"set_cipher_pref(cipher, enabled)\n\
\n\
:Parameters:\n\
    cipher : integer\n\
        The cipher suite enumeration (e.g. SSL_RSA_WITH_NULL_MD5, etc.)\n\
    enabled : bool\n\
        Boolean value\n\
\n\
Sets the application default preference for the specified SSL2, SSL3,\n\
or TLS cipher. A cipher suite is used only if the policy allows it and\n\
the preference for it is set to True.\n\
\n\
This function must be called once for each cipher you want to enable\n\
or disable by default.\n\
\n\
Note, which cipher suites are permitted or disallowed are modified by\n\
previous calls to one or more of the SSL Export Policy Functions.\n\
"
);

static PyObject *
SSL_set_default_cipher_pref(PyObject *self, PyObject *args)
{
    int cipher;
    int enabled;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "ii:set_default_cipher_pref", &cipher, &enabled))
        return NULL;

    if (SSL_CipherPrefSetDefault(cipher, enabled) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSL_get_default_cipher_pref_doc,
"get_default_cipher_pref(cipher) -> enabled\n\
\n\
:Parameters:\n\
    cipher : integer\n\
        The cipher suite enumeration (e.g. SSL_RSA_WITH_NULL_MD5, etc.)\n\
\n\
Returns the application default preference for the specified SSL2,\n\
SSL3, or TLS cipher.\n\
");

static PyObject *
SSL_get_default_cipher_pref(PyObject *self, PyObject *args)
{
    int cipher;
    int enabled;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:get_default_cipher_pref", &cipher))
        return NULL;

    if (SSL_CipherPrefGetDefault(cipher, &enabled) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    if (enabled)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

PyDoc_STRVAR(SSL_set_cipher_policy_doc,
"set_cipher_pref(cipher, enabled)\n\
\n\
:Parameters:\n\
    cipher : integer\n\
        The cipher suite enumeration (e.g. SSL_RSA_WITH_NULL_MD5, etc.)\n\
    enabled : bool\n\
        Boolean value\n\
\n\
Tells the SSL library that the specified cipher suite is allowed by\n\
the application's export license, or is not allowed by the\n\
application's export license, or is allowed to be used only with a\n\
Step-Up certificate. It overrides the factory default policy for that\n\
cipher suite. The default policy for all cipher suites is\n\
SSL_NOT_ALLOWED, meaning that the application's export license does\n\
not approve the use of this cipher suite. A U.S.domestic version of a\n\
product typically sets all cipher suites to SSL_ALLOWED. This setting\n\
is used to separate export and domestic versions of a product, and is\n\
not intended to express user cipher preferences.\n\
");

static PyObject *
SSL_set_cipher_policy(PyObject *self, PyObject *args)
{
    int cipher;
    int policy;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "ii:set_cipher_policy", &cipher, &policy))
        return NULL;

    if (SSL_CipherPolicySet(cipher, policy) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSL_get_cipher_policy_doc,
"get_cipher_policy(cipher) -> policy\n\
\n\
:Parameters:\n\
    cipher : integer\n\
        The cipher suite enumeration (e.g. SSL_RSA_WITH_NULL_MD5, etc.)\n\
\n\
Returns the cipher policy."
);

static PyObject *
SSL_get_cipher_policy(PyObject *self, PyObject *args)
{
    int cipher;
    int policy;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:get_cipher_policy", &cipher))
        return NULL;

    if (SSL_CipherPolicyGet(cipher, &policy) != SECSuccess) {
        return set_nspr_error(NULL);
    }


    if (policy)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

PyDoc_STRVAR(SSL_config_server_session_id_cache_doc,
"config_server_session_id_cache(max_cache_entries=0, ssl2_timeout=0, ssl3_timeout=0, directory=None)\n\
\n\
:Parameters:\n\
    max_cache_entries : integer\n\
        The maximum number of entries in the cache. If ZERO the server\n\
        default value is used (10,000).\n\
    \n\
    ssl2_timeout : integer\n\
        The lifetime in seconds of an SSL2 session. The minimum timeout\n\
        value is 5 seconds and the maximum is 24 hours. Values outside\n\
        this range are replaced by the server default value (100 seconds).\n\
    \n\
    ssl3_timeout : integer\n\
        The lifetime in seconds of an SSL3 session. The minimum timeout\n\
        value is 5 seconds and the maximum is 24 hours. Values outside\n\
        this range are replaced by the server default value (24 hours).\n\
    \n\
    directory : string\n\
        A string specifying the pathname of the directory that will\n\
        contain the session cache. If None the server default value is\n\
        used (/tmp (Unix) or \\temp (NT)).\n\
\n\
If you are writing an application which will use SSL sockets to\n\
handshake as a server, you must call config_server_session_id_cache()\n\
to configure the session caches for server sessions.\n\
\n\
If your server application uses multiple processes (instead of or in\n\
addition to multiple threads), use `ssl.config_mp_server_sid_cache()`\n\
instead.  You must use one of these functions to create a server\n\
cache.\n\
\n\
This function creates two caches: the server session ID cache (also\n\
called the server session cache, or server cache), and the client-auth\n\
certificate cache (also called the client cert cache, or client auth\n\
cache). Both caches are used only for sessions where the program will\n\
handshakes as a server. The client-auth certificate cache is used to\n\
remember the certificates previously presented by clients for client\n\
certificate authentication.\n\
\n\
A zero value or a value that is out of range for any of the parameters\n\
causes the server default value to be used in the server cache. Note,\n\
this function only affects the server cache, not the client cache.\n\
");


static PyObject *
SSL_config_server_session_id_cache(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"max_cache_entries", "ssl2_timeout", "ssl3_timeout", "directory", NULL};
    int max_cache_entries = 0;
    PRUint32 ssl2_timeout = 0;
    PRUint32 ssl3_timeout = 0;
    PyObject *py_directory = Py_None;
    PyObject *py_directory_fs_encoded = NULL;
    char *directory = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iIIO:config_server_session_id_cache", kwlist,
                                     &max_cache_entries, &ssl2_timeout, &ssl3_timeout, &py_directory))
        return NULL;

    if (py_directory ) {
        if (PyNone_Check(py_directory)) { /* None implies default */
            directory = NULL;
        } else if (!PyUnicode_FSConverter(py_directory, &py_directory_fs_encoded)) {
            return NULL;
        }
    }

    if (SSL_ConfigServerSessionIDCache(max_cache_entries, ssl2_timeout,
                                       ssl3_timeout, directory) != SECSuccess) {
        Py_XDECREF(py_directory_fs_encoded);
        return set_nspr_error(NULL);
    }

    Py_XDECREF(py_directory_fs_encoded);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSL_config_server_session_id_cache_with_opt_doc,
"config_server_session_id_cache_with_opt(max_cache_entries=0, max_cert_cache_entries=0, max_server_name_cache_entries=0, ssl2_timeout=0, ssl3_timeout=0, directory=None, enable_mp_cache=False)\n\
\n\
:Parameters:\n\
    max_cache_entries : integer\n\
        The maximum number of entries in the cache. If ZERO the server\n\
        default value is used (10,000).\n\
    \n\
    max_cert_cache_entries : integer\n\
        The maximum number of entries in the cert cache. If ZERO the server\n\
        default value is used (10,000).\n\
    \n\
    max_server_name_cache_entries : integer\n\
        The maximum number of entries in the server name cache. If ZERO the server\n\
        default value is used (10,000).\n\
    \n\
    ssl2_timeout : integer\n\
        The lifetime in seconds of an SSL2 session. The minimum timeout\n\
        value is 5 seconds and the maximum is 24 hours. Values outside\n\
        this range are replaced by the server default value (100 seconds).\n\
    \n\
    ssl3_timeout : integer\n\
        The lifetime in seconds of an SSL3 session. The minimum timeout\n\
        value is 5 seconds and the maximum is 24 hours. Values outside\n\
        this range are replaced by the server default value (24 hours).\n\
    \n\
    directory : string\n\
        A string specifying the pathname of the directory that will\n\
        contain the session cache. If None the server default value is\n\
        used (/tmp (Unix) or \\temp (NT)).\n\
    \n\
    enable_mp_cache : bool\n\
        If True enable the multi-process cache.\n\
\n\
Configure a secure server's session-id cache. Depends on value of\n\
enable_mp_cache, configures multi-proc or single proc cache.\n\
\n\
A zero value or a value that is out of range for any of the parameters\n\
causes the server default value to be used in the server cache. Note,\n\
this function only affects the server cache, not the client cache.\n\
");


static PyObject *
SSL_config_server_session_id_cache_with_opt(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"max_cache_entries", "max_cert_cache_entries", "max_server_name_cache_entries",
                             "ssl2_timeout", "ssl3_timeout", "directory", "enable_mp_cache", NULL};
    int max_cache_entries = 0;
    int max_cert_cache_entries = 0;
    int max_server_name_cache_entries = 0;
    PRUint32 ssl2_timeout = 0;
    PRUint32 ssl3_timeout = 0;
    PyObject *py_directory = Py_None;
    PyObject *py_directory_fs_encoded = NULL;
    char *directory = NULL;
    PyObject * py_enable_mp_cache = NULL;
    PRBool enable_mp_cache = PR_FALSE;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iiiIIO:config_server_session_id_cache_with_opt", kwlist,
                                     &max_cache_entries, &max_cert_cache_entries, &max_server_name_cache_entries,
                                     &ssl2_timeout, &ssl3_timeout, &py_directory, &py_enable_mp_cache))
        return NULL;

    if (py_directory ) {
        if (PyNone_Check(py_directory)) { /* None implies default */
            directory = NULL;
        } else if (!PyUnicode_FSConverter(py_directory, &py_directory_fs_encoded)) {
            return NULL;
        }
    }

    if (py_enable_mp_cache) {
        enable_mp_cache = PyBoolAsPRBool(py_enable_mp_cache);
    }

    if (SSL_ConfigServerSessionIDCacheWithOpt(ssl2_timeout, ssl3_timeout, directory,
                                              max_cache_entries, max_cert_cache_entries,
                                              max_server_name_cache_entries,
                                              enable_mp_cache) != SECSuccess) {
        Py_XDECREF(py_directory_fs_encoded);
        return set_nspr_error(NULL);
    }

    Py_XDECREF(py_directory_fs_encoded);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSL_config_mp_server_sid_cache_doc,
"config_mp_server_sid_cache(max_cache_entries=0, ssl2_timeout=0, ssl3_timeout=0, directory=None)\n\
\n\
:Parameters:\n\
    max_cache_entries : integer\n\
        The maximum number of entries in the cache. If ZERO the server\n\
        default value is used (10,000).\n\
    \n\
    ssl2_timeout : integer\n\
        The lifetime in seconds of an SSL2 session. The minimum timeout\n\
        value is 5 seconds and the maximum is 24 hours. Values outside\n\
        this range are replaced by the server default value (100 seconds).\n\
    \n\
    ssl3_timeout : integer\n\
        The lifetime in seconds of an SSL3 session. The minimum timeout\n\
        value is 5 seconds and the maximum is 24 hours. Values outside\n\
        this range are replaced by the server default value (24 hours).\n\
    \n\
    directory : string\n\
        A string specifying the pathname of the directory that will\n\
        contain the session cache. If None the server default value is\n\
        used (/tmp (Unix) or \\temp (NT)).\n\
\n\
This function sets up a Server Session ID (SID) cache that is safe for\n\
access by multiple processes on the same system.\n\
\n\
Like `ssl.config_server_session_id_cache()`, with one important\n\
difference.  If the application will run multiple processes (as\n\
opposed to, or in addition to multiple threads), then it must call\n\
this function, instead of calling\n\
`ssl.config_server_session_id_cache()`.  This has nothing to do with\n\
the number of processors, only processes.\n\
");


static PyObject *
SSL_config_mp_server_sid_cache(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"max_cache_entries", "ssl2_timeout", "ssl3_timeout", "directory", NULL};
    int max_cache_entries = 0;
    PRUint32 ssl2_timeout = 0;
    PRUint32 ssl3_timeout = 0;
    PyObject *py_directory = Py_None;
    PyObject *py_directory_fs_encoded = NULL;
    char *directory = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iIIO:config_mp_server_sid_cache", kwlist,
                                     &max_cache_entries, &ssl2_timeout, &ssl3_timeout, &py_directory))
        return NULL;

    if (py_directory ) {
        if (PyNone_Check(py_directory)) { /* None implies default */
            directory = NULL;
        } else if (!PyUnicode_FSConverter(py_directory, &py_directory_fs_encoded)) {
            return NULL;
        }
    }

    if (SSL_ConfigMPServerSIDCache(max_cache_entries, ssl2_timeout,
                                   ssl3_timeout, directory) != SECSuccess) {
        Py_XDECREF(py_directory_fs_encoded);
        return set_nspr_error(NULL);
    }

    Py_XDECREF(py_directory_fs_encoded);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSL_get_max_server_cache_locks_doc,
"get_max_server_cache_locks() -> int\n\
\n\
Get the configured maximum number of mutexes used for the server's\n\
store of SSL sessions.  This value is used by the server session ID\n\
cache initialization functions.\n\
");

static PyObject *
SSL_get_max_server_cache_locks(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    return PyLong_FromLong(SSL_GetMaxServerCacheLocks());
}

PyDoc_STRVAR(SSL_set_max_server_cache_locks_doc,
"set_max_server_cache_locks(max_locks)\n\
\n\
:Parameters:\n\
    max_locks : int\n\
        Maximum number of locks\n\
\n\
Set the configured maximum number of mutexes used for the server's\n\
store of SSL sessions.  This value is used by the server session ID\n\
cache initialization functions.  Note that on some platforms, these\n\
mutexes are actually implemented with POSIX semaphores, or with\n\
unnamed pipes.  The default value varies by platform.  An attempt to\n\
set a too-low maximum will return an error and the configured value\n\
will not be changed.\n\
");

static PyObject *
SSL_set_max_server_cache_locks(PyObject *self, PyObject *args)
{
    unsigned int max_locks;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "I:set_max_server_cache_locks",
                                     &max_locks))
        return NULL;

    if (SSL_SetMaxServerCacheLocks(max_locks) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;

}

PyDoc_STRVAR(SSL_clear_session_cache_doc,
"clear_session_cache()\n\
\n\
You must call ssl.clear_session_cache() after you use one of the SSL\n\
Export Policy Functions to change cipher suite policy settings or use\n\
ssl.set_default_cipher_pref() to enable or disable any cipher\n\
suite. Otherwise, the old settings remain in the session cache and\n\
will be used instead of the new settings. This function clears only\n\
the client cache. The client cache is not configurable. It is located\n\
in RAM (not on disk).\n\
");

static PyObject *
SSL_clear_session_cache(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    SSL_ClearSessionCache();
    Py_RETURN_NONE;
}

PyDoc_STRVAR(SSL_shutdown_server_session_id_cache_doc,
"shutdown_server_session_id_cache()\n\
\n\
");

static PyObject *
SSL_shutdown_server_session_id_cache(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    SSL_ShutdownServerSessionIDCache();
    Py_RETURN_NONE;
}

PyDoc_STRVAR(NSS_set_domestic_policy_doc,
"set_domestic_policy()\n\
\n\
Configures cipher suites to conform with current U.S. export\n\
regulations related to domestic software products with encryption\n\
features.\n\
");

static PyObject *
NSS_set_domestic_policy(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (NSS_SetDomesticPolicy() != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(NSS_set_export_policy_doc,
"set_export_policy()\n\
\n\
Configures the SSL cipher suites to conform with current U.S. export\n\
regulations related to international software products with encryption\n\
features.\n\
");

static PyObject *
NSS_set_export_policy(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (NSS_SetExportPolicy() != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(NSS_set_france_policy_doc,
"set_france_policy()\n\
Configures the SSL cipher suites to conform with French import\n\
regulations related to software products with encryption features.\n\
\n\
");

static PyObject *
NSS_set_france_policy(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (NSS_SetFrancePolicy() != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

static PyObject *
ssl_library_version_to_py_enum_name(unsigned long ssl_library_version)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyLong_FromLong(ssl_library_version)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create object");
        return NULL;
    }

    if ((py_name = PyDict_GetItem(ssl_library_version_value_to_name, py_value)) == NULL) {
        Py_DECREF(py_value);
	PyErr_Format(PyExc_KeyError, "SSL Library Version name not found: %lu", ssl_library_version);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}

static PyObject *
ssl_library_version_to_py_string(unsigned long ssl_library_version)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyLong_FromLong(ssl_library_version)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create object");
        return NULL;
    }

    if ((py_name = PyDict_GetItem(ssl_library_version_value_to_alias, py_value)) == NULL) {
        Py_DECREF(py_value);
	PyErr_Format(PyExc_KeyError, "SSL Library Version name not found: %lu", ssl_library_version);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}

static SECStatus
ssl_library_version_from_name(PyObject *py_name, unsigned long *version_enum)
{
    PyObject *py_lower_name;
    PyObject *py_value;


    if (!PyBaseString_Check(py_name)) {
        PyErr_Format(PyExc_TypeError, "ssl library version name must be a string, not %.200s",
                     Py_TYPE(py_name)->tp_name);

        return SECFailure;
    }

    if ((py_lower_name = PyUnicode_Lower(py_name)) == NULL) {
        return SECFailure;
    }

    if ((py_value = PyDict_GetItem(ssl_library_version_name_to_value, py_lower_name)) == NULL) {
        if ((py_value = PyDict_GetItem(ssl_library_version_alias_to_value, py_lower_name)) == NULL) {
            PyObject *py_name_utf8 = PyBaseString_UTF8(py_name, "name");
            PyErr_Format(PyExc_KeyError, "ssl_library_version name not found: %s", PyBytes_AsString(py_name_utf8));
            Py_DECREF(py_lower_name);
            Py_XDECREF(py_name_utf8);
            return SECFailure;
        }
    }

    Py_DECREF(py_lower_name);

    *version_enum = PyLong_AsUnsignedLong(py_value);

    return SECSuccess;
}

static SECStatus
ssl_library_version_from_pyobject(PyObject *py_value, const char *bound, unsigned long *version_enum)
{
    if (PyInteger_Check(py_value)) {
        *version_enum = PyLong_AsUnsignedLong(py_value);
        return SECSuccess;
    }

    if (PyBaseString_Check(py_value)) {
        return ssl_library_version_from_name(py_value, version_enum);
    }

    PyErr_Format(PyExc_TypeError, "ssl library %s version value be an integer or string, not %.200s",
                 bound, Py_TYPE(py_value)->tp_name);
    return SECFailure;
}

PyDoc_STRVAR(SSL_get_ssl_version_from_major_minor_doc,
"get_ssl_version_from_major_minor(major, minor, repr_kind=AsString) -> Object\n\
\n\
:Parameters:\n\
    major : int\n\
        The major version number.\n\
    minor : int\n\
        The minor version number.\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what format the return value will be in.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsString\n\
            A short friendly name for the enumerated constant.\n\
\n\
Given the major and minor SSL protocol versions return the SSL version\n\
it's according to repr_kind\n\
\n\
Example:\n\
    get_ssl_version_from_major_minor(3, 1, nss.AsString) -> 'tls1.0'\n\
\n\
");
static PyObject *
SSL_get_ssl_version_from_major_minor(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"ssl_library_version", "repr_kind", NULL};
    unsigned int major, minor;
    RepresentationKind repr_kind = AsString;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "II|i:get_ssl_version_from_major_minor", kwlist,
                                     &major, &minor, &repr_kind))
        return NULL;

    return ssl_version_to_repr_kind(major, minor, repr_kind);
}

PyDoc_STRVAR(SSL_ssl_library_version_name_doc,
"ssl_library_version_name(ssl_library_version, repr_kind=AsEnumName) -> string\n\
\n\
:Parameters:\n\
    ssl_library_version : int\n\
        SSL_LIBRARY_VERSION constant\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what format the contents of the returned tuple will be in.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsString\n\
            A short friendly name for the enumerated constant.\n\
\n\
Given a SSL_LIBRARY_VERSION constant\n\
return it's according to repr_kind\n\
");
static PyObject *
SSL_ssl_library_version_name(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"ssl_library_version", "repr_kind", NULL};
    unsigned long ssl_library_version;
    RepresentationKind repr_kind = AsEnumName;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "k|i:ssl_library_version_name", kwlist,
                                     &ssl_library_version, &repr_kind))
        return NULL;

    return ssl_library_version_to_repr_kind(ssl_library_version, repr_kind);
}

PyDoc_STRVAR(SSL_ssl_library_version_from_name_doc,
"ssl_library_version_from_name(name) -> int\n\
\n\
:Parameters:\n\
    name : string\n\
        name of SSL_LIBRARY_VERSION\n\
\n\
Given the name of a SSL_LIBRARY_VERSION\n\
return it's integer constant\n\
The string comparison is case insensitive.\n\
In addition to the names of the SSL_LIBRARY_VERSION constants\n\
the following aliases are recognized:\n\
\n\
+--------+-----------------------------+\n\
| Alias  | Constant                    |\n\
+========+=============================+\n\
| ssl2   | SSL_LIBRARY_VERSION_2       |\n\
+--------+-----------------------------+\n\
| ssl3   | SSL_LIBRARY_VERSION_3_0     |\n\
+--------+-----------------------------+\n\
| tls1.0 | SSL_LIBRARY_VERSION_TLS_1_0 |\n\
+--------+-----------------------------+\n\
| tls1.1 | SSL_LIBRARY_VERSION_TLS_1_1 |\n\
+--------+-----------------------------+\n\
| tls1.2 | SSL_LIBRARY_VERSION_TLS_1_2 |\n\
+--------+-----------------------------+\n\
| tls1.3 | SSL_LIBRARY_VERSION_TLS_1_3 |\n\
+--------+-----------------------------+\n\
\n\
");
static PyObject *
SSL_ssl_library_version_from_name(PyObject *self, PyObject *args)
{
    PyObject *py_name;
    unsigned long version_enum;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:ssl_library_version_from_name", &py_name))
        return NULL;

    if (ssl_library_version_from_name(py_name, &version_enum) != SECSuccess) {
        return NULL;
    }

    return PyLong_FromLong(version_enum);
}

PyDoc_STRVAR(SSL_get_supported_ssl_version_range_doc,
"get_supported_ssl_version_range(protocol_variant=SSL_VARIANT_STREAM, repr_kind=AsEnum) -> (min_version, max_version)\n\
\n\
:Parameters:\n\
    protocol_variant : int\n\
        One of: SSL_VARIANT_STREAM or SSL_VARIANT_DATAGRAM\n\
        enumerated constants\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what format the contents of the returned tuple will be in.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsString\n\
            A short friendly name for the enumerated constant.\n\
\n\
Returns the range of SSL3/TLS versions supported for the\n\
given protocol variant by the version of libssl linked-to at runtime.\n\
The result is a tuple of enumerations (min_version, max_version).\n\
\n\
");

static PyObject *
SSL_get_supported_ssl_version_range(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"protocol_variant", "repr_kind", NULL};
    unsigned long protocol_variant = ssl_variant_stream;
    RepresentationKind repr_kind = AsEnum;
    SSLVersionRange range;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ki:get_supported_ssl_version_range", kwlist,
                                     &protocol_variant, &repr_kind))
        return NULL;

    if (SSL_VersionRangeGetSupported(protocol_variant, &range) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return SSLVersionRange_to_tuple(&range, repr_kind);

}

PyDoc_STRVAR(SSL_get_default_ssl_version_range_doc,
"get_default_ssl_version_range(protocol_variant=SSL_VARIANT_STREAM, repr_kind=AsEnum) -> (min_version, max_version)\n\
\n\
:Parameters:\n\
    protocol_variant : int\n\
        One of: SSL_VARIANT_STREAM or SSL_VARIANT_DATAGRAM\n\
        enumerated constants\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what format the contents of the returned tuple will be in.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsString\n\
            A short friendly name for the enumerated constant.\n\
\n\
Returns the range of SSL3/TLS versions enabled by default for the given\n\
protocol variant.\n\
The result is a tuple of enumerations (min_version, max_version).\n\
\n\
");

static PyObject *
SSL_get_default_ssl_version_range(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"protocol_variant", "repr_kind", NULL};
    unsigned long protocol_variant = ssl_variant_stream;
    RepresentationKind repr_kind = AsEnum;
    SSLVersionRange range;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ki:get_default_ssl_version_range", kwlist,
                                     &protocol_variant, &repr_kind))
        return NULL;

    if (SSL_VersionRangeGetDefault(protocol_variant, &range) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return SSLVersionRange_to_tuple(&range, repr_kind);

}

PyDoc_STRVAR(SSL_set_default_ssl_version_range_doc,
"set_default_ssl_version_range(min_version, max_version, protocol_variant=SSL_VARIANT_STREAM)\n\
\n\
:Parameters:\n\
    min_version : int or string\n\
        Either a SSL_LIBRARY_VERSION_* enumerated constant or it's\n\
        string equivalent, see `ssl_library_version_from_name()`\n\
    max_version : int or string\n\
        Either a SSL_LIBRARY_VERSION_* enumerated constant or it's\n\
        string equivalent, see `ssl_library_version_from_name()`\n\
    protocol_variant : int\n\
        One of: SSL_VARIANT_STREAM or SSL_VARIANT_DATAGRAM\n\
        enumerated constants\n\
\n\
Sets the range of SSL3/TLS versions enabled by default for the given\n\
protocol variant.\n\
");

static PyObject *
SSL_set_default_ssl_version_range(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"min_version", "max_version", "protocol_variant", NULL};
    PyObject *py_min = NULL;
    PyObject *py_max = NULL;
    unsigned long min_version;
    unsigned long max_version;
    unsigned long protocol_variant = ssl_variant_stream;
    SSLVersionRange range;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO|k:set_default_ssl_version_range", kwlist,
                                     &py_min, &py_max, &protocol_variant))
        return NULL;

    if (ssl_library_version_from_pyobject(py_min, "min", &min_version)
        != SECSuccess) {
        return NULL;
    }

    if (ssl_library_version_from_pyobject(py_max, "max", &max_version)
        != SECSuccess) {
        return NULL;
    }

    range.min = min_version;
    range.max = max_version;

    if (SSL_VersionRangeSetDefault(protocol_variant, &range) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;

}

PyDoc_STRVAR(SSL_get_cipher_suite_info_doc,
"get_cipher_suite_info(suite) -> SSLCipherSuiteInfo\n\
\n\
:Parameters:\n\
    suite : int\n\
        a cipher suite enumerated constant\n\
\n\
Returns a `ssl.SSLCipherSuiteInfo`.\n\
");

static PyObject *
SSL_get_cipher_suite_info(PyObject *self, PyObject *args)
{
    unsigned int suite;
    SSLCipherSuiteInfo info;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "I:get_cipher_suite_info",
                          &suite))
        return NULL;

    if (SSL_GetCipherSuiteInfo(suite, &info, sizeof(info)) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return SSLCipherSuiteInformation_new_from_SSLCipherSuiteInfo(&info);

}

PyDoc_STRVAR(SSL_ssl_cipher_suite_name_doc,
"ssl_cipher_suite_name(cipher) -> string\n\
\n\
:Parameters:\n\
    cipher : int\n\
        SSL cipher enumerated constant\n\
\n\
Given an enumerated SSL Cipher constant\n\
return it's name as a string\n\
");
static PyObject *
SSL_ssl_cipher_suite_name(PyObject *self, PyObject *args)
{
    unsigned long cipher;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:ssl_cipher_suite_name",
                          &cipher))
        return NULL;

    return cipher_suite_to_name(cipher);
}

PyDoc_STRVAR(SSL_ssl_cipher_suite_from_name_doc,
"ssl_cipher_suite_from_name(name) -> int\n\
\n\
:Parameters:\n\
    name : string\n\
        name of SSL cipher enumerated constant\n\
\n\
Given the name of a SSL cipher constant\n\
return it's integer constant\n\
The string comparison is case insensitive.\n\
");
static PyObject *
SSL_ssl_cipher_suite_from_name(PyObject *self, PyObject *args)
{
    PyObject *py_name;
    unsigned long suite;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:ssl_cipher_suite_from_name",
                          &py_name))
        return NULL;

    if (cipher_suite_from_name(py_name, &suite) != SECSuccess) {
        return NULL;
    }

    return PyLong_FromLong(suite);
}



/* List of functions exported by this module. */
static PyMethodDef module_methods[] = {
{"set_ssl_default_option",                  (PyCFunction)SSL_set_ssl_default_option,                  METH_VARARGS,               SSL_set_ssl_default_option_doc},
{"get_ssl_default_option",                  (PyCFunction)SSL_get_ssl_default_option,                  METH_VARARGS,               SSL_get_ssl_default_option_doc},
{"set_default_cipher_pref",                 (PyCFunction)SSL_set_default_cipher_pref,                 METH_VARARGS,               SSL_set_default_cipher_pref_doc},
{"get_default_cipher_pref",                 (PyCFunction)SSL_get_default_cipher_pref,                 METH_VARARGS,               SSL_get_default_cipher_pref_doc},
{"set_cipher_policy",                       (PyCFunction)SSL_set_cipher_policy,                       METH_VARARGS,               SSL_set_cipher_policy_doc},
{"get_cipher_policy",                       (PyCFunction)SSL_get_cipher_policy,                       METH_VARARGS,               SSL_get_cipher_policy_doc},
{"config_server_session_id_cache",          (PyCFunction)SSL_config_server_session_id_cache,          METH_VARARGS|METH_KEYWORDS, SSL_config_server_session_id_cache_doc},
{"config_mp_server_sid_cache",              (PyCFunction)SSL_config_mp_server_sid_cache,              METH_VARARGS|METH_KEYWORDS, SSL_config_mp_server_sid_cache_doc},
{"config_server_session_id_cache_with_opt", (PyCFunction)SSL_config_server_session_id_cache_with_opt, METH_VARARGS|METH_KEYWORDS, SSL_config_server_session_id_cache_with_opt_doc},
{"get_max_server_cache_locks",              (PyCFunction)SSL_get_max_server_cache_locks,              METH_NOARGS,                SSL_get_max_server_cache_locks_doc},
{"set_max_server_cache_locks",              (PyCFunction)SSL_set_max_server_cache_locks,              METH_VARARGS,               SSL_set_max_server_cache_locks_doc},
{"clear_session_cache",                     (PyCFunction)SSL_clear_session_cache,                     METH_NOARGS,                SSL_clear_session_cache_doc},
{"shutdown_server_session_id_cache",        (PyCFunction)SSL_shutdown_server_session_id_cache,        METH_NOARGS,                SSL_shutdown_server_session_id_cache_doc},
{"set_domestic_policy",                     (PyCFunction)NSS_set_domestic_policy,                     METH_NOARGS,                NSS_set_domestic_policy_doc},
{"set_export_policy",                       (PyCFunction)NSS_set_export_policy,                       METH_NOARGS,                NSS_set_export_policy_doc},
{"set_france_policy",                       (PyCFunction)NSS_set_france_policy,                       METH_NOARGS,                NSS_set_france_policy_doc},
{"get_ssl_version_from_major_minor",        (PyCFunction)SSL_get_ssl_version_from_major_minor,        METH_VARARGS|METH_KEYWORDS, SSL_get_ssl_version_from_major_minor_doc},
{"ssl_library_version_name",                (PyCFunction)SSL_ssl_library_version_name,                METH_VARARGS|METH_KEYWORDS, SSL_ssl_library_version_name_doc},
{"ssl_library_version_from_name",           (PyCFunction)SSL_ssl_library_version_from_name,           METH_VARARGS,               SSL_ssl_library_version_from_name_doc},
{"get_supported_ssl_version_range",         (PyCFunction)SSL_get_supported_ssl_version_range,         METH_VARARGS|METH_KEYWORDS, SSL_get_supported_ssl_version_range_doc},
{"get_default_ssl_version_range",           (PyCFunction)SSL_get_default_ssl_version_range,           METH_VARARGS|METH_KEYWORDS, SSL_get_default_ssl_version_range_doc},
{"set_default_ssl_version_range",           (PyCFunction)SSL_set_default_ssl_version_range,           METH_VARARGS|METH_KEYWORDS, SSL_set_default_ssl_version_range_doc},
{"get_cipher_suite_info",                   (PyCFunction)SSL_get_cipher_suite_info,                   METH_VARARGS,               SSL_get_cipher_suite_info_doc},
{"ssl_cipher_suite_name",                   (PyCFunction)SSL_ssl_cipher_suite_name,                   METH_VARARGS,               SSL_ssl_cipher_suite_name_doc},
{"ssl_cipher_suite_from_name",              (PyCFunction)SSL_ssl_cipher_suite_from_name,              METH_VARARGS,               SSL_ssl_cipher_suite_from_name_doc},
{NULL, NULL}            /* Sentinel */
};

/* ============================== Module Exports ============================= */

static PyNSS_SSL_C_API_Type nss_ssl_c_api =
{
    &SSLSocketType,                /* sslsocket_type */
};

/* ============================== Module Construction ============================= */

PyDoc_STRVAR(module_doc,
"This module implements the SSL functionality in NSS\n\
\n\
SSL Version Range API\n\
=====================\n\
\n\
This API should be used to control SSL 3.0 & TLS support instead of\n\
the older `SSLSocket.set_ssl_option()` API; however,\n\
`SSLSocket.set_ssl_option()` API MUST still be used to control SSL 2.0\n\
support. In this version of libssl, SSL 3.0 and TLS 1.0 are enabled by\n\
default. Future versions of libssl may change which versions of the\n\
protocol are enabled by default.\n\
\n\
The protocol_variant enums (SSL_VARIANT_STREAM, SSL_VARIANT_DATAGRAM)\n\
indicates whether the protocol is of type stream or datagram. This\n\
must be provided to the functions that do not take an fd. Functions\n\
which take an fd will get the variant from the fd.\n\
\n\
Using the new version range API in conjunction with the older\n\
`SSLSocket.set_ssl_option()` API for controlling the enabled protocol\n\
versions may cause unexpected results. Going forward, we guarantee\n\
only the following:\n\
\n\
``SSLSocket.get_ssl_option(ssl.SSL_ENABLE_TLS)`` will return True if\n\
*ANY* versions of TLS are enabled.\n\
\n\
``SSLSocket.set_ssl_option(ssl.SSL_ENABLE_TLS, False)`` will disable\n\
*ALL* versions of TLS, including TLS 1.0 and later.\n\
\n\
The above two properties provide compatibility for applications that\n\
use `SSLSocket.set_ssl_option()` to implement the insecure fallback\n\
from TLS 1.x to SSL 3.0.\n\
\n\
``SSLSocket.set_ssl_option(ssl.SSL_ENABLE_TLS, True)`` will enable TLS\n\
1.0, and may also enable some later versions of TLS, if it is\n\
necessary to do so in order to keep the set of enabled versions\n\
contiguous. For example, if TLS 1.2 is enabled, then after\n\
``SSLSocket.set_ssl_option(ss.SSL_ENABLE_TLS, True)``, TLS 1.0, TLS\n\
1.1, and TLS 1.2 will be enabled, and the call will have no effect on\n\
whether SSL 3.0 is enabled. If no later versions of TLS are enabled at\n\
the time ``SSLSocket.set_ssl_option(ssl.SSL_ENABLE_TLS, True)`` is\n\
called, then no later versions of TLS will be enabled by the call.\n\
\n\
``SSLSocket.set_ssl_option(ssl.SSL_ENABLE_SSL3, False)`` will disable\n\
SSL 3.0, and will not change the set of TLS versions that are enabled.\n\
\n\
``SSLSocket.set_ssl_option(ssl.SSL_ENABLE_SSL3, True)`` will enable SSL\n\
3.0, and may also enable some versions of TLS if TLS 1.1 or later is\n\
enabled at the time of the call, the same way\n\
``SSLSocket.set_ssl_option(ssl.SSL_ENABLE_TLS, True)`` works, in order\n\
to keep the set of enabled versions contiguous.\n\
");

#if PY_MAJOR_VERSION >= 3

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    NSS_SSL_MODULE_NAME,        /* m_name */
    module_doc,                 /* m_doc */
    -1,                         /* m_size */
    module_methods,             /* m_methods */
    NULL,                       /* m_reload */
    NULL,                       /* m_traverse */
    NULL,                       /* m_clear */
    NULL                        /* m_free */
};

#else /* PY_MAOR_VERSION < 3 */
#endif /* PY_MAJOR_VERSION */

MOD_INIT(ssl)
{
    PyObject *m;
    int i;


    if (import_nspr_error_c_api() < 0)
        return MOD_ERROR_VAL;

    if (import_nspr_io_c_api() < 0)
        return MOD_ERROR_VAL;

    if (import_nspr_nss_c_api() < 0)
        return MOD_ERROR_VAL;

    SSLSocketType.tp_base = &SocketType;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&module_def);
#else
    m = Py_InitModule3(NSS_SSL_MODULE_NAME, module_methods, module_doc);
#endif

    if (m == NULL) {
        return MOD_ERROR_VAL;
    }

    if ((empty_tuple = PyTuple_New(0)) == NULL) {
        return MOD_ERROR_VAL;
    }
    Py_INCREF(empty_tuple);

    TYPE_READY(SSLSocketType);
    TYPE_READY(SSLCipherSuiteInformationType);
    TYPE_READY(SSLChannelInformationType);

    /* Export C API */
    if (PyModule_AddObject(m, "_C_API",
                           PyCapsule_New((void *)&nss_ssl_c_api, "_C_API", NULL)) != 0)
        return MOD_ERROR_VAL;

    /* SSL_ImplementedCiphers */
    {
        PRUint16 n_implemented_ciphers = SSL_GetNumImplementedCiphers();
        const PRUint16 *implemented_ciphers = SSL_GetImplementedCiphers();

        if ((py_ssl_implemented_ciphers = PyTuple_New(n_implemented_ciphers)) == NULL) {
            return MOD_ERROR_VAL;
        }

        for (i = 0; i < n_implemented_ciphers; i++) {
            PyTuple_SetItem(py_ssl_implemented_ciphers, i, PyLong_FromLong(implemented_ciphers[i]));
        }

        PyModule_AddObject(m, "ssl_implemented_ciphers", py_ssl_implemented_ciphers);
    }

    /***************************************************************************
     * SSL Library Version
     ***************************************************************************/

    if ((ssl_library_version_name_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((ssl_library_version_value_to_name = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstant(constant)                      \
if (_AddIntConstantWithLookup(m, #constant, constant, \
    NULL, ssl_library_version_name_to_value, ssl_library_version_value_to_name) < 0) return MOD_ERROR_VAL;

    ExportConstant(SSL_LIBRARY_VERSION_2);
    ExportConstant(SSL_LIBRARY_VERSION_3_0);
    ExportConstant(SSL_LIBRARY_VERSION_TLS_1_0);
    ExportConstant(SSL_LIBRARY_VERSION_TLS_1_1);
    ExportConstant(SSL_LIBRARY_VERSION_TLS_1_2);
    ExportConstant(SSL_LIBRARY_VERSION_TLS_1_3);


    if ((ssl_library_version_alias_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((ssl_library_version_value_to_alias = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstantAlias(constant, alias)          \
if (_AddIntConstantWithLookup(m, alias, constant, \
    NULL, ssl_library_version_alias_to_value, ssl_library_version_value_to_alias) < 0) return MOD_ERROR_VAL;

    ExportConstantAlias(SSL_LIBRARY_VERSION_2,       "ssl2");
    ExportConstantAlias(SSL_LIBRARY_VERSION_3_0,     "ssl3");
    ExportConstantAlias(SSL_LIBRARY_VERSION_TLS_1_0, "tls1.0");
    ExportConstantAlias(SSL_LIBRARY_VERSION_TLS_1_1, "tls1.1");
    ExportConstantAlias(SSL_LIBRARY_VERSION_TLS_1_2, "tls1.2");
    ExportConstantAlias(SSL_LIBRARY_VERSION_TLS_1_3, "tls1.3");


#undef ExportConstant
#undef ExportConstantAlias

    AddIntConstantName(SSL_VARIANT_STREAM, ssl_variant_stream);
    AddIntConstantName(SSL_VARIANT_DATAGRAM, ssl_variant_datagram);


    /* NSS SSL Constants */
    AddIntConstant(SSL_SECURITY);
    AddIntConstant(SSL_SOCKS);
    AddIntConstant(SSL_REQUEST_CERTIFICATE);
    AddIntConstant(SSL_HANDSHAKE_AS_CLIENT);
    AddIntConstant(SSL_HANDSHAKE_AS_SERVER);
    AddIntConstant(SSL_ENABLE_SSL2);
    AddIntConstant(SSL_ENABLE_SSL3);
    AddIntConstant(SSL_NO_CACHE);
    AddIntConstant(SSL_REQUIRE_CERTIFICATE);
    AddIntConstant(SSL_ENABLE_FDX);
    AddIntConstant(SSL_V2_COMPATIBLE_HELLO);
    AddIntConstant(SSL_ENABLE_TLS);
    AddIntConstant(SSL_ROLLBACK_DETECTION);
    AddIntConstant(SSL_NO_STEP_DOWN);
    AddIntConstant(SSL_BYPASS_PKCS11);
    AddIntConstant(SSL_NO_LOCKS);

    /* Values for "policy" argument to SSL_PolicySet and returned by SSL_CipherPolicyGet. */
    AddIntConstant(SSL_NOT_ALLOWED);
    AddIntConstant(SSL_ALLOWED);
    AddIntConstant(SSL_RESTRICTED);

    /* Values for "on" with SSL_REQUIRE_CERTIFICATE.*/
    AddIntConstant(SSL_REQUIRE_NEVER);
    AddIntConstant(SSL_REQUIRE_ALWAYS);
    AddIntConstant(SSL_REQUIRE_FIRST_HANDSHAKE);
    AddIntConstant(SSL_REQUIRE_NO_ERROR);

    /* Values for "on" with SSL_SecurityStatus. */
    AddIntConstant(SSL_SECURITY_STATUS_NOOPT);
    AddIntConstant(SSL_SECURITY_STATUS_OFF);
    AddIntConstant(SSL_SECURITY_STATUS_ON_HIGH);
    AddIntConstant(SSL_SECURITY_STATUS_ON_LOW);

    /* Cypher kinds (not the spec version!) */
    AddIntConstant(SSL_CK_RC4_128_WITH_MD5);
    AddIntConstant(SSL_CK_RC4_128_EXPORT40_WITH_MD5);
    AddIntConstant(SSL_CK_RC2_128_CBC_WITH_MD5);
    AddIntConstant(SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5);
    AddIntConstant(SSL_CK_IDEA_128_CBC_WITH_MD5);
    AddIntConstant(SSL_CK_DES_64_CBC_WITH_MD5);
    AddIntConstant(SSL_CK_DES_192_EDE3_CBC_WITH_MD5);

    /* Cipher enables.  These are used only for SSL_EnableCipher
     * These values define the SSL2 suites, and do not colide with the
     * SSL3 Cipher suites defined below.
     */
    AddIntConstant(SSL_EN_RC4_128_WITH_MD5);
    AddIntConstant(SSL_EN_RC4_128_EXPORT40_WITH_MD5);
    AddIntConstant(SSL_EN_RC2_128_CBC_WITH_MD5);
    AddIntConstant(SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5);
    AddIntConstant(SSL_EN_IDEA_128_CBC_WITH_MD5);
    AddIntConstant(SSL_EN_DES_64_CBC_WITH_MD5);
    AddIntConstant(SSL_EN_DES_192_EDE3_CBC_WITH_MD5);

    /**************************************************************************
     * Cipher Suites
     **************************************************************************/

    if ((cipher_suite_name_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((cipher_suite_value_to_name = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstant(constant)                      \
if (_AddIntConstantWithLookup(m, #constant, constant, \
    NULL, cipher_suite_name_to_value, cipher_suite_value_to_name) < 0) return MOD_ERROR_VAL;

    /* Deprecated SSL 3.0 & libssl names replaced by IANA-registered TLS names. */
#ifndef SSL_DISABLE_DEPRECATED_CIPHER_SUITE_NAMES
    ExportConstant(SSL_NULL_WITH_NULL_NULL);
    ExportConstant(SSL_RSA_WITH_NULL_MD5);
    ExportConstant(SSL_RSA_WITH_NULL_SHA);
    ExportConstant(SSL_RSA_EXPORT_WITH_RC4_40_MD5);
    ExportConstant(SSL_RSA_WITH_RC4_128_MD5);
    ExportConstant(SSL_RSA_WITH_RC4_128_SHA);
    ExportConstant(SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
    ExportConstant(SSL_RSA_WITH_IDEA_CBC_SHA);
    ExportConstant(SSL_RSA_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(SSL_RSA_WITH_DES_CBC_SHA);
    ExportConstant(SSL_RSA_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(SSL_DH_DSS_WITH_DES_CBC_SHA);
    ExportConstant(SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(SSL_DH_RSA_WITH_DES_CBC_SHA);
    ExportConstant(SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(SSL_DHE_DSS_WITH_DES_CBC_SHA);
    ExportConstant(SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(SSL_DHE_RSA_WITH_DES_CBC_SHA);
    ExportConstant(SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(SSL_DH_ANON_WITH_RC4_128_MD5);
    ExportConstant(SSL_DH_ANON_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(SSL_DH_ANON_WITH_DES_CBC_SHA);
    ExportConstant(SSL_DH_ANON_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(SSL_DH_ANON_EXPORT_WITH_RC4_40_MD5);
    ExportConstant(TLS_DH_ANON_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_DH_ANON_WITH_AES_256_CBC_SHA);
    ExportConstant(TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA);
    ExportConstant(TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA);
#endif

    ExportConstant(TLS_NULL_WITH_NULL_NULL);

    ExportConstant(TLS_RSA_WITH_NULL_MD5);
    ExportConstant(TLS_RSA_WITH_NULL_SHA);
    ExportConstant(TLS_RSA_EXPORT_WITH_RC4_40_MD5);
    ExportConstant(TLS_RSA_WITH_RC4_128_MD5);
    ExportConstant(TLS_RSA_WITH_RC4_128_SHA);
    ExportConstant(TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
    ExportConstant(TLS_RSA_WITH_IDEA_CBC_SHA);
    ExportConstant(TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(TLS_RSA_WITH_DES_CBC_SHA);
    ExportConstant(TLS_RSA_WITH_3DES_EDE_CBC_SHA);

    ExportConstant(TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(TLS_DH_DSS_WITH_DES_CBC_SHA);
    ExportConstant(TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(TLS_DH_RSA_WITH_DES_CBC_SHA);
    ExportConstant(TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA);

    ExportConstant(TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(TLS_DHE_DSS_WITH_DES_CBC_SHA);
    ExportConstant(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(TLS_DHE_RSA_WITH_DES_CBC_SHA);
    ExportConstant(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);

    ExportConstant(TLS_DH_anon_EXPORT_WITH_RC4_40_MD5);
    ExportConstant(TLS_DH_anon_WITH_RC4_128_MD5);
    ExportConstant(TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA);
    ExportConstant(TLS_DH_anon_WITH_DES_CBC_SHA);
    ExportConstant(TLS_DH_anon_WITH_3DES_EDE_CBC_SHA);

    ExportConstant(SSL_FORTEZZA_DMS_WITH_NULL_SHA);
    ExportConstant(SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA);
    ExportConstant(SSL_FORTEZZA_DMS_WITH_RC4_128_SHA);

    ExportConstant(TLS_RSA_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_DH_DSS_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_DH_RSA_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_DH_anon_WITH_AES_128_CBC_SHA);

    ExportConstant(TLS_RSA_WITH_AES_256_CBC_SHA);
    ExportConstant(TLS_DH_DSS_WITH_AES_256_CBC_SHA);
    ExportConstant(TLS_DH_RSA_WITH_AES_256_CBC_SHA);
    ExportConstant(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
    ExportConstant(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
    ExportConstant(TLS_DH_anon_WITH_AES_256_CBC_SHA);
    ExportConstant(TLS_RSA_WITH_NULL_SHA256);
    ExportConstant(TLS_RSA_WITH_AES_128_CBC_SHA256);
    ExportConstant(TLS_RSA_WITH_AES_256_CBC_SHA256);

    ExportConstant(TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
    ExportConstant(TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA);
    ExportConstant(TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA);
    ExportConstant(TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
    ExportConstant(TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA);
    ExportConstant(TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA);

    ExportConstant(TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA);
    ExportConstant(TLS_RSA_EXPORT1024_WITH_RC4_56_SHA);

    ExportConstant(TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA);
    ExportConstant(TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA);
    ExportConstant(TLS_DHE_DSS_WITH_RC4_128_SHA);
    ExportConstant(TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
    ExportConstant(TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);

    ExportConstant(TLS_RSA_WITH_CAMELLIA_256_CBC_SHA);
    ExportConstant(TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA);
    ExportConstant(TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA);
    ExportConstant(TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA);
    ExportConstant(TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
    ExportConstant(TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA);

    ExportConstant(TLS_RSA_WITH_SEED_CBC_SHA);

    ExportConstant(TLS_RSA_WITH_AES_128_GCM_SHA256);
    ExportConstant(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
    ExportConstant(TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);

    /* TLS "Signaling Cipher Suite Value" (SCSV). May be requested by client.
     * Must NEVER be chosen by server.  SSL 3.0 server acknowledges by sending
     * back an empty Renegotiation Info (RI) server hello extension.
     */
    ExportConstant(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    /* TLS_FALLBACK_SCSV is a signaling cipher suite value that indicates that a
     * handshake is the result of TLS version fallback.
     */
    ExportConstant(TLS_FALLBACK_SCSV);

    /* Cipher Suite Values starting with 0xC000 are defined in informational
     * RFCs.
     */
    ExportConstant(TLS_ECDH_ECDSA_WITH_NULL_SHA);
    ExportConstant(TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
    ExportConstant(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);

    ExportConstant(TLS_ECDHE_ECDSA_WITH_NULL_SHA);
    ExportConstant(TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
    ExportConstant(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);

    ExportConstant(TLS_ECDH_RSA_WITH_NULL_SHA);
    ExportConstant(TLS_ECDH_RSA_WITH_RC4_128_SHA);
    ExportConstant(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);

    ExportConstant(TLS_ECDHE_RSA_WITH_NULL_SHA);
    ExportConstant(TLS_ECDHE_RSA_WITH_RC4_128_SHA);
    ExportConstant(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);

    ExportConstant(TLS_ECDH_anon_WITH_NULL_SHA);
    ExportConstant(TLS_ECDH_anon_WITH_RC4_128_SHA);
    ExportConstant(TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
    ExportConstant(TLS_ECDH_anon_WITH_AES_256_CBC_SHA);

    ExportConstant(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
    ExportConstant(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);

    ExportConstant(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    ExportConstant(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
    ExportConstant(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    ExportConstant(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);

    /* draft-ietf-tls-chacha20-poly1305-04 */
#ifdef TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    ExportConstant(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    ExportConstant(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
    ExportConstant(TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
#endif
#ifdef TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    ExportConstant(TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
    ExportConstant(TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256);
#endif

    /* TLS 1.3 cipher suites */
#ifdef TLS_AES_128_GCM_SHA256
    ExportConstant(TLS_AES_128_GCM_SHA256);
    ExportConstant(TLS_AES_256_GCM_SHA384);
    ExportConstant(TLS_CHACHA20_POLY1305_SHA256);
#endif

    /* Netscape "experimental" cipher suites. */
    ExportConstant(SSL_RSA_OLDFIPS_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(SSL_RSA_OLDFIPS_WITH_DES_CBC_SHA);

    /* New non-experimental openly spec'ed versions of those cipher suites. */
    ExportConstant(SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA);
    ExportConstant(SSL_RSA_FIPS_WITH_DES_CBC_SHA);

    /* DTLS-SRTP cipher suites from RFC 5764 */
    ExportConstant(SRTP_AES128_CM_HMAC_SHA1_80);
    ExportConstant(SRTP_AES128_CM_HMAC_SHA1_32);
    ExportConstant(SRTP_NULL_HMAC_SHA1_80);
    ExportConstant(SRTP_NULL_HMAC_SHA1_32);

#undef ExportConstant

    return MOD_SUCCESS_VAL(m);
}
