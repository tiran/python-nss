/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* NSPR header files */
#undef HAVE_LONG_LONG           /* FIXME: both Python.h and nspr.h define HAVE_LONG_LONG  */
#include "nspr.h"
#include "private/pprio.h"
#include "prnetdb.h"

/* ========================================================================== */
/* ============================== AddrInfo Class ============================ */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRAddrInfo *pr_addrinfo;
    PyObject *py_hostname;
    PyObject *py_canonical_name;
    PyObject *py_netaddrs;
} AddrInfo;

#define PyAddrInfo_Check(op) PyObject_TypeCheck(op, &AddrInfoType)

/* ========================================================================== */
/* ============================= HostEntry Class ============================ */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRHostEnt entry;
    char buffer[PR_NETDB_BUF_SIZE]; /* this is where data pointed to in PRHostEnt is stored */
    PyObject *py_aliases;
    PyObject *py_netaddrs;
} HostEntry;

#define PyHostEntry_Check(op) PyObject_TypeCheck(op, &HostEntryType)

/* ========================================================================== */
/* =========================== NetworkAddress Class ========================= */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    PRNetAddr pr_netaddr;
    PyObject *py_hostname;
    HostEntry *py_hostentry;
} NetworkAddress;

#define PyNetworkAddress_Check(op) PyObject_TypeCheck(op, &NetworkAddressType)

/* ========================================================================== */
/* ============================== Socket Class ============================== */
/* ========================================================================== */

#define ALLOC_INCREMENT 1024
typedef struct {
    char *buf;
    long len;
    long alloc_len;
} ReadAhead;


#define SOCKET_OPEN_FOR_READ(py_socket)         \
{                                               \
    Socket *sock = (Socket*)py_socket;          \
                                                \
    sock->open_for_read = 1;                    \
}

#define SOCKET_CLOSED_FOR_READ(py_socket)       \
{                                               \
    Socket *sock = (Socket*)py_socket;          \
                                                \
    sock->open_for_read = 0;                    \
}

#define INIT_READAHEAD(readahead)               \
{                                               \
    (readahead)->buf = NULL;                    \
    (readahead)->len = 0;                       \
    (readahead)->alloc_len = 0;                 \
}

#define FREE_READAHEAD(readahead)               \
{                                               \
    if ((readahead)->buf)                       \
        PyMem_FREE((readahead)->buf);           \
    INIT_READAHEAD(readahead);                  \
}

#define SOCKET_HEAD                             \
    PyObject_HEAD;                              \
    PRFileDesc *pr_socket;                      \
    int family;                                 \
    int makefile_refs;                          \
    int open_for_read;                          \
    NetworkAddress *py_netaddr;                 \
    ReadAhead readahead;


typedef struct {
    SOCKET_HEAD
} Socket;

#define PySocket_Check(op) PyObject_TypeCheck(op, &SocketType)

typedef struct {
    PyTypeObject *network_address_type;
    PyTypeObject *host_entry_type;
    PyTypeObject *socket_type;
    void         (*Socket_init_from_PRFileDesc)(Socket *py_socket, PRFileDesc *pr_socket, int family);
    PyObject     *(*NetworkAddress_new_from_PRNetAddr)(PRNetAddr *pr_netaddr);
} PyNSPR_IO_C_API_Type;

#ifdef NSS_IO_MODULE

static PyObject *
HostEntry_new_from_PRNetAddr(PRNetAddr *pr_netaddr);

#else  /* not NSS_IO_MODULE */

static PyNSPR_IO_C_API_Type nspr_io_c_api;

#define NetworkAddressType (*nspr_io_c_api.network_address_type)
#define HostEntryType (*nspr_io_c_api.host_entry_type)
#define SocketType (*nspr_io_c_api.socket_type)

#define Socket_init_from_PRFileDesc (*nspr_io_c_api.Socket_init_from_PRFileDesc)
#define NetworkAddress_new_from_PRNetAddr (*nspr_io_c_api.NetworkAddress_new_from_PRNetAddr)

static int
import_nspr_io_c_api(void)
{
    PyObject *module = NULL;
    PyObject *c_api_object = NULL;
    void *api = NULL;

    if ((module = PyImport_ImportModule("nss.io")) == NULL)
        return -1;

    if ((c_api_object = PyObject_GetAttrString(module, "_C_API")) == NULL) {
        Py_DECREF(module);
        return -1;
    }

    if (!(PyCObject_Check(c_api_object))) {
        Py_DECREF(c_api_object);
        Py_DECREF(module);
        return -1;
    }

    if ((api = PyCObject_AsVoidPtr(c_api_object)) == NULL) {
        Py_DECREF(c_api_object);
        Py_DECREF(module);
        return -1;
    }

    memcpy(&nspr_io_c_api, api, sizeof(nspr_io_c_api));
    Py_DECREF(c_api_object);
    Py_DECREF(module);
    return 0;
}

#endif /* NSS_IO_MODULE */
