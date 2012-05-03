/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#undef HAVE_LONG_LONG           /* FIXME: both Python.h and nspr.h define HAVE_LONG_LONG  */
#include "nss.h"
#include "ssl.h"

typedef struct {
    SOCKET_HEAD;
    PyObject *py_auth_certificate_callback;
    PyObject *py_auth_certificate_callback_data;
    PyObject *py_pk11_pin_args;
    PyObject *py_handshake_callback;
    PyObject *py_handshake_callback_data;
    PyObject *py_client_auth_data_callback;
    PyObject *py_client_auth_data_callback_data;
} SSLSocket;

#define PySSLSocket_Check(op) PyObject_TypeCheck(op, &SSLSocketType)

typedef struct {
    PyTypeObject *sslsocket_type;
} PyNSS_SSL_C_API_Type;

#ifdef NSS_SSL_MODULE

static PyTypeObject SSLSocketType;

#else /* not NSS_SSL_MODULE */

static PyNSS_SSL_C_API_Type nss_ssl_c_api;

#define SSLSocketType (*nss_ssl_c_api.sslsocket_type)

static int
import_nss_ssl_c_api(void)
{
    PyObject *module = NULL;
    PyObject *c_api_object = NULL;
    void *api = NULL;

    if ((module = PyImport_ImportModule("nss.ss;")) == NULL)
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

    memcpy(&nss_ssl_c_api, api, sizeof(nss_ssl_c_api));
    Py_DECREF(c_api_object);
    Py_DECREF(module);
    return 0;
}

#endif /* NSS_SSL_MODULE */

