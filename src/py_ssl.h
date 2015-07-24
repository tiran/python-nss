/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef NSS_SSL_MODULE_H
#define NSS_SSL_MODULE_H

#define NSS_SSL_MODULE_NAME "ssl"

#undef HAVE_LONG_LONG           /* FIXME: both Python.h and nspr.h define HAVE_LONG_LONG  */
#include "nss.h"
#include "ssl.h"

/* ========================================================================== */
/* ============================== SSLSocket Class =========================== */
/* ========================================================================== */

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

/* ========================================================================== */
/* ====================== SSLCipherSuiteInformation Class =================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SSLCipherSuiteInfo info;
} SSLCipherSuiteInformation;

/* ========================================================================== */
/* ======================== SSLChannelInformation Class ===================== */
/* ========================================================================== */

typedef struct {
    PyObject_HEAD
    SSLChannelInfo info;
} SSLChannelInformation;

/* =========================== C API =========================== */

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
    void *api = NULL;

    if ((api = PyCapsule_Import(PACKAGE_NAME "." NSS_SSL_MODULE_NAME "._C_API", 0)) == NULL) {
        return -1;
    }

    memcpy(&nss_ssl_c_api, api, sizeof(nss_ssl_c_api));

    return 0;
}

#endif /* NSS_SSL_MODULE */
#endif /* NSS_SSL_MODULE_H */
