/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef NSS_ERROR_MODULE_H
#define NSS_ERROR_MODULE_H

#define NSS_ERROR_MODULE_NAME "error"

#include <stdbool.h>

/* NSPR header files */
#undef HAVE_LONG_LONG           /* FIXME: both Python.h and nspr.h define HAVE_LONG_LONG  */
#include "nspr.h"
#include "prerror.h"

typedef struct {
    PRErrorCode	 num;
    const char *name;
    const char *string;
} NSPRErrorDesc;

typedef struct {
    PyObject     *nspr_exception;
    PyObject     *(*set_nspr_error)(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
    PyObject     *(*set_cert_verify_error)(unsigned int usages, PyObject * log, const char *format, ...)  __attribute__ ((format (printf, 3, 4)));
    PyObject     *(*tuple_str)(PyObject *tuple);
    const NSPRErrorDesc *(*lookup_nspr_error)(PRErrorCode num);
} PyNSPR_ERROR_C_API_Type;

#ifdef NSS_ERROR_MODULE

#else  /* not NSS_ERROR_MODULE */

static PyNSPR_ERROR_C_API_Type nspr_error_c_api;

#define set_nspr_error (*nspr_error_c_api.set_nspr_error)
#define set_cert_verify_error (*nspr_error_c_api.set_cert_verify_error)
#define tuple_str (*nspr_error_c_api.tuple_str)
#define lookup_nspr_error (*nspr_error_c_api.lookup_nspr_error)

static int
import_nspr_error_c_api(void)
{
    void *api = NULL;

    if ((api = PyCapsule_Import(PACKAGE_NAME "." NSS_ERROR_MODULE_NAME "._C_API", 0)) == NULL) {
        return -1;
    }

    memcpy(&nspr_error_c_api, api, sizeof(nspr_error_c_api));

    return 0;
}

#endif /* NSS_ERROR_MODULE */
#endif /* NSS_ERROR_MODULE_H */
