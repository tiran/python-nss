/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "structmember.h"

#define NSS_ERROR_MODULE
#include "py_nspr_error.h"
#include "py_nspr_common.h"

#include "nspr.h"
#include "seccomon.h"

#define ER2(a,b)   {a, #a, b},
#define ER3(a,b,c) {a, #a, c},

#include "secerr.h"
#include "sslerr.h"

typedef struct {
    PyBaseExceptionObject base;
    PyObject *error_desc;
    PyObject *error_message;
    PyObject *str_value;
    int error_code;
} NSPRError;

typedef struct {
    NSPRError base;
    PyObject *log;
    unsigned int usages;
} CertVerifyError;

static PyObject *empty_tuple = NULL;
static PyTypeObject NSPRErrorType;
static PyTypeObject CertVerifyErrorType;

NSPRErrorDesc nspr_errors[] = {
    {0, "SUCCESS", "Success"},
#include "SSLerrs.h"
#include "SECerrs.h"
#include "NSPRerrs.h"
};

static int
cmp_error(const void *p1, const void *p2)
{
    NSPRErrorDesc *e1 = (NSPRErrorDesc *) p1;
    NSPRErrorDesc *e2 = (NSPRErrorDesc *) p2;

    if (e1->num < e2->num) return -1;
    if (e1->num > e2->num) return  1;
    return 0;
}

const int nspr_error_count = sizeof(nspr_errors) / sizeof(NSPRErrorDesc);

static int
IntOrNoneConvert(PyObject *obj, int *param)
{
    if (PyInt_Check(obj)) {
        *param = PyInt_AsLong(obj);
        return 1;
    }

    if (PyNone_Check(obj)) {
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be int or None, not %.50s",
                 Py_TYPE(obj)->tp_name);
    return 0;
}

static PRStatus
init_nspr_errors(void) {
    int low  = 0;
    int high = nspr_error_count - 1;
    int i;
    PRErrorCode err_num;
    int result = SECSuccess;

    /* Make sure table is in ascending order. binary search depends on it. */

    qsort((void*)nspr_errors, nspr_error_count, sizeof(NSPRErrorDesc), cmp_error);

    PRErrorCode last_num = ((PRInt32)0x80000000);
    for (i = low; i <= high; ++i) {
        err_num = nspr_errors[i].num;
        if (err_num <= last_num) {
            result = SECFailure;
            fprintf(stderr,
"sequence error in error strings at item %d\n"
"error %d (%s)\n"
"should come after \n"
"error %d (%s)\n",
                    i, last_num, nspr_errors[i-1].string,
                    err_num, nspr_errors[i].string);
        }
        last_num = err_num;
    }
    return result;
}

static const NSPRErrorDesc *
lookup_nspr_error(PRErrorCode num) {
    int low  = 0;
    int high = nspr_error_count - 1;
    int i;
    PRErrorCode err_num;

    /* Do binary search of table. */
    while (low + 1 < high) {
    	i = (low + high) / 2;
	err_num = nspr_errors[i].num;
	if (num == err_num)
	    return &nspr_errors[i];
        if (num < err_num)
	    high = i;
	else
	    low = i;
    }
    if (num == nspr_errors[low].num)
    	return &nspr_errors[low];
    if (num == nspr_errors[high].num)
    	return &nspr_errors[high];
    return NULL;
}

static PyObject *
get_error_desc(PRErrorCode *p_error_code)
{
    PRErrorCode error_code = 0;
    NSPRErrorDesc const *error_desc = NULL;
    char *pr_err_msg = NULL;
    PRInt32 pr_err_msg_len;
    char *final_err_msg = NULL;
    PyObject *result = NULL;

    if (!p_error_code || *p_error_code == -1) {
        error_code = PR_GetError();
        if (p_error_code) {
            *p_error_code = error_code;
        }
        if ((pr_err_msg_len = PR_GetErrorTextLength())) {
            if ((pr_err_msg = PyMem_Malloc(pr_err_msg_len + 1))) {
                PR_GetErrorText(pr_err_msg);
            }
        }
    } else {
        error_code = *p_error_code;
    }

    error_desc = lookup_nspr_error(error_code);

    if (pr_err_msg && error_desc) {
        final_err_msg = PR_smprintf("%s (%s) %s", pr_err_msg, error_desc->name, error_desc->string);
    } else if (error_desc) {
        final_err_msg = PR_smprintf("(%s) %s", error_desc->name, error_desc->string);
    } else if (pr_err_msg) {
        final_err_msg = PR_smprintf("%s", pr_err_msg);
    } else {
        final_err_msg = PR_smprintf("error (%d) unknown", error_code);
    }

    result = PyString_FromString(final_err_msg);

    if (final_err_msg) PR_smprintf_free(final_err_msg);
    if (pr_err_msg) PyMem_Free(pr_err_msg);

    return result;
}

static PyObject *
set_nspr_error(const char *format, ...)
{
    va_list vargs;
    PyObject *error_message = NULL;
    PyObject *kwds = NULL;
    PyObject *exception_obj = NULL;

    if (format) {
#ifdef HAVE_STDARG_PROTOTYPES
        va_start(vargs, format);
#else
        va_start(vargs);
#endif
        error_message = PyString_FromFormatV(format, vargs);
        va_end(vargs);
    }

    if ((kwds = PyDict_New()) == NULL) {
        return NULL;
    }

    if (error_message) {
        if (PyDict_SetItemString(kwds, "error_message", error_message) != 0) {
            return NULL;
        }
    }
    
    exception_obj = PyObject_Call((PyObject *)&NSPRErrorType, empty_tuple, kwds);
    Py_DECREF(kwds);

    PyErr_SetObject((PyObject *)&NSPRErrorType, exception_obj);

    return NULL;
}

static PyObject *
set_cert_verify_error(unsigned int usages, PyObject *log, const char *format, ...)
{
    va_list vargs;
    PyObject *error_message = NULL;
    PyObject *kwds = NULL;
    PyObject *exception_obj = NULL;

    if (format) {
#ifdef HAVE_STDARG_PROTOTYPES
        va_start(vargs, format);
#else
        va_start(vargs);
#endif
        error_message = PyString_FromFormatV(format, vargs);
        va_end(vargs);
    }

    if ((kwds = PyDict_New()) == NULL) {
        return NULL;
    }

    if (error_message) {
        if (PyDict_SetItemString(kwds, "error_message", error_message) != 0) {
            return NULL;
        }
    }
    
    if (PyDict_SetItemString(kwds, "usages", PyInt_FromLong(usages)) != 0) {
        return NULL;
    }

    if (log) {
        if (PyDict_SetItemString(kwds, "log", log) != 0) {
            return NULL;
        }
    }
    
    exception_obj = PyObject_Call((PyObject *)&CertVerifyErrorType, empty_tuple, kwds);
    Py_DECREF(kwds);

    PyErr_SetObject((PyObject *)&CertVerifyErrorType, exception_obj);

    return NULL;
}


PyDoc_STRVAR(io_get_nspr_error_string_doc,
"get_nspr_error_string(number) -> string\n\
\n\
Given an NSPR error number, returns it's string description\n\
");

static PyObject *
io_get_nspr_error_string(PyObject *self, PyObject *args)
{
    int err_num;
    NSPRErrorDesc const *error_desc = NULL;

    if (!PyArg_ParseTuple(args, "i:get_nspr_error_string", &err_num)) {
        return NULL;
    }

    if ((error_desc = lookup_nspr_error(err_num)) == NULL)
        Py_RETURN_NONE;

    return PyString_FromString(error_desc->string);
}

/* List of functions exported by this module. */
static PyMethodDef
module_methods[] = {
    {"get_nspr_error_string", io_get_nspr_error_string, METH_VARARGS, io_get_nspr_error_string_doc},
    {NULL, NULL}            /* Sentinel */
};

static PyObject *
init_py_nspr_errors(PyObject *module)
{
    NSPRErrorDesc *error_desc = NULL;
    PyObject *py_error_doc = NULL;
    PyObject *error_str = NULL;
    int i;

    /* Load and intialize NSPR error descriptions */
    if (init_nspr_errors() != PR_SUCCESS)
        return NULL;

    /* Create a python string to hold the modules error documentation */
    if ((py_error_doc = PyString_FromString("NSPR Error Constants:\n\n")) == NULL)
        return NULL;

    /*
     * Iterate over all the NSPR errors, for each:
     * add it's doc string to the module doc
     * add it's numeric value as as a module constant
     */
    for (i = 0, error_desc = &nspr_errors[0]; i < nspr_error_count; i++, error_desc++) {

        if ((error_str = PyString_FromFormat("%s: %s\n\n", error_desc->name, error_desc->string)) == NULL) {
            Py_DECREF(py_error_doc);
            return NULL;
        }
        PyString_ConcatAndDel(&py_error_doc, error_str);

        if (PyModule_AddIntConstant(module, error_desc->name, error_desc->num) < 0) {
            Py_DECREF(py_error_doc);
            return NULL;
        }
    }
    return py_error_doc;
}

/* ================= Utilities shared with other modules  ================= */


/*
 * Format a tuple into a string by calling the str() method on
 * each member of the tuple.
 * 
 * Tuples do not implement a str method only a repr with the 
 * unfortunate result repr() is invoked on each of its members.
 */
static PyObject *tuple_str(PyObject *tuple)
{
    PyObject *separator = NULL;
    PyObject *obj = NULL;
    PyObject *tmp_obj = NULL;
    PyObject *text = NULL;
    Py_ssize_t i, len;
        
    if (!PyTuple_Check(tuple)) return NULL;

    len = PyTuple_GET_SIZE(tuple);
    
    if (len == 0) {
        return PyString_FromString("()");
    }

    if ((text = PyString_FromString("(")) == NULL) {
        goto exit;
    }

    if (len > 1) {
        if ((separator = PyString_FromString(", ")) == NULL) {
            goto exit;
        }
    }

    for (i = 0; i < len; i++) {
        obj = PyTuple_GET_ITEM(tuple, i);
        tmp_obj = PyObject_Str(obj);
        PyString_ConcatAndDel(&text, tmp_obj);
        if (text == NULL) {
            goto exit;
        }
        if (i < len-1) {
            PyString_Concat(&text, separator);
            if (text == NULL) {
                goto exit;
            }
        }
    }

    if ((tmp_obj = PyString_FromString(")")) == NULL) {
        Py_CLEAR(text);
        goto exit;
    }

    PyString_ConcatAndDel(&text, tmp_obj);
    if (text == NULL) {
        goto exit;
    }

 exit:
    Py_XDECREF(separator);
    return text;
}

/* ========================================================================== */
/* ========================= NSPRError Class ========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */


static PyMemberDef NSPRError_members[] = {
    {"errno", T_INT, offsetof(NSPRError, error_code), READONLY,
     PyDoc_STR("NSS error code")},
    {"error_code", T_INT, offsetof(NSPRError, error_code), READONLY,
     PyDoc_STR("NSS error code")},

    {"strerror", T_OBJECT, offsetof(NSPRError, error_desc), READONLY,
     PyDoc_STR("NSS error code description")},
    {"error_desc", T_OBJECT, offsetof(NSPRError, error_desc), READONLY,
     PyDoc_STR("NSS error code description")},

    {"error_message", T_OBJECT, offsetof(NSPRError, error_message), READONLY,
     PyDoc_STR("error message specific to this error")},
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
NSPRError_str(NSPRError *self)
{
    TraceMethodEnter(self);

    Py_XINCREF(self->str_value);
    return self->str_value;

}

/* =========================== Class Construction =========================== */

static int
NSPRError_traverse(NSPRError *self, visitproc visit, void *arg)
{
    Py_VISIT(self->error_desc);
    Py_VISIT(self->error_message);
    Py_VISIT(self->str_value);
    CALL_BASE(&NSPRErrorType, traverse, (PyObject *)self, visit, arg);

    return 0;
}

static int
NSPRError_clear(NSPRError* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->error_desc);
    Py_CLEAR(self->error_message);
    Py_CLEAR(self->str_value);
    CALL_BASE(&NSPRErrorType, clear, (PyObject *)self);

    return 0;
}

static void
NSPRError_dealloc(NSPRError* self)
{
    TraceMethodEnter(self);

    NSPRError_clear(self);

    Py_TYPE(self)->tp_free((PyObject *)self);
}

PyDoc_STRVAR(NSPRError_doc,
"NSPRError(error_message=None, error_code=None)\n\
\n\
:Parameters:\n\
    error_message : string\n\
        Detail message specific to this error.\n\
    error_code : int\n\
        NSS or NSPR error value, if None get current error\n\
\n\
Exception object (derived from StandardException), raised when an\n\
NSS or NSPR error occurs. The error model in python-nss is anytime\n\
a NSS or NSPR C function returns an error the python-nss binding\n\n\
raises a NSPRError exception.\n\
\n\
Raised internally, there should be no need to raise this exception\n\
from with a Python program using python-nss.\n\
\n\
The error_message is an optional string detailing the specifics\n\
of an error.\n\
\n\
If the error_code is not passed then the current error is queried.\n\
\n\
A NSPRError contains the following attributes:\n\
\n\
    error_code\n\
        The numeric NSPR or NSS error code (integer).\n\
        If not passed the current NSPR or NSS error for the\n\
        current thread is queried and substituted.\n\
    error_desc\n\
        Error description associated with error code (string).\n\
    error_message\n\
        Optional message with details specific to the error (string).\n\
    errno\n\
        Alias for errno.\n\
    strerr\n\
        Alias for error_desc.\n\
\n\
");

static int
NSPRError_init(NSPRError *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"error_message", "error_code", NULL};
    const char *error_message = NULL;
    int error_code = -1;
    PyObject *error_desc = NULL;
    PyObject *str_value = NULL;

    TraceMethodEnter(self);

    CALL_BASE(&NSPRErrorType, init, (PyObject *)self, args, NULL);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zO&:NSPRError", kwlist,
                                     &error_message,
                                     IntOrNoneConvert, &error_code))
        return -1;

    error_desc = get_error_desc(&error_code);

    if (error_message) {
        str_value = PyString_FromFormat("%s: %s",
                                        error_message,
                                        error_desc ? PyString_AsString(error_desc) :
                                        _("Error description unavailable"));
    } else {
        str_value = error_desc;
    }


    Py_CLEAR(self->base.message);
    self->base.message = str_value;
    Py_XINCREF(self->base.message);

    Py_CLEAR(self->str_value);
    self->str_value = str_value;
    Py_XINCREF(self->str_value);

    Py_CLEAR(self->error_desc);
    self->error_desc = error_desc;
    Py_XINCREF(self->error_desc);

    self->error_code = error_code;

    return 0;
}

static PyTypeObject NSPRErrorType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.error.NSPRError",			/* tp_name */
    sizeof(NSPRError),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)NSPRError_dealloc,		/* tp_dealloc */
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
    (reprfunc)NSPRError_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC, /* tp_flags */
    NSPRError_doc,				/* tp_doc */
    (traverseproc)NSPRError_traverse,		/* tp_traverse */
    (inquiry)NSPRError_clear,			/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    0,						/* tp_methods */
    NSPRError_members,				/* tp_members */
    0,						/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)NSPRError_init,			/* tp_init */
    0,						/* tp_alloc */
    0,						/* tp_new */
};

/* ========================================================================== */
/* ========================= CertVerifyError Class ========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */


static PyMemberDef CertVerifyError_members[] = {
    {"usages", T_UINT, offsetof(CertVerifyError, usages), READONLY,
     PyDoc_STR("usages returned by NSS")},
    {"log", T_OBJECT, offsetof(CertVerifyError, log), READONLY,
     PyDoc_STR("verifcation log, see `CertVerifyLog`")},
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
CertVerifyError_str(CertVerifyError *self)
{
    PyObject *super_str = NULL;
    PyObject *str = NULL;

    TraceMethodEnter(self);

    if ((super_str = CALL_BASE(&CertVerifyErrorType, str, (PyObject *)self)) == NULL) {
        return NULL;
    }

    str = PyString_FromFormat("%s usages=%#x", PyString_AsString(super_str), self->usages);
    Py_DECREF(super_str);
    return str;
}

/* =========================== Class Construction =========================== */

static int
CertVerifyError_traverse(CertVerifyError *self, visitproc visit, void *arg)
{
    Py_VISIT(self->log);
    CALL_BASE(&CertVerifyErrorType, traverse, (PyObject *)self, visit, arg);

    return 0;
}

static int
CertVerifyError_clear(CertVerifyError* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->log);
    CALL_BASE(&CertVerifyErrorType, clear, (PyObject *)self);

    return 0;
}

static void
CertVerifyError_dealloc(CertVerifyError* self)
{
    TraceMethodEnter(self);

    CertVerifyError_clear(self);

    Py_TYPE(self)->tp_free((PyObject *)self);
}

PyDoc_STRVAR(CertVerifyError_doc,
"CertVerifyError(error_message=None, error_code=None, usages=None, log=None)\n\
\n\
:Parameters:\n\
    error_message : string\n\
        Detail message specific to this error.\n\
    error_code : int\n\
        NSS or NSPR error value, if None get current error\n\
    usages : int\n\
        The returned usages bitmaks from the verify function.\n\
    log : `CertVerifyLog` object\n\
        The verification log generated during the verification\n\
        operation.\n\
\n\
Exception object (derived from NSPRError), raised when an\n\
error occurs during certificate verification.\n\
\n\
Raised internally, there should be no need to raise this exception\n\
from with a Python program using python-nss.\n\
\n\
Certificate verification presents a problem for the normal error\n\
handling model whereby any error returned from an underlying C\n\
function causes a `NSPRError` exception to be raised. When an\n\
exception is raised the return values are lost. It is unusual for a\n\
function to have useful return values when the function also returns\n\
an error.\n\
\n\
The certificate verification functions are one such example. If\n\
verification fails useful information concerning validated usages and\n\
the verification log need to be available. But to be consistent with\n\
model of always raising an exception on an error return some other\n\
mechanism is needed to return the extra information. The solution is\n\
to embed the information which normally would have been in the return\n\
values in the exception object where it can be queried. The\n\
CertVerifyError contails the returned usages bitmask and optionally\n\
the `CertVerifyLog` verification log object if requested.\n\
\n\
In addtion to the attributes in a `NSPRError` a CertVerifyError contains\n\
the following attributes:\n\
\n\
    usages\n\
        The retured usages bitmask (unsigned int) from the Certificate\n\
        verification function.\n\
    log\n\
        The (optional) `CertVerifyLog` object which contains the\n\
        diagnostic information for why a certificate failed to validate.\n\
\n\
");

static int
CertVerifyError_init(CertVerifyError *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"error_message", "error_code", "usages", "log", NULL};
    const char *error_message = NULL;
    int error_code = -1;
    unsigned int usages = 0;
    PyObject *log = NULL;
    PyObject *super_kwds = NULL;
    int result = 0;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zO&IO:CertVerifyError", kwlist,
                                     &error_message,
                                     IntOrNoneConvert, &error_code,
                                     &usages,
                                     &log))
        return -1;

    if ((super_kwds = PyDict_New()) == NULL) {
        return -1;
    }
    if (error_message) {
        if (PyDict_SetItemString(super_kwds, "error_message", PyString_FromString(error_message)) != 0) {
            Py_DECREF(super_kwds);
            return -1;
        }
    }
    if (error_code != -1) {
        if (PyDict_SetItemString(super_kwds, "error_code", PyInt_FromLong(error_code)) != 0) {
            Py_DECREF(super_kwds);
            return -1;
        }
    }
    if ((result = CertVerifyErrorType.tp_base->tp_init((PyObject *)self, empty_tuple, super_kwds)) != 0) {
        Py_DECREF(super_kwds);
        return result;
    }
    

    self->usages = usages;

    Py_CLEAR(self->log);
    self->log = log;
    Py_XINCREF(self->log);

    return 0;
}

static PyTypeObject CertVerifyErrorType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.error.CertVerifyError",		/* tp_name */
    sizeof(CertVerifyError),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CertVerifyError_dealloc,	/* tp_dealloc */
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
    (reprfunc)CertVerifyError_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    CertVerifyError_doc,			/* tp_doc */
    (traverseproc)CertVerifyError_traverse,	/* tp_traverse */
    (inquiry)CertVerifyError_clear,		/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    0,						/* tp_methods */
    CertVerifyError_members,			/* tp_members */
    0,						/* tp_getset */
    &NSPRErrorType,				/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)CertVerifyError_init,		/* tp_init */
    0,						/* tp_alloc */
    0,						/* tp_new */
};


/* ============================== Module Exports ============================= */

static PyNSPR_ERROR_C_API_Type nspr_error_c_api =
{
    NULL,                       /* nspr_exception */
    set_nspr_error,
    set_cert_verify_error,
    tuple_str,
    lookup_nspr_error,
};

/* ============================== Module Construction ============================= */

PyDoc_STRVAR(module_doc,
"This module defines the NSPR errors and provides functions to\n\
manipulate them.\n\
");

PyMODINIT_FUNC
initerror(void)
{
    PyObject *m;
    PyObject *py_error_doc = NULL;
    PyObject *py_module_doc = NULL;

    if ((m = Py_InitModule3("error", module_methods, module_doc)) == NULL)
        return;

    if ((empty_tuple = PyTuple_New(0)) == NULL) {
        return;
    }
    Py_INCREF(empty_tuple);

    if ((py_error_doc = init_py_nspr_errors(m)) == NULL)
        return;

    if ((py_module_doc = PyString_FromString(module_doc)) == NULL)
        return;

    PyString_ConcatAndDel(&py_module_doc, py_error_doc);
    PyModule_AddObject(m, "__doc__", py_module_doc);

    NSPRErrorType.tp_base = (PyTypeObject *)PyExc_StandardError;

    TYPE_READY(NSPRErrorType);
    TYPE_READY(CertVerifyErrorType);

    /* Export C API */
    nspr_error_c_api.nspr_exception = (PyObject *)&NSPRErrorType;
    if (PyModule_AddObject(m, "_C_API", PyCObject_FromVoidPtr((void *)&nspr_error_c_api, NULL)) != 0)
        return;

}
