/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * FIXME - below are general things which need fixing
 *
 * repr() vs. str() class methods. repr should just use the default of
 * printing out the object class name and object pointer, not the contents
 * of the object, that's the role of str().
 *
 * When receiving string parameters via PyArg_ParseTuple*() we should
 * allow both str and unicode objects and encode unicode to UTF-8
 * this would be done by changing the 's' format specifier to 'es'
 * and adding a 'utf-8' parameter prior to the string address parameter.
 * Unlike the 's' format specifier the char pointer will need to be
 * freed because it's copy of the encoded string.
 *
 * We should consider setting the default encoding to UTF-8 when our
 * module loads. This is global and would affect all other modules loaded
 * into the Python application. At the moment the default is 'ascii' which
 * breaks anything which is expecting a sane default.
 */

#if 0

//Template for new classes

/* ========================================================================== */
/* ============================= NewType Class ============================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
NewType_get_classproperty(NewType *self, void *closure)
{
    TraceMethodEnter(self);

    return NULL;
}

static int
NewType_set_classproperty(NewType *self, PyObject *value, void *closure)
{
    TraceMethodEnter(self);

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the classproperty attribute");
        return -1;
    }

    if (!PyString_Check(value)) {
        PyErr_Format(PyExc_TypeError, "classproperty must be a string, not %.200s",
                     Py_TYPE(value)->tp_name);
        return -1;
    }

    return 0;
}

static
PyGetSetDef NewType_getseters[] = {
    {"classproperty", (getter)NewType_get_classproperty,    (setter)NewType_set_classproperty,
     "xxx", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef NewType_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
NewType_format_lines(NewType *self, PyObject *args, PyObject *kwds)
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

    return lines;
 fail:
    Py_XDECREF(obj1);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
NewType_format(NewType *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)NewType_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
NewType_str(NewType *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  NewType_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

PyDoc_STRVAR(NewType_func_name_doc,
"func_name() -> \n\
\n\
:Parameters:\n\
    arg1 : object\n\
        xxx\n\
\n\
xxx\n\
");

static PyObject *
NewType_func_name(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"arg1", NULL};
    PyObject *arg;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:func_name", kwlist,
                                     &arg))
        return NULL;

    return NULL;
}

static PyMethodDef NewType_methods[] = {
    {"format_lines", (PyCFunction)NewType_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)NewType_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {"func_name",    (PyCFunction)NewType_func_name, METH_VARARGS|METH_KEYWORDS, NewType_func_name_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Sequence Protocol ============================ */
static Py_ssize_t
NSSType_list_count(NSSType *head)
{
    NSSType *cur;
    Py_ssize_t count;

    count = 0;
    if (!head) {
        return count;
    }

    cur = head;
    do {
        count++;
        cur = NSSType_Next(cur);
    } while (cur != head);

    return count;
}

static Py_ssize_t
NewType_length(NewType *self)
{
    if (!self->name) {
        PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
        return -1;
    }

    return NSSType_list_count(self->name);
}

static PyObject *
NewType_item(NewType *self, register Py_ssize_t i)
{
    NSSType *head, *cur;
    Py_ssize_t index;

    if (!self->name) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }

    index = 0;
    cur = head = self->name;
    do {
        cur = NSSType_Next(cur);
        if (i == index) {
            return NewType_new_from_NSSType(cur);
        }
        index++;
    } while (cur != head);

    PyErr_SetString(PyExc_IndexError, "NewType index out of range");
    return NULL;
}


/* =========================== Class Construction =========================== */

static PyObject *
NewType_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    NewType *self;

    TraceObjNewEnter(type);

    if ((self = (NewType *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

Py_TPFLAGS_HAVE_GC
static int
NewType_traverse(NewType *self, visitproc visit, void *arg)
{
    Py_VISIT(self->obj);
    return 0;
}

static int
NewType_clear(NewType* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->obj);
    return 0;
}

static void
NewType_dealloc(NewType* self)
{
    TraceMethodEnter(self);

    NewType_clear(self);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(NewType_doc,
"NewType(obj)\n\
\n\
:Parameters:\n\
    obj : xxx\n\
\n\
An object representing NewType.\n\
");

static int
NewType_init(NewType *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"arg", NULL};
    PyObject *arg;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:NewType", kwlist,
                                     &arg))
        return -1;

    return 0;
}

static PySequenceMethods NewType_as_sequence = {
    (lenfunc)NewType_length,		/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)NewType_item,		/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyTypeObject NewTypeType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.NewType",				/* tp_name */
    sizeof(NewType),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)NewType_dealloc,		/* tp_dealloc */
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
    (reprfunc)NewType_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    NewType_doc,				/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    NewType_methods,				/* tp_methods */
    NewType_members,				/* tp_members */
    NewType_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)NewType_init,			/* tp_init */
    0,						/* tp_alloc */
    NewType_new,				/* tp_new */
};

static PyObject *
NewType_new_from_NSSType(NSSType *id)
{
    NewType *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (NewType *) NewTypeType.tp_new(&NewTypeType, NULL, NULL)) == NULL) {
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

#endif

// FIXME: should we be calling these?
// SECKEY_DestroyEncryptedPrivateKeyInfo
// SECKEY_DestroyPrivateKey	   SECKEY_DestroyPrivateKeyInfo
// SECKEY_DestroyPrivateKeyList	   SECKEY_DestroyPublicKey
// SECKEY_DestroyPublicKeyList	   SECKEY_DestroySubjectPublicKeyInfo

#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "py_2_3_compat.h"
#include "structmember.h"
#include "datetime.h"

#include "py_nspr_common.h"
#define NSS_NSS_MODULE
#include "py_nss.h"
#include "py_shared_doc.h"
#include "py_nspr_error.h"

#include "secder.h"
#include "sechash.h"
#include "certdb.h"
#include "hasht.h"
#include "nssb64.h"
#include "secport.h"
#include "secerr.h"
#include "secpkcs5.h"
#include "p12plcy.h"
#include "ciferfam.h"
#include "ocsp.h"

#if (NSS_VMAJOR > 3) || (NSS_VMAJOR == 3 && NSS_VMINOR >= 13)
#define HAVE_RSA_PSS
#endif

#define MAX_AVAS 10
#define MAX_RDNS 10

#ifdef DEBUG
#include "py_traceback.h"

static void
print_cert(CERTCertificate *cert, const char *format, ...) __attribute__ ((format (printf, 2, 3)));

static void
print_cert(CERTCertificate *cert, const char *format, ...)
{
    va_list va;
    char *subject;

    if (cert == NULL) {
        printf("Certificate was null\n");
        return;
    }

    subject = CERT_NameToAscii(&cert->subject);

    if (format) {
        va_start(va, format);
        vprintf(format, va);
        va_end(va);
        printf(" subject %s\n", subject);
    } else {
        printf("Certificate subject: %s\n", subject);
    }

    PORT_Free(subject);
    nss_DumpCertificateCacheInfo();
    print_traceback();
}
#endif

/* FIXME: convert all equality tests to Py_None to PyNone_Check() */

//FIXME, should be in py_nss.h
#define PyAVA_Check(op)  PyObject_TypeCheck(op, &AVAType)
#define PyRDN_Check(op)  PyObject_TypeCheck(op, &RDNType)
#define PyDN_Check(op) PyObject_TypeCheck(op, &DNType)

#define PyRSAGenParams_Check(op) PyObject_TypeCheck(op, &RSAGenParamsType)
#define PyKEYPQGParams_Check(op) PyObject_TypeCheck(op, &KEYPQGParamsType)
#define PyCertVerifyLog_Check(op) PyObject_TypeCheck(op, &CertVerifyLogType)


#define BIT_FLAGS_TO_LIST_PROLOGUE()                                    \
    PyObject *py_flags = NULL;                                          \
    PyObject *py_flag = NULL;                                           \
                                                                        \
    switch(repr_kind) {                                                 \
    case AsEnum:                                                        \
    case AsEnumName:                                                    \
    case AsEnumDescription:                                             \
        break;                                                          \
    default:                                                            \
        PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind); \
        return NULL;                                                    \
    }                                                                   \
                                                                        \
    if ((py_flags = PyList_New(0)) == NULL)                             \
        return NULL;



#define BIT_FLAGS_TO_LIST(enum, description)                            \
{                                                                       \
    if (flags & enum) {                                                 \
        flags &= ~enum;                                                 \
        switch(repr_kind) {                                             \
        case AsEnum:                                                    \
            py_flag = PyInt_FromLong(enum);                             \
            break;                                                      \
        case AsEnumName:                                                \
            py_flag = PyString_FromString(#enum);                       \
            break;                                                      \
        case AsEnumDescription:                                         \
            py_flag = PyString_FromString(description);                 \
            break;                                                      \
        default:                                                        \
            PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind); \
            Py_DECREF(py_flags);                                        \
            return NULL;                                                \
        }                                                               \
	if (py_flag == NULL) {                                          \
            Py_DECREF(py_flags);                                        \
            return NULL;                                                \
        }                                                               \
        PyList_Append(py_flags, py_flag);                               \
	Py_DECREF(py_flag);                                             \
    }                                                                   \
}

#define BIT_FLAGS_TO_LIST_EPILOGUE()                                    \
{                                                                       \
    if (flags) {                                                        \
        if ((py_flag = PyString_FromFormat("unknown bit flags %#x", flags)) == NULL) { \
            Py_DECREF(py_flags);                                        \
            return NULL;                                                \
        }                                                               \
        PyList_Append(py_flags, py_flag);                               \
	Py_DECREF(py_flag);                                             \
    }                                                                   \
                                                                        \
    if (PyList_Sort(py_flags) == -1) {                                  \
            Py_DECREF(py_flags);                                        \
            return NULL;                                                \
    }                                                                   \
                                                                        \
    return py_flags;                                                    \
}

// FIXME, should use this in more places.
PyObject *
PyString_UTF8(PyObject *obj, char *name);


// FIXME, should this be SecItem_param() instead?
#define SECITEM_PARAM(py_param, pitem, tmp_item, none_ok, param_name)   \
{                                                                       \
    pitem = NULL;                                                       \
    if (py_param) {                                                     \
        if (PySecItem_Check(py_param)) {                                \
            pitem = &((SecItem *)py_param)->item;                       \
        } else if (none_ok && PyNone_Check(py_param)) {                 \
            pitem = NULL;                                               \
        } else if (PyObject_CheckReadBuffer(py_param)) {                \
            unsigned char *data = NULL;                                 \
            Py_ssize_t data_len;                                        \
                                                                        \
            if (PyObject_AsReadBuffer(py_param, (void *)&data, &data_len)) \
                return -1;                                              \
                                                                        \
            tmp_item.data = data;                                       \
            tmp_item.len = data_len;                                    \
            pitem = &tmp_item;                                          \
        } else {                                                        \
            if (none_ok) {                                              \
                PyErr_SetString(PyExc_TypeError, param_name " must be SecItem, buffer compatible or None"); \
                return -1;                                              \
            } else {                                                    \
                PyErr_SetString(PyExc_TypeError, param_name " must be SecItem or buffer compatible"); \
                return -1;                                              \
            }                                                           \
        }                                                               \
    }                                                                   \
}

/* ========================================================================== */
/* ========================= Formatting Utilities =========================== */
/* ========================================================================== */


static PyObject *
line_fmt_tuple(int level, const char *label, PyObject *py_value);

static PyObject *
make_line_fmt_tuples(int level, PyObject *src);

static PyObject *
py_make_line_fmt_tuples(PyObject *self, PyObject *args, PyObject *kwds);

static PyObject *
fmt_label(int level, char *label);

static PyObject *
format_from_lines(format_lines_func formatter, PyObject *self, PyObject *args, PyObject *kwds);

static PyObject *
py_indented_format(PyObject *self, PyObject *args, PyObject *kwds);

/* Steals reference to obj_str */
static PyObject *
line_fmt_tuple(int level, const char *label, PyObject *py_value)
{
    Py_ssize_t tuple_size, i;
    PyObject *fmt_tuple = NULL;
    PyObject *py_label = NULL;
    PyObject *py_value_str = NULL;

    tuple_size = 1;             /* always have level */

    if (label) {
        tuple_size++;
        if ((py_label = PyString_FromFormat("%s:", label)) == NULL) {
            return NULL;
        }
    }

    if (py_value) {
        tuple_size++;
        if (PyString_Check(py_value) || PyUnicode_Check(py_value)) {
            py_value_str = py_value;
            Py_INCREF(py_value_str);
        } else {
            if ((py_value_str = PyObject_Str(py_value)) == NULL) {
                return NULL;
            }
        }
    }

    if ((fmt_tuple = PyTuple_New(tuple_size)) == NULL) {
        return NULL;
    }

    i = 0;
    PyTuple_SetItem(fmt_tuple, i++, PyInt_FromLong(level));

    if (py_label) {
        PyTuple_SetItem(fmt_tuple, i++, py_label);
    }

    if (py_value_str) {
        PyTuple_SetItem(fmt_tuple, i++, py_value_str);
    }

    return fmt_tuple;
}

static PyObject *
make_line_fmt_tuples(int level, PyObject *src)
{
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *fmt_tuple = NULL;
    PyObject *seq = NULL;
    Py_ssize_t n_objs, i;

    if (PyList_Check(src) || PyTuple_Check(src)) {
        seq = src;
        n_objs = PySequence_Size(seq);
        Py_INCREF(seq);
    } else {
        obj = src;
        Py_INCREF(obj);
        n_objs = 1;
    }

    if ((lines = PyList_New(n_objs)) == NULL) {
        goto exit;
    }

    if (seq) {
        for (i = 0; i < n_objs; i++) {
            if ((obj = PySequence_GetItem(seq, i)) == NULL) { /* new reference */
                Py_DECREF(lines);
                goto exit;
            }
            if ((fmt_tuple = line_fmt_tuple(level, NULL, obj)) == NULL) {
                Py_DECREF(lines);
                goto exit;
            }
            PyList_SetItem(lines, i, fmt_tuple);
            Py_CLEAR(obj);
        }
    } else {
        if ((fmt_tuple = line_fmt_tuple(level, NULL, obj)) == NULL) {
            Py_DECREF(lines);
            goto exit;
        }
        PyList_SetItem(lines, 0, fmt_tuple);
    }

 exit:
    Py_XDECREF(obj);
    Py_XDECREF(seq);
    return lines;
}

PyDoc_STRVAR(py_make_line_fmt_tuples_doc,
"make_line_fmt_tuples(level, obj) -> [(level, str), ...]\n\
\n\
:Parameters:\n\
    obj : object\n\
        If obj is a tuple or list then each member will be wrapped\n\
        in a 2-tuple of (level, str). If obj is a scalar object\n\
        then obj will be wrapped in a 2-tuple of (level, obj)\n\
    level : integer\n\
        Initial indentation level, all subsequent indents are relative\n\
        to this starting level.\n\
\n\
Return a list of line formatted tuples sutible to passing to\n\
`indented_format()`. Each tuple consists of a integer\n\
level value and a string object. This is equivalent to:\n\
[(level, str(x)) for x in obj].\n\
As a special case convenience if obj is a scalar object (i.e.\n\
not a list or tuple) then [(level, str(obj))] will be returned.\n\
");

static PyObject *
py_make_line_fmt_tuples(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", "obj", NULL};
    int level = 0;
    PyObject *obj;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "iO:make_line_fmt_tuples", kwlist,
                                     &level, &obj))
        return NULL;

    return make_line_fmt_tuples(level, obj);
}

static PyObject *
fmt_label(int level, char *label)
{
    return line_fmt_tuple(level, label, NULL);
}

static PyObject *
format_from_lines(format_lines_func formatter, PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", "indent_len",  NULL};
    int level = 0;
    int indent_len = 4;
    PyObject *py_lines = NULL;
    PyObject *py_formatted_result = NULL;
    PyObject *tmp_args = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ii:format", kwlist, &level, &indent_len))
        return NULL;

    if ((tmp_args = Py_BuildValue("(i)", level)) == NULL) {
        goto fail;
    }
    if ((py_lines = formatter(self, tmp_args, NULL)) == NULL) {
        goto fail;
    }
    Py_CLEAR(tmp_args);

    if ((tmp_args = Py_BuildValue("Oi", py_lines, indent_len)) == NULL) {
        goto fail;
    }
    if ((py_formatted_result = py_indented_format(NULL, tmp_args, NULL)) == NULL) {
        goto fail;
    }

    Py_DECREF(tmp_args);
    Py_DECREF(py_lines);
    return py_formatted_result;

 fail:
    Py_XDECREF(tmp_args);
    Py_XDECREF(py_lines);
    return NULL;
}

PyDoc_STRVAR(py_indented_format_doc,
"indented_format(line_fmt_tuples, indent_len=4) -> string\n\
\n\
The function supports the display of complex objects which may be\n\
composed of other complex objects. There is often a need to output\n\
section headers or single strings and lists of <attribute,value> pairs\n\
(the attribute in this discussion is called a label), or even blank\n\
lines. All of these items should line up in columns at different\n\
indentation levels in order to visually see the structure.\n\
\n\
It would not be flexible enough to have object formatting routines\n\
which simply returned a single string with all the indentation and\n\
formatting pre-applied. The indentation width may not be what is\n\
desired. Or more importantly you might not be outputting to text\n\
display. It might be a GUI which desires to display the\n\
information. Most GUI's want to handle each string seperately and\n\
control indentation and the visibility of each item (e.g. a tree\n\
control).\n\
\n\
At the same time we want to satisfy the need for easy and simple text\n\
output. This routine will do that, e.g.:\n\
\n\
    print indented_format(obj.format_lines())\n\
\n\
To accomodate necessary flexibility the object formatting methods\n\
(format_lines()) return a list of tuples. Each tuple represents a\n\
single line with the first tuple item being the indentation level for\n\
the line. There may be 0,1 or 2 additional strings in the tuple which\n\
are to be output on the line. A single string are usually one of two\n\
things, either a section header or data that has been continuted onto\n\
multiple lines. Two strings usually represent a <attribute,value> pair\n\
with the first string being a label (e.g. attribute name).\n\
\n\
Each tuple may be:\n\
\n\
    (int,)\n\
        1-value tuple, no strings, e.g. blank line.\n\
\n\
    (int, string)\n\
        2-value tuple, output string at indent level.\n\
\n\
    (int, string, string)\n\
        3-value tuple, first string is a label, second string is a\n\
        value.  Starting at the indent level output the label, then\n\
        follow with the value. By keeping the label separate from the\n\
        value the ouput formatter may elect to align the values in\n\
        vertical columns for adjacent lines.\n\
\n\
Example::\n                                     \
\n\
    # This list of tuples,\n\
\n\
    [(0, 'Constraints'),\n\
     (1, 'min:', '0')\n\
     (1, 'max:', '100'),\n\
     (1, 'Filter Data'),\n\
     (2, 'ab bc de f0 12 34 56 78 9a bc de f0')\n\
     (2, '12 34 56 78 9a bc de f0 12 34 56 78')\n\
    ]\n\
\n\
    # would product this output\n\
\n\
    Constraints\n\
        min: 0\n\
        max: 100\n\
        Filter Data:\n\
           ab bc de f0 12 34 56 78 9a bc de f0\n\
           12 34 56 78 9a bc de f0 12 34 56 78\n\
\n\
:Parameters:\n\
    line_fmt_tuples : [(level, ...),...]\n\
        A list of tuples. First tuple value is the indentation level\n\
        followed by optional strings for the line.\n\
    indent_len : int\n\
        Number of space characters repeated for each level and\n\
        prepended to the line string.\n\
\n\
");

static PyObject *
py_indented_format(PyObject *self, PyObject *args, PyObject *kwds)
{
    typedef struct {
        Py_ssize_t indent_len;
        Py_ssize_t label_len;
        Py_ssize_t value_len;
        Py_ssize_t justification_len;
    } LineInfo;


    static char *kwlist[] = {"lines_pairs", "indent_len", NULL};
    PyObject *py_lines = NULL;
    long line_level = 0;
    int indent_len = 4;
    int cur_indent_len = 0;
    char *src=NULL, *dst=NULL;
    Py_ssize_t num_lines, tuple_len;
    char *label = NULL;
    char *value = NULL;
    Py_ssize_t label_len, value_len, justification_len, max_align;
    char *src_end = NULL;
    PyObject *py_line_fmt_tuple = NULL;
    PyObject *py_level = NULL;
    PyObject *py_label = NULL;
    PyObject *py_value = NULL;
    PyObject *py_string_utf8 = NULL;
    Py_ssize_t cur_formatted_line_len;
    PyObject *py_formatted_str = NULL;
    Py_ssize_t formatted_str_len;
    char *formatted_str;
    Py_ssize_t i, j, k;
    LineInfo *line_info = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|i:indented_format", kwlist,
                                     &PyList_Type, &py_lines, &indent_len))
        return NULL;

    num_lines = PyList_Size(py_lines);

    /*
     * Because we interrogate the length of the various strings
     * multiple times in the various loops we don't want to repeatedly
     * dereference and query the Pyton objects each time. So we
     * allocate an array to cache the information for efficency
     * purposes.
     */

    if ((line_info = PyMem_Malloc(num_lines*sizeof(LineInfo))) == NULL) {
        return PyErr_NoMemory();
    }

    /*
     * Step 1: Scan all the lines and get the string sizes.  Do all
     * error checking in this loop so we don't have to do it again
     * later. Cache the size information for faster access in
     * subseqent loops.
     */

    for (i = 0; i < num_lines; i++) {
        py_label = NULL;
        label = NULL;
        label_len = 0;

        py_value = NULL;
        value = NULL;
        value_len = 0;

        py_line_fmt_tuple = PyList_GetItem(py_lines, i);
        if (!PyTuple_Check(py_line_fmt_tuple)) {
            PyErr_Format(PyExc_TypeError, "line_fmt_tuples[%zd] must be a tuple, not %.200s",
                         i, Py_TYPE(py_line_fmt_tuple)->tp_name);
            goto fail;
        }

        tuple_len = PyTuple_Size(py_line_fmt_tuple);

        if (tuple_len < 1 || tuple_len > 3) {
            PyErr_Format(PyExc_TypeError, "line_fmt_tuples[%zd] tuple must have 1-3 items, not %zd items",
                         i, tuple_len);
            goto fail;
        }

        py_level = PyTuple_GetItem(py_line_fmt_tuple, 0);
        if (tuple_len == 2) {
            py_label = PyTuple_GetItem(py_line_fmt_tuple, 1);
        } else if (tuple_len == 3) {
            py_label = PyTuple_GetItem(py_line_fmt_tuple, 1);
            py_value = PyTuple_GetItem(py_line_fmt_tuple, 2);
        }

        if (!PyInt_Check(py_level)) {
            PyErr_Format(PyExc_TypeError, "item[0] in the tuple at line_fmt_tuples[%zd] list must be an integer, not %.200s",
                         i, Py_TYPE(py_level)->tp_name);
            goto fail;
        }
        line_level = PyInt_AsLong(py_level);
        if (line_level < 0) {
            PyErr_Format(PyExc_TypeError, "item[0] in the tuple at line_fmt_tuples[%zd] list must be a non-negative integer, not %ld",
                         i, line_level);
            goto fail;
        }

        label_len = value_len = 0;
        if (py_label) {
            if ((py_string_utf8 = PyString_UTF8(py_label, "label")) == NULL) {
                PyErr_Format(PyExc_TypeError, "item[1] in the tuple at line_fmt_tuples[%zd] list must be a string, not %.200s",
                             i, Py_TYPE(py_label)->tp_name);
                goto fail;
            }
            if (PyString_AsStringAndSize(py_string_utf8, &label, &label_len) == -1) {
                goto fail;
            }
        }
        Py_CLEAR(py_string_utf8);

        if (py_value) {
            if ((py_string_utf8 = PyString_UTF8(py_value, "value")) == NULL) {
                PyErr_Format(PyExc_TypeError, "item[2] in the tuple at line_fmt_tuples[%zd] list must be a string, not %.200s",
                             i, Py_TYPE(py_value)->tp_name);
                goto fail;
            }
            if (PyString_AsStringAndSize(py_string_utf8, &value, &value_len) == -1) {
                goto fail;
            }
        }
        Py_CLEAR(py_string_utf8);

        /* Cache the length information */
        line_info[i].label_len = label_len;
        line_info[i].value_len = value_len;
        line_info[i].justification_len = 0;
        line_info[i].indent_len = line_level * indent_len;
    }

    /*
     * Step 2: Locate labels and values that appear on consecutive
     * lines at the same indentation level. Compute the alignment for
     * values such that values all line up in the same column.
     *
     * We consider only lines that have both a label and a value for
     * the purpose of computing the alignment, if a line has only a
     * label we ignore it when establishing value alignment.
     *
     * A change in the indendation level resets the alignment.
     */
    for (i = 0; i < num_lines;) {
        cur_indent_len = line_info[i].indent_len;
        if (line_info[i].value_len) {
            max_align = line_info[i].label_len;
        } else {
            max_align = 0;
        }

        /*
         * Search forward for consecutive lines that share the same
         * indendation level.  If the line has value then use it's
         * label to compute the maximum width of all labels in this
         * group of lines.
         */
        for (j = i+1; j < num_lines && cur_indent_len == line_info[j].indent_len; j++) {
            if (line_info[j].value_len) {
                if (line_info[j].label_len > max_align) {
                    max_align = line_info[j].label_len;
                }
            }
        }

        /*
         * Now we know the maximum width of all labels in this group
         * of lines.  We always provide 1 space between a label and
         * it's value so we add 1 to the maximum label width, this
         * becomes our column for value alignment.
         *
         * If there were no values in this group of lines max_align
         * will be zero and we won't be doing any value alignment.
         */
        if (max_align) {
            max_align += 1;
        }

        /*
         * Now that we know the alignment column go back and compute
         * how much space to add at the end of each label to hit the
         * alignment column when we append the value.
         */
        for (k = i; k < j; k++) {
            if (line_info[k].value_len) { /* Only justify if there is a value */
                line_info[k].justification_len = max_align - line_info[k].label_len;
            }
        }

        /* This group of lines is processed, advance to the next group. */
        i = j;
    }

    /*
     * Step 3: We now know how many characters every line consumes,
     * compute the total buffer size required and allocate it.
     */
    formatted_str_len = 0;
    for (i = 0; i < num_lines; i++) {
        cur_formatted_line_len = line_info[i].indent_len +
                                 line_info[i].label_len +
                                 line_info[i].justification_len +
                                 line_info[i].value_len + 1; /* +1 for newline */
        formatted_str_len += cur_formatted_line_len;
    }

    if (num_lines > 0) formatted_str_len -= 1; /* last line doesn't get a new line appended */
    if ((py_formatted_str = PyString_FromStringAndSize(NULL, formatted_str_len)) == NULL) {
        goto fail;
    }

    formatted_str = PyString_AsString(py_formatted_str);
    dst = formatted_str;

    /*
     * Step 4: For each line: Insert the indent. If it has a label
     * insert the label. If it has a value insert the justification to
     * align the values, then insert the value. Finally append a
     * newline (except for the last line).
     */
    for (i = 0; i < num_lines; i++) {
        py_label = NULL;
        label = NULL;

        py_value = NULL;
        value = NULL;

        py_line_fmt_tuple = PyList_GetItem(py_lines, i);

        cur_indent_len = line_info[i].indent_len;
        label_len = line_info[i].label_len;
        value_len = line_info[i].value_len;
        justification_len = line_info[i].justification_len;

        /* Insert the indent */
        for (j = 0; j < cur_indent_len; j++) *dst++ = ' ';

        /* Insert the label */
        if (label_len) {
            py_label = PyTuple_GetItem(py_line_fmt_tuple, 1);
            py_string_utf8 = PyString_UTF8(py_label, "label");
            label = PyString_AsString(py_string_utf8);

            for (src = label, src_end = label + label_len; src < src_end; *dst++ = *src++);

            Py_CLEAR(py_string_utf8);
        }

        /* Insert the alignment justification for the value */
        for (j = 0; j < justification_len; j++) *dst++ = ' ';

        /* Insert the value */
        if (value_len) {
            py_value = PyTuple_GetItem(py_line_fmt_tuple, 2);
            py_string_utf8 = PyString_UTF8(py_value, "value");
            value = PyString_AsString(py_string_utf8);

            for (src = value, src_end = value + value_len; src < src_end; *dst++ = *src++);

            Py_CLEAR(py_string_utf8);
        }

        /* Add a new line, except for the last line */
        if (i < num_lines-1)
            *dst++ = '\n';
    }

    /*
     * Done. Sanity check we've written exactly the buffer we allocated.
     */
    assert(formatted_str + PyString_Size(py_formatted_str) == dst);
    return py_formatted_str;

 fail:
    Py_CLEAR(py_string_utf8);
    PyMem_Free(line_info);
    Py_XDECREF(py_formatted_str);
    return NULL;
}

/* ========================================================================== */

/* Copied from mozilla/security/nss/lib/certdb/alg1485.c */
typedef struct DnAvaPropsStr {
    const char * name;
    unsigned int maxLen; /* max bytes in UTF8 encoded string value */
    SECOidTag    oid_tag;
    int		 value_type;
} DnAvaProps;

static const DnAvaProps dn_ava_props[] = {
/* IANA registered type names
 * (See: http://www.iana.org/assignments/ldap-parameters)
 */
/* RFC 3280, 4630 MUST SUPPORT */
    { "CN",             64, SEC_OID_AVA_COMMON_NAME,    SEC_ASN1_UTF8_STRING},
    { "ST",            128, SEC_OID_AVA_STATE_OR_PROVINCE,
							SEC_ASN1_UTF8_STRING},
    { "O",              64, SEC_OID_AVA_ORGANIZATION_NAME,
							SEC_ASN1_UTF8_STRING},
    { "OU",             64, SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME,
                                                        SEC_ASN1_UTF8_STRING},
    { "dnQualifier", 32767, SEC_OID_AVA_DN_QUALIFIER, SEC_ASN1_PRINTABLE_STRING},
    { "C",               2, SEC_OID_AVA_COUNTRY_NAME, SEC_ASN1_PRINTABLE_STRING},
    { "serialNumber",   64, SEC_OID_AVA_SERIAL_NUMBER,SEC_ASN1_PRINTABLE_STRING},

/* RFC 3280, 4630 SHOULD SUPPORT */
    { "L",             128, SEC_OID_AVA_LOCALITY,       SEC_ASN1_UTF8_STRING},
    { "title",          64, SEC_OID_AVA_TITLE,          SEC_ASN1_UTF8_STRING},
    { "SN",             64, SEC_OID_AVA_SURNAME,        SEC_ASN1_UTF8_STRING},
    { "givenName",      64, SEC_OID_AVA_GIVEN_NAME,     SEC_ASN1_UTF8_STRING},
    { "initials",       64, SEC_OID_AVA_INITIALS,       SEC_ASN1_UTF8_STRING},
    { "generationQualifier",
                        64, SEC_OID_AVA_GENERATION_QUALIFIER,
                                                        SEC_ASN1_UTF8_STRING},
/* RFC 3280, 4630 MAY SUPPORT */
    { "DC",            128, SEC_OID_AVA_DC,             SEC_ASN1_IA5_STRING},
    { "MAIL",          256, SEC_OID_RFC1274_MAIL,       SEC_ASN1_IA5_STRING},
    { "UID",           256, SEC_OID_RFC1274_UID,        SEC_ASN1_UTF8_STRING},

/* values from draft-ietf-ldapbis-user-schema-05 (not in RFC 3280) */
    { "postalAddress", 128, SEC_OID_AVA_POSTAL_ADDRESS, SEC_ASN1_UTF8_STRING},
    { "postalCode",     40, SEC_OID_AVA_POSTAL_CODE,    SEC_ASN1_UTF8_STRING},
    { "postOfficeBox",  40, SEC_OID_AVA_POST_OFFICE_BOX,SEC_ASN1_UTF8_STRING},
    { "houseIdentifier",64, SEC_OID_AVA_HOUSE_IDENTIFIER,SEC_ASN1_UTF8_STRING},
/* end of IANA registered type names */

/* legacy keywords */
    { "E",             128, SEC_OID_PKCS9_EMAIL_ADDRESS,SEC_ASN1_IA5_STRING},

#if 0 /* removed.  Not yet in any IETF draft or RFC. */
    { "pseudonym",      64, SEC_OID_AVA_PSEUDONYM,      SEC_ASN1_UTF8_STRING},
#endif

    { 0,           256, SEC_OID_UNKNOWN                      , 0},
};

/* ========================================================================== */
typedef struct {
    unsigned short len;
    char *encoded;
} AsciiEscapes;

static AsciiEscapes ascii_encoding_table[256] = {
    {4, "\\x00"}, /*   0      */    {4, "\\x01"}, /*   1      */
    {4, "\\x02"}, /*   2      */    {4, "\\x03"}, /*   3      */
    {4, "\\x04"}, /*   4      */    {4, "\\x05"}, /*   5      */
    {4, "\\x06"}, /*   6      */    {2, "\\a"  }, /*   7 BELL */
    {2, "\\b"  }, /*   8 BS   */    {2, "\\t"  }, /*   9 HTAB */
    {2, "\\n"  }, /*  10 NL   */    {2, "\\v"  }, /*  11 VTAB */
    {2, "\\f"  }, /*  12 FF   */    {2, "\\r"  }, /*  13 CR   */
    {4, "\\x0E"}, /*  14      */    {4, "\\x0F"}, /*  15      */
    {4, "\\x10"}, /*  16      */    {4, "\\x11"}, /*  17      */
    {4, "\\x12"}, /*  18      */    {4, "\\x13"}, /*  19      */
    {4, "\\x14"}, /*  20      */    {4, "\\x15"}, /*  21      */
    {4, "\\x16"}, /*  22      */    {4, "\\x17"}, /*  23      */
    {4, "\\x18"}, /*  24      */    {4, "\\x19"}, /*  25      */
    {4, "\\x1A"}, /*  26      */    {4, "\\x1B"}, /*  27      */
    {4, "\\x1C"}, /*  28      */    {4, "\\x1D"}, /*  29      */
    {4, "\\x1E"}, /*  30      */    {4, "\\x1F"}, /*  31      */
    {1, " "    }, /*  32      */    {1, "!"    }, /*  33 !    */
    {2, "\\\"" }, /*  34 "    */    {1, "#"    }, /*  35 #    */
    {1, "$"    }, /*  36 $    */    {1, "%"    }, /*  37 %    */
    {1, "&"    }, /*  38 &    */    {2, "\\'"  }, /*  39 '    */
    {1, "("    }, /*  40 (    */    {1, ")"    }, /*  41 )    */
    {1, "*"    }, /*  42 *    */    {1, "+"    }, /*  43 +    */
    {1, ","    }, /*  44 ,    */    {1, "-"    }, /*  45 -    */
    {1, "."    }, /*  46 .    */    {1, "/"    }, /*  47 /    */
    {1, "0"    }, /*  48 0    */    {1, "1"    }, /*  49 1    */
    {1, "2"    }, /*  50 2    */    {1, "3"    }, /*  51 3    */
    {1, "4"    }, /*  52 4    */    {1, "5"    }, /*  53 5    */
    {1, "6"    }, /*  54 6    */    {1, "7"    }, /*  55 7    */
    {1, "8"    }, /*  56 8    */    {1, "9"    }, /*  57 9    */
    {1, ":"    }, /*  58 :    */    {1, ";"    }, /*  59 ;    */
    {1, "<"    }, /*  60 <    */    {1, "="    }, /*  61 =    */
    {1, ">"    }, /*  62 >    */    {2, "\\?"  }, /*  63 ?    */
    {1, "@"    }, /*  64 @    */    {1, "A"    }, /*  65 A    */
    {1, "B"    }, /*  66 B    */    {1, "C"    }, /*  67 C    */
    {1, "D"    }, /*  68 D    */    {1, "E"    }, /*  69 E    */
    {1, "F"    }, /*  70 F    */    {1, "G"    }, /*  71 G    */
    {1, "H"    }, /*  72 H    */    {1, "I"    }, /*  73 I    */
    {1, "J"    }, /*  74 J    */    {1, "K"    }, /*  75 K    */
    {1, "L"    }, /*  76 L    */    {1, "M"    }, /*  77 M    */
    {1, "N"    }, /*  78 N    */    {1, "O"    }, /*  79 O    */
    {1, "P"    }, /*  80 P    */    {1, "Q"    }, /*  81 Q    */
    {1, "R"    }, /*  82 R    */    {1, "S"    }, /*  83 S    */
    {1, "T"    }, /*  84 T    */    {1, "U"    }, /*  85 U    */
    {1, "V"    }, /*  86 V    */    {1, "W"    }, /*  87 W    */
    {1, "X"    }, /*  88 X    */    {1, "Y"    }, /*  89 Y    */
    {1, "Z"    }, /*  90 Z    */    {1, "["    }, /*  91 [    */
    {2, "\\\\" }, /*  92 \    */    {1, "]"    }, /*  93 ]    */
    {1, "^"    }, /*  94 ^    */    {1, "_"    }, /*  95 _    */
    {1, "`"    }, /*  96 `    */    {1, "a"    }, /*  97 a    */
    {1, "b"    }, /*  98 b    */    {1, "c"    }, /*  99 c    */
    {1, "d"    }, /* 100 d    */    {1, "e"    }, /* 101 e    */
    {1, "f"    }, /* 102 f    */    {1, "g"    }, /* 103 g    */
    {1, "h"    }, /* 104 h    */    {1, "i"    }, /* 105 i    */
    {1, "j"    }, /* 106 j    */    {1, "k"    }, /* 107 k    */
    {1, "l"    }, /* 108 l    */    {1, "m"    }, /* 109 m    */
    {1, "n"    }, /* 110 n    */    {1, "o"    }, /* 111 o    */
    {1, "p"    }, /* 112 p    */    {1, "q"    }, /* 113 q    */
    {1, "r"    }, /* 114 r    */    {1, "s"    }, /* 115 s    */
    {1, "t"    }, /* 116 t    */    {1, "u"    }, /* 117 u    */
    {1, "v"    }, /* 118 v    */    {1, "w"    }, /* 119 w    */
    {1, "x"    }, /* 120 x    */    {1, "y"    }, /* 121 y    */
    {1, "z"    }, /* 122 z    */    {1, "{"    }, /* 123 {    */
    {1, "|"    }, /* 124 |    */    {1, "}"    }, /* 125 }    */
    {1, "~"    }, /* 126 ~    */    {4, "\\x7F"}, /* 127      */
    {4, "\\x80"}, /* 128      */    {4, "\\x81"}, /* 129      */
    {4, "\\x82"}, /* 130      */    {4, "\\x83"}, /* 131      */
    {4, "\\x84"}, /* 132      */    {4, "\\x85"}, /* 133      */
    {4, "\\x86"}, /* 134      */    {4, "\\x87"}, /* 135      */
    {4, "\\x88"}, /* 136      */    {4, "\\x89"}, /* 137      */
    {4, "\\x8A"}, /* 138      */    {4, "\\x8B"}, /* 139      */
    {4, "\\x8C"}, /* 140      */    {4, "\\x8D"}, /* 141      */
    {4, "\\x8E"}, /* 142      */    {4, "\\x8F"}, /* 143      */
    {4, "\\x90"}, /* 144      */    {4, "\\x91"}, /* 145      */
    {4, "\\x92"}, /* 146      */    {4, "\\x93"}, /* 147      */
    {4, "\\x94"}, /* 148      */    {4, "\\x95"}, /* 149      */
    {4, "\\x96"}, /* 150      */    {4, "\\x97"}, /* 151      */
    {4, "\\x98"}, /* 152      */    {4, "\\x99"}, /* 153      */
    {4, "\\x9A"}, /* 154      */    {4, "\\x9B"}, /* 155      */
    {4, "\\x9C"}, /* 156      */    {4, "\\x9D"}, /* 157      */
    {4, "\\x9E"}, /* 158      */    {4, "\\x9F"}, /* 159      */
    {4, "\\xA0"}, /* 160      */    {4, "\\xA1"}, /* 161      */
    {4, "\\xA2"}, /* 162      */    {4, "\\xA3"}, /* 163      */
    {4, "\\xA4"}, /* 164      */    {4, "\\xA5"}, /* 165      */
    {4, "\\xA6"}, /* 166      */    {4, "\\xA7"}, /* 167      */
    {4, "\\xA8"}, /* 168      */    {4, "\\xA9"}, /* 169      */
    {4, "\\xAA"}, /* 170      */    {4, "\\xAB"}, /* 171      */
    {4, "\\xAC"}, /* 172      */    {4, "\\xAD"}, /* 173      */
    {4, "\\xAE"}, /* 174      */    {4, "\\xAF"}, /* 175      */
    {4, "\\xB0"}, /* 176      */    {4, "\\xB1"}, /* 177      */
    {4, "\\xB2"}, /* 178      */    {4, "\\xB3"}, /* 179      */
    {4, "\\xB4"}, /* 180      */    {4, "\\xB5"}, /* 181      */
    {4, "\\xB6"}, /* 182      */    {4, "\\xB7"}, /* 183      */
    {4, "\\xB8"}, /* 184      */    {4, "\\xB9"}, /* 185      */
    {4, "\\xBA"}, /* 186      */    {4, "\\xBB"}, /* 187      */
    {4, "\\xBC"}, /* 188      */    {4, "\\xBD"}, /* 189      */
    {4, "\\xBE"}, /* 190      */    {4, "\\xBF"}, /* 191      */
    {4, "\\xC0"}, /* 192      */    {4, "\\xC1"}, /* 193      */
    {4, "\\xC2"}, /* 194      */    {4, "\\xC3"}, /* 195      */
    {4, "\\xC4"}, /* 196      */    {4, "\\xC5"}, /* 197      */
    {4, "\\xC6"}, /* 198      */    {4, "\\xC7"}, /* 199      */
    {4, "\\xC8"}, /* 200      */    {4, "\\xC9"}, /* 201      */
    {4, "\\xCA"}, /* 202      */    {4, "\\xCB"}, /* 203      */
    {4, "\\xCC"}, /* 204      */    {4, "\\xCD"}, /* 205      */
    {4, "\\xCE"}, /* 206      */    {4, "\\xCF"}, /* 207      */
    {4, "\\xD0"}, /* 208      */    {4, "\\xD1"}, /* 209      */
    {4, "\\xD2"}, /* 210      */    {4, "\\xD3"}, /* 211      */
    {4, "\\xD4"}, /* 212      */    {4, "\\xD5"}, /* 213      */
    {4, "\\xD6"}, /* 214      */    {4, "\\xD7"}, /* 215      */
    {4, "\\xD8"}, /* 216      */    {4, "\\xD9"}, /* 217      */
    {4, "\\xDA"}, /* 218      */    {4, "\\xDB"}, /* 219      */
    {4, "\\xDC"}, /* 220      */    {4, "\\xDD"}, /* 221      */
    {4, "\\xDE"}, /* 222      */    {4, "\\xDF"}, /* 223      */
    {4, "\\xE0"}, /* 224      */    {4, "\\xE1"}, /* 225      */
    {4, "\\xE2"}, /* 226      */    {4, "\\xE3"}, /* 227      */
    {4, "\\xE4"}, /* 228      */    {4, "\\xE5"}, /* 229      */
    {4, "\\xE6"}, /* 230      */    {4, "\\xE7"}, /* 231      */
    {4, "\\xE8"}, /* 232      */    {4, "\\xE9"}, /* 233      */
    {4, "\\xEA"}, /* 234      */    {4, "\\xEB"}, /* 235      */
    {4, "\\xEC"}, /* 236      */    {4, "\\xED"}, /* 237      */
    {4, "\\xEE"}, /* 238      */    {4, "\\xEF"}, /* 239      */
    {4, "\\xF0"}, /* 240      */    {4, "\\xF1"}, /* 241      */
    {4, "\\xF2"}, /* 242      */    {4, "\\xF3"}, /* 243      */
    {4, "\\xF4"}, /* 244      */    {4, "\\xF5"}, /* 245      */
    {4, "\\xF6"}, /* 246      */    {4, "\\xF7"}, /* 247      */
    {4, "\\xF8"}, /* 248      */    {4, "\\xF9"}, /* 249      */
    {4, "\\xFA"}, /* 250      */    {4, "\\xFB"}, /* 251      */
    {4, "\\xFC"}, /* 252      */    {4, "\\xFD"}, /* 253      */
    {4, "\\xFE"}, /* 254      */    {4, "\\xFF"}, /* 255      */
};

/* From nss/cmd/certutil/keystuff.c */
static const unsigned char P[] = { 0,
       0x98, 0xef, 0x3a, 0xae, 0x70, 0x98, 0x9b, 0x44,
       0xdb, 0x35, 0x86, 0xc1, 0xb6, 0xc2, 0x47, 0x7c,
       0xb4, 0xff, 0x99, 0xe8, 0xae, 0x44, 0xf2, 0xeb,
       0xc3, 0xbe, 0x23, 0x0f, 0x65, 0xd0, 0x4c, 0x04,
       0x82, 0x90, 0xa7, 0x9d, 0x4a, 0xc8, 0x93, 0x7f,
       0x41, 0xdf, 0xf8, 0x80, 0x6b, 0x0b, 0x68, 0x7f,
       0xaf, 0xe4, 0xa8, 0xb5, 0xb2, 0x99, 0xc3, 0x69,
       0xfb, 0x3f, 0xe7, 0x1b, 0xd0, 0x0f, 0xa9, 0x7a,
       0x4a, 0x04, 0xbf, 0x50, 0x9e, 0x22, 0x33, 0xb8,
       0x89, 0x53, 0x24, 0x10, 0xf9, 0x68, 0x77, 0xad,
       0xaf, 0x10, 0x68, 0xb8, 0xd3, 0x68, 0x5d, 0xa3,
       0xc3, 0xeb, 0x72, 0x3b, 0xa0, 0x0b, 0x73, 0x65,
       0xc5, 0xd1, 0xfa, 0x8c, 0xc0, 0x7d, 0xaa, 0x52,
       0x29, 0x34, 0x44, 0x01, 0xbf, 0x12, 0x25, 0xfe,
       0x18, 0x0a, 0xc8, 0x3f, 0xc1, 0x60, 0x48, 0xdb,
       0xad, 0x93, 0xb6, 0x61, 0x67, 0xd7, 0xa8, 0x2d };
static const unsigned char Q[] = { 0,
       0xb5, 0xb0, 0x84, 0x8b, 0x44, 0x29, 0xf6, 0x33,
       0x59, 0xa1, 0x3c, 0xbe, 0xd2, 0x7f, 0x35, 0xa1,
       0x76, 0x27, 0x03, 0x81                         };
static const unsigned char G[] = {
       0x04, 0x0e, 0x83, 0x69, 0xf1, 0xcd, 0x7d, 0xe5,
       0x0c, 0x78, 0x93, 0xd6, 0x49, 0x6f, 0x00, 0x04,
       0x4e, 0x0e, 0x6c, 0x37, 0xaa, 0x38, 0x22, 0x47,
       0xd2, 0x58, 0xec, 0x83, 0x12, 0x95, 0xf9, 0x9c,
       0xf1, 0xf4, 0x27, 0xff, 0xd7, 0x99, 0x57, 0x35,
       0xc6, 0x64, 0x4c, 0xc0, 0x47, 0x12, 0x31, 0x50,
       0x82, 0x3c, 0x2a, 0x07, 0x03, 0x01, 0xef, 0x30,
       0x09, 0x89, 0x82, 0x41, 0x76, 0x71, 0xda, 0x9e,
       0x57, 0x8b, 0x76, 0x38, 0x37, 0x5f, 0xa5, 0xcd,
       0x32, 0x84, 0x45, 0x8d, 0x4c, 0x17, 0x54, 0x2b,
       0x5d, 0xc2, 0x6b, 0xba, 0x3e, 0xa0, 0x7b, 0x95,
       0xd7, 0x00, 0x42, 0xf7, 0x08, 0xb8, 0x83, 0x87,
       0x60, 0xe1, 0xe5, 0xf4, 0x1a, 0x54, 0xc2, 0x20,
       0xda, 0x38, 0x3a, 0xd1, 0xb6, 0x10, 0xf4, 0xcb,
       0x35, 0xda, 0x97, 0x92, 0x87, 0xd6, 0xa5, 0x37,
       0x62, 0xb4, 0x93, 0x4a, 0x15, 0x21, 0xa5, 0x10 };

static const SECKEYPQGParams default_pqg_params = {
    NULL,
    { 0, (unsigned char *)P, sizeof(P) },
    { 0, (unsigned char *)Q, sizeof(Q) },
    { 0, (unsigned char *)G, sizeof(G) }
};

/*
 * Returns the number of bytes needed to escape an ascii string.
 */
static size_t
ascii_encoded_strnlen(const char *str, size_t len)
{
    size_t result;
    const unsigned char *s;     /* must be unsigned for table indexing to work */

    for (s = (unsigned char *)str, result = 0; len; s++, len--) {
        result += ascii_encoding_table[*s].len;
    }
    return result;
}

/* ========================================================================== */
static char time_format[] = "%a %b %d %H:%M:%S %Y UTC";
static char hex_chars[] = "0123456789abcdef";
static PyObject *empty_tuple = NULL;
static PyObject *sec_oid_name_to_value = NULL;
static PyObject *sec_oid_value_to_name = NULL;
static PyObject *ckm_name_to_value = NULL;
static PyObject *ckm_value_to_name = NULL;
static PyObject *cka_name_to_value = NULL;
static PyObject *cka_value_to_name = NULL;
static PyObject *general_name_name_to_value = NULL;
static PyObject *general_name_value_to_name = NULL;
static PyObject *crl_reason_name_to_value = NULL;
static PyObject *crl_reason_value_to_name = NULL;
static PyObject *pkcs12_cipher_name_to_value = NULL;
static PyObject *pkcs12_cipher_value_to_name = NULL;

static PyTypeObject PK11SymKeyType;
static PyTypeObject PK11ContextType;
static PyTypeObject SecItemType;
static PyTypeObject AVAType;
static PyTypeObject RDNType;
static PyTypeObject DNType;
static PyTypeObject CertVerifyLogType;

/* === Forward Declarations */

static PyTypeObject CertDBType;
static PyTypeObject CertificateType;
static PyTypeObject PK11SlotType;

/* === Prototypes === */

static PyObject *
obj_to_hex(PyObject *obj, int octets_per_line, char *separator);

static PyObject *
raw_data_to_hex(unsigned char *data, int data_len, int octets_per_line, char *separator);

static SECStatus
sec_strip_tag_and_length(SECItem *item);

static PyObject *
der_context_specific_secitem_to_pystr(SECItem *item);

static PyObject *
secitem_to_pystr_hex(SECItem *item);

static PyObject *
der_any_secitem_to_pystr(SECItem *item);

static PyObject *
der_set_or_str_secitem_to_pylist_of_pystr(SECItem *item);

static PyObject *
boolean_secitem_to_pystr(SECItem *item);

static PyObject *
der_boolean_secitem_to_pystr(SECItem *item);

static PyObject *
integer_secitem_to_pylong(SECItem *item);

static PyObject *
integer_secitem_to_pystr(SECItem *item);

static PyObject *
der_integer_secitem_to_pystr(SECItem *item);

static bool
is_oid_string(const char *oid_string);

static SECOidTag
ava_name_to_oid_tag(const char *name);

static PyObject *
oid_secitem_to_pystr_desc(SECItem *oid);

static PyObject *
oid_secitem_to_pyint_tag(SECItem *oid);

static PyObject *
oid_secitem_to_pystr_dotted_decimal(SECItem *oid);

static PyObject *
der_oid_secitem_to_pystr_desc(SECItem *item);

static PyObject *
der_utc_time_secitem_to_pystr(SECItem *item);

static PyObject *
der_generalized_time_secitem_to_pystr(SECItem *item);

static PRTime
time_choice_secitem_to_prtime(SECItem *item);

static PyObject *
time_choice_secitem_to_pystr(SECItem *item);

static PyObject *
der_octet_secitem_to_pystr(SECItem *item, int octets_per_line, char *separator);

static PyObject *
ascii_string_secitem_to_escaped_ascii_pystr(SECItem *item);

static PyObject *
der_ascii_string_secitem_to_escaped_ascii_pystr(SECItem *item);

static PyObject *
der_utf8_string_secitem_to_pyunicode(SECItem *item);

static PyObject *
der_bmp_string_secitem_to_pyunicode(SECItem *item);

static PyObject *
der_universal_string_secitem_to_pyunicode(SECItem *item);

static PyObject *
der_bit_string_secitem_to_pystr(SECItem *item);

static PyObject *
der_universal_secitem_to_pystr(SECItem *item);

static PyObject *
ip_addr_secitem_to_pystr(SECItem *item);

static PyObject *
CERTGeneralName_to_pystr_with_label(CERTGeneralName *general_name);

static PyObject *
CERTGeneralName_to_pystr(CERTGeneralName *general_name);

static PyObject *
cert_oid_tag_name(PyObject *self, PyObject *args);

static PyObject *
cert_trust_flags(unsigned int flags, RepresentationKind repr_kind);

static PyObject *
SecItem_new_from_SECItem(const SECItem *item, SECItemKind kind);

static PyObject *
SecItem_new_alloc(size_t len, SECItemType type, SECItemKind kind);

static PyObject *
pk11_md5_digest(PyObject *self, PyObject *args);

static PyObject *
pk11_sha1_digest(PyObject *self, PyObject *args);

static PyObject *
pk11_sha256_digest(PyObject *self, PyObject *args);

static PyObject *
pk11_sha512_digest(PyObject *self, PyObject *args);

static PyObject *
PyPK11Context_new_from_PK11Context(PK11Context *pk11_context);

static PyObject *
PyPK11SymKey_new_from_PK11SymKey(PK11SymKey *pk11_sym_key);

static PyObject *
key_mechanism_type_to_pystr(CK_MECHANISM_TYPE mechanism);

static PyObject *
pk11_attribute_type_to_pystr(CK_ATTRIBUTE_TYPE type);

static PyObject *
SignedCRL_new_from_CERTSignedCRL(CERTSignedCrl *signed_crl);

static PyObject *
AVA_repr(AVA *self);

static bool
CERTRDN_has_tag(CERTRDN *rdn, int tag);

static PyObject *
CERTAVA_value_to_pystr(CERTAVA *ava);

static Py_ssize_t
CERTRDN_ava_count(CERTRDN *rdn);

static Py_ssize_t
DN_length(DN *self);

static PyObject *
DN_item(DN *self, register Py_ssize_t i);

static PyObject *
general_name_type_to_pystr(CERTGeneralNameType type);

static PyObject *
CERTGeneralName_type_string_to_pystr(CERTGeneralName *general_name);

static PyObject *
CRLDistributionPt_general_names_tuple(CRLDistributionPt *self, RepresentationKind repr_kind);

PyObject *
GeneralName_new_from_CERTGeneralName(CERTGeneralName *name);

static Py_ssize_t
AuthKeyID_general_names_count(AuthKeyID *self);

static PyObject *
AuthKeyID_general_names_tuple(AuthKeyID *self, RepresentationKind repr_kind);

static int
set_thread_local(const char *name, PyObject *obj);

static PyObject *
get_thread_local(const char *name);

static int
del_thread_local(const char *name);

static PyObject *
SECItem_to_hex(SECItem *item, int octets_per_line, char *separator);

static PyObject *
SECItem_der_to_hex(SECItem *item, int octets_per_line, char *separator);

static PyObject *
cert_x509_key_usage(PyObject *self, PyObject *args, PyObject *kwds);

static PyObject *
cert_x509_cert_type(PyObject *self, PyObject *args, PyObject *kwds);

PyObject *
CRLDistributionPts_new_from_SECItem(SECItem *item);

PyObject *
AuthorityInfoAccesses_new_from_SECItem(SECItem *item);

PyObject *
AuthKeyID_new_from_SECItem(SECItem *item);

static PyObject *
cert_x509_ext_key_usage(PyObject *self, PyObject *args, PyObject *kwds);

PyObject *
BasicConstraints_new_from_SECItem(SECItem *item);

static PyObject *
cert_x509_alt_name(PyObject *self, PyObject *args, PyObject *kwds);

PyObject *
DN_new_from_CERTName(CERTName *name);

PyObject *
AlgorithmID_new_from_SECAlgorithmID(SECAlgorithmID *id);

static PyObject *
Certificate_new_from_signed_der_secitem(SECItem *der);

static PyObject *
Certificate_get_subject(Certificate *self, void *closure);

static PyObject *
Certificate_get_issuer(Certificate *self, void *closure);

static PyObject *
Certificate_new_from_CERTCertificate(CERTCertificate *cert, bool add_reference);

static PyObject *
fingerprint_format_lines(SECItem *item, int level);

static PyObject *
PKCS12Decoder_item(PKCS12Decoder *self, register Py_ssize_t i);

PyObject *
KEYPQGParams_init_from_SECKEYPQGParams(KEYPQGParams *self, const SECKEYPQGParams *params);

static PyObject *
CertVerifyLog_new(PyTypeObject *type, PyObject *args, PyObject *kwds);

static Py_ssize_t
CertVerifyLog_length(CertVerifyLog *self);

static PyObject *
CertVerifyLog_item(CertVerifyLog *self, register Py_ssize_t i);

static PyObject *
CertAttribute_new_from_CERTAttribute(CERTAttribute *attr);

PyObject *
CertificateExtension_new_from_CERTCertExtension(CERTCertExtension *extension);

static PyObject *
CertificateExtension_get_name(CertificateExtension *self, void *closure);

static PyObject *
CertificateExtension_get_oid_tag(CertificateExtension *self, void *closure);

static Py_ssize_t
CERTCertExtension_count(CERTCertExtension **extensions);

static PyObject *
CERTCertExtension_tuple(CERTCertExtension **extensions, RepresentationKind repr_kind);

static SECStatus
CERTCertExtensions_from_CERTAttribute(PRArenaPool *arena,
                                      CERTAttribute *attr, CERTCertExtension ***exts);

static SECStatus
My_CERT_GetCertificateRequestExtensions(CERTCertificateRequest *req, CERTCertExtension ***exts);

static PyObject *
timestamp_to_DateTime(time_t timestamp, bool utc);

static PyObject *
pk11_pk11_disabled_reason_str(PyObject *self, PyObject *args);

/* ==================================== */

typedef struct BitStringTableStr {
    int enum_value;
    const char *enum_name;
    const char *enum_description;
} BitStringTable;

#define BITSTRING_TBL_INIT(enum, description) \
    {enum, #enum, description}

static BitStringTable CRLReasonDef[] = {
    BITSTRING_TBL_INIT(crlEntryReasonUnspecified,          _("Unspecified")           ), /* bit 0  */
    BITSTRING_TBL_INIT(crlEntryReasonKeyCompromise,        _("Key Compromise")        ), /* bit 1  */
    BITSTRING_TBL_INIT(crlEntryReasonCaCompromise,         _("CA Compromise")         ), /* bit 2  */
    BITSTRING_TBL_INIT(crlEntryReasonAffiliationChanged,   _("Affiliation Changed")   ), /* bit 3  */
    BITSTRING_TBL_INIT(crlEntryReasonSuperseded,           _("Superseded")            ), /* bit 4  */
    BITSTRING_TBL_INIT(crlEntryReasonCessationOfOperation, _("Cessation Of Operation")), /* bit 5  */
    BITSTRING_TBL_INIT(crlEntryReasoncertificatedHold,     _("Certificate On Hold")   ), /* bit 6  */
    BITSTRING_TBL_INIT(-1,                                 NULL                       ), /* bit 7  */
    BITSTRING_TBL_INIT(crlEntryReasonRemoveFromCRL,        _("Remove From CRL")       ), /* bit 8  */
    BITSTRING_TBL_INIT(crlEntryReasonPrivilegeWithdrawn,   _("Privilege Withdrawn")   ), /* bit 9  */
    BITSTRING_TBL_INIT(crlEntryReasonAaCompromise,         _("AA Compromise")         ), /* bit 10 */
};

static BitStringTable KeyUsageDef[] = {
    BITSTRING_TBL_INIT(KU_DIGITAL_SIGNATURE, _("Digital Signature")  ), /* bit 0 */
    BITSTRING_TBL_INIT(KU_NON_REPUDIATION,   _("Non-Repudiation")    ), /* bit 1 */
    BITSTRING_TBL_INIT(KU_KEY_ENCIPHERMENT,  _("Key Encipherment")   ), /* bit 2 */
    BITSTRING_TBL_INIT(KU_DATA_ENCIPHERMENT, _("Data Encipherment")  ), /* bit 3 */
    BITSTRING_TBL_INIT(KU_KEY_AGREEMENT,     _("Key Agreement")      ), /* bit 4 */
    BITSTRING_TBL_INIT(KU_KEY_CERT_SIGN,     _("Certificate Signing")), /* bit 5 */
    BITSTRING_TBL_INIT(KU_CRL_SIGN,          _("CRL Signing")        ), /* bit 6 */
    BITSTRING_TBL_INIT(KU_ENCIPHER_ONLY,     _("Encipher Only")      ), /* bit 7 */
#ifdef KU_DECIPHER_ONLY
    BITSTRING_TBL_INIT(KU_DECIPHER_ONLY,     _("Decipher Only")      ), /* bit 8 */
#endif
};

static BitStringTable CertTypeDef[] = {
    BITSTRING_TBL_INIT(NS_CERT_TYPE_SSL_CLIENT,        _("SSL Client")        ), /* bit 0 */
    BITSTRING_TBL_INIT(NS_CERT_TYPE_SSL_SERVER,        _("SSL Server")        ), /* bit 1 */
    BITSTRING_TBL_INIT(NS_CERT_TYPE_EMAIL,             _("Email")             ), /* bit 2 */
    BITSTRING_TBL_INIT(NS_CERT_TYPE_OBJECT_SIGNING,    _("Object Signing")    ), /* bit 3 */
    BITSTRING_TBL_INIT(NS_CERT_TYPE_RESERVED,          _("Reserved")          ), /* bit 4 */
    BITSTRING_TBL_INIT(NS_CERT_TYPE_SSL_CA,            _("SSL CA")            ), /* bit 5 */
    BITSTRING_TBL_INIT(NS_CERT_TYPE_EMAIL_CA,          _("Email CA")          ), /* bit 6 */
    BITSTRING_TBL_INIT(NS_CERT_TYPE_OBJECT_SIGNING_CA, _("Object Signing CA") ), /* bit 7 */
};

static PyObject *
timestamp_to_DateTime(time_t timestamp, bool utc)
{
    double d_timestamp = timestamp;
    PyObject *py_datetime = NULL;
    char *method;

    method = utc ? "utcfromtimestamp" : "fromtimestamp";
    if ((py_datetime =
         PyObject_CallMethod((PyObject *)PyDateTimeAPI->DateTimeType,
                             method, "(d)", d_timestamp)) == NULL) {
            return NULL;
    }

    return py_datetime;
}

/* returns new reference or NULL on error */
PyObject *
PyString_UTF8(PyObject *obj, char *name)
{
    if (PyString_Check(obj)) {
        Py_INCREF(obj);
        return obj;
    }

    if  (PyUnicode_Check(obj)) {
        return PyUnicode_AsUTF8String(obj);
    }

    PyErr_Format(PyExc_TypeError, "%s must be a string, not %.200s",
                 name, Py_TYPE(obj)->tp_name);
    return NULL;
}

static SECStatus
SecItem_param(PyObject *py_param, SECItem **pitem, SECItem *tmp_item,
              bool none_ok, const char *param_name)
{
    *pitem = NULL;
    if (py_param) {
        if (PySecItem_Check(py_param)) {
            *pitem = &((SecItem *)py_param)->item;
        } else if (none_ok && PyNone_Check(py_param)) {
            *pitem = NULL;
        } else if (PyObject_CheckReadBuffer(py_param)) {
            unsigned char *data = NULL;
            Py_ssize_t data_len;

            if (PyObject_AsReadBuffer(py_param, (void *)&data, &data_len))
                return SECFailure;

            tmp_item->data = data;
            tmp_item->len = data_len;
            *pitem = tmp_item;
        } else {
            if (none_ok) {
                PyErr_Format(PyExc_TypeError, "%s must be SecItem, buffer compatible or None", param_name);
            } else {
                PyErr_Format(PyExc_TypeError, "%s must be SecItem or buffer compatible", param_name);
            }
            return SECFailure;
        }
    }
    return SECSuccess;
}

/*
 * Parse text as base64 data. base64 may optionally be wrapped in PEM
 * header/footer. der SECItem must be freed with
 * SECITEM_FreeItem(&der, PR_FALSE);
 */
static SECStatus
base64_to_SECItem(SECItem *der, char *text, size_t text_len)
{
    char *p, *text_end, *tmp, *der_begin, *der_end;

    der->data = NULL;
    der->len = 0;
    der->type = siBuffer;

    p = text;
    text_end = text + text_len;
    /* check for headers and trailers and remove them */
    if ((tmp = PL_strnstr(p, "-----BEGIN", text_end-p)) != NULL) {
        p = tmp;
        tmp = PORT_Strchr(p, '\n');
        if (!tmp) {
            tmp = strchr(p, '\r'); /* maybe this is a MAC file */
        }
        if (!tmp) {
            PyErr_SetString(PyExc_ValueError, "no line ending after PEM BEGIN");
            return SECFailure;
        }
        p = der_begin = tmp + 1;
        tmp = PL_strnstr(p, "-----END", text_end-p);
        if (tmp != NULL) {
            der_end = tmp;
            *der_end = '\0';
        } else {
            PyErr_SetString(PyExc_ValueError, "no PEM END found");
            return SECFailure;
        }
    } else {
        der_begin = p;
        der_end = p + strlen(p);
    }

    /* Convert to binary */
    if (NSSBase64_DecodeBuffer(NULL, der, der_begin, der_end - der_begin) == NULL) {
        set_nspr_error("Could not base64 decode");
        return SECFailure;
    }
    return SECSuccess;
}

SECStatus
base64_to_SECItemX(SECItem *der, char *text)
{
    char *p, *tmp, *der_begin, *der_end;

    der->data = NULL;
    der->len = 0;
    der->type = siBuffer;

    p = text;
    /* check for headers and trailers and remove them */
    if ((tmp = strstr(p, "-----BEGIN")) != NULL) {
        p = tmp;
        tmp = PORT_Strchr(p, '\n');
        if (!tmp) {
            tmp = strchr(p, '\r'); /* maybe this is a MAC file */
        }
        if (!tmp) {
            PyErr_SetString(PyExc_ValueError, "no line ending after PEM BEGIN");
            return SECFailure;
        }
        p = der_begin = tmp + 1;
        tmp = strstr(p, "-----END");
        if (tmp != NULL) {
            der_end = tmp;
            *der_end = '\0';
        } else {
            PyErr_SetString(PyExc_ValueError, "no PEM END found");
            return SECFailure;
        }
    } else {
        der_begin = p;
        der_end = p + strlen(p);
    }

    /* Convert to binary */
    if (NSSBase64_DecodeBuffer(NULL, der, der_begin, der_end - der_begin) == NULL) {
        set_nspr_error("Could not base64 decode");
        return SECFailure;
    }
    return SECSuccess;
}

/*
 * Parse text as base64 data. base64 may optionally be wrapped in PEM
 * header/footer. Return python SecItem.
 */
static PyObject *
base64_to_SecItem(char *text)
{
    PyObject *py_sec_item;
    SECItem der;

    if (base64_to_SECItem(&der, text, strlen(text)) != SECSuccess) {
        return NULL;
    }

    py_sec_item = SecItem_new_from_SECItem(&der, SECITEM_unknown);
    SECITEM_FreeItem(&der, PR_FALSE);
    return py_sec_item;
}

static PyObject *
SECItem_to_base64(SECItem *item, size_t chars_per_line, char *pem_type)
{
    char *base64 = NULL;
    PyObject *lines = NULL;
    PyObject *py_base64 = NULL;
    size_t base64_len = 0;

    if ((base64 = NSSBase64_EncodeItem(NULL, NULL, 0, item)) == NULL) {
        return set_nspr_error("unable to encode SECItem to base64");
    }

    if (pem_type && chars_per_line == 0) {
        chars_per_line = 64;
    }

    base64_len = strlen(base64);
    if (chars_per_line) {
        size_t n_lines, line_number, line_len;
        char *src, *src_end;
        PyObject *line = NULL;

        n_lines = ((base64_len + chars_per_line - 1) / chars_per_line);

        if (pem_type) {
            n_lines += 2;
        }

        if ((lines = PyList_New(n_lines)) == NULL) {
            goto fail;
        }
        line_number = 0;

        if (pem_type) {
            if ((line = PyString_FromFormat("-----BEGIN %s-----",
                                            pem_type)) == NULL) {
                goto fail;
            }
            PyList_SetItem(lines, line_number++, line);
        }

        src = base64;
        src_end = base64 + base64_len;

        while(src < src_end) {
            line_len = MIN(chars_per_line, src_end - src);
            if ((line = PyString_FromStringAndSize(src, line_len)) == NULL) {
                goto fail;
            }
            PyList_SetItem(lines, line_number++, line);

            src += line_len;
        }

        if (pem_type) {
            if ((line = PyString_FromFormat("-----END %s-----",
                                            pem_type)) == NULL) {
                goto fail;
            }
            PyList_SetItem(lines, line_number++, line);
        }

        PORT_Free(base64);
        return lines;
    } else {
        py_base64 = PyString_FromStringAndSize(base64, base64_len);
        PORT_Free(base64);
        return py_base64;

    }

 fail:
    if (base64)
        PORT_Free(base64);
    Py_XDECREF(lines);
    Py_XDECREF(py_base64);
    return NULL;
}

static bool
pyobject_has_method(PyObject* obj, const char *method_name)
{
    PyObject *attr;
    int is_callable;

    if ((attr = PyObject_GetAttrString(obj, method_name)) == NULL) {
        return false;
    }
    is_callable = PyCallable_Check(attr);
    Py_DECREF(attr);
    return is_callable ? true : false;
}

/*
 * read_data_from_file(PyObject *file_arg)
 *
 * :Parameters:
 *     file_arg : file name or file object
 *         If string treat as file path to open and read,
 *         if file object read from file object.
 *
 * Read the contents of a file and return as a PyString object.
 * If file is a string then treat it as a file pathname and open
 * and read the contents of that file. If file is a file object
 * then read the contents from the file object
 */
static PyObject *
read_data_from_file(PyObject *file_arg)
{
    PyObject *py_file=NULL;
    PyObject *py_file_contents=NULL;

    if (PyString_Check(file_arg) || PyUnicode_Check(file_arg)) {
        if ((py_file = PyFile_FromString(PyString_AsString(file_arg), "r")) == NULL) {
            return NULL;
        }
    } else if (pyobject_has_method(file_arg, "read")) {
        py_file = file_arg;
	Py_INCREF(py_file);
    } else {
        PyErr_SetString(PyExc_TypeError, "Bad file, must be pathname or file like object with read() method");
        return NULL;
    }

    if ((py_file_contents = PyObject_CallMethod(py_file, "read", "")) == NULL) {
        Py_DECREF(py_file);
        return NULL;
    }
    Py_DECREF(py_file);

    return py_file_contents;
}

static SECStatus
secport_ucs2_swap_bytes(SECItem *ucs2_item)
{
    unsigned int i;
    unsigned char tmp;

    if ((ucs2_item == NULL) || (ucs2_item->len % 2)) {
        return SECFailure;
    }

    for (i = 0; i < ucs2_item->len; i += 2) {
        tmp = ucs2_item->data[i];
        ucs2_item->data[i] = ucs2_item->data[i+1];
        ucs2_item->data[i+1] = tmp;
    }
    return SECSuccess;
}

static PRBool
secport_ucs2_to_utf8(PRBool to_unicode,
                     unsigned char *in_buf, unsigned int in_buf_len,
                     unsigned char *out_buf, unsigned int max_out_buf_len, unsigned int *out_buf_len,
                     PRBool swap_bytes)
{
    SECItem src_item = {siBuffer, NULL, 0};
    SECItem *swapped_item = NULL;
    PRBool result;

    /* If converting Unicode to ASCII, swap bytes before conversion as neccessary. */
    if (!to_unicode && swap_bytes) {
        SECItem in_buf_item = {siBuffer, NULL, 0};

        in_buf_item.data = in_buf;
        in_buf_item.len = in_buf_len;
        swapped_item = SECITEM_DupItem(&in_buf_item);

        if (secport_ucs2_swap_bytes(swapped_item) != SECSuccess) {
            SECITEM_ZfreeItem(swapped_item, PR_TRUE);
            return PR_FALSE;
        }

        src_item = *swapped_item;

    } else {
        src_item.data = in_buf;
        src_item.len = in_buf_len;
    }

    /* Perform the conversion. */
    result = PORT_UCS2_UTF8Conversion(to_unicode, src_item.data, src_item.len,
                                      out_buf, max_out_buf_len, out_buf_len);
    if (swapped_item)
        SECITEM_ZfreeItem(swapped_item, PR_TRUE);

    return result;
}

/*
 * NSS WART
 * NSS encodes a bit string in a SECItem by setting the len field
 * to a bit count and stripping off the leading "unused" octet.
 */
static int
der_bitstring_to_nss_bitstring(SECItem *dst, SECItem *src) {
    unsigned long data_len;
    int src_len;
    unsigned char *src_data, octet, unused;

    if (!src || !dst) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    src_len = src->len;
    src_data = src->data;

    /* First octet is ASN1 type */
    if (src_len <= 0) goto bad_data;
    octet = *src_data++; src_len--;

    if ((octet & SEC_ASN1_TAGNUM_MASK) != SEC_ASN1_BIT_STRING)
        goto bad_data;

    /* Next octets are ASN1 length */
    if (src_len <= 0) goto bad_data;
    octet = *src_data++; src_len--;

    data_len = octet;
    if (data_len & 0x80) {
        int  len_count = data_len & 0x7f;

        if (len_count > src_len)
            goto bad_data;

        for (data_len = 0, octet = *src_data++, src_len--;
             len_count;
             len_count--,  octet = *src_data++, src_len--) {
            data_len = (data_len << 8) | octet;
        }
    }

    /* After ASN1 length comes one octet containing the unused bit count */
    if (src_len <= 0) goto bad_data;
    unused = *src_data++; src_len--;

    if (data_len <= 1) {
        goto bad_data;
    } else {
        data_len--;             /* account for unused octet */
        dst->len = (data_len << 3) - (unused & 0x07);
        dst->data = src_len > 0 ? src_data : NULL;
    }

    return SECSuccess;

 bad_data:
    PORT_SetError(SEC_ERROR_BAD_DATA);
    return SECFailure;
}

/*
 * Given a decoded bit string in a SECItem (where len is a bit count and
 * the high bit of data[0] is bit[0] of the bitstring) return a tuple of
 * every enabled bit in the bit string. The members of the tuple come from
 * a table of predined values for the bit string. The repr_kind
 * enumeration specifies what type of item should be put in the tuple, for
 * example the string name for the bit position, or the enumerated constant
 * representing that bit postion, or the bit posisiton.
 */
static PyObject *
bitstr_table_to_tuple(SECItem *bitstr, BitStringTable *table,
                      size_t table_len, RepresentationKind repr_kind)
{
    PyObject *tuple = NULL;
    size_t bitstr_len, len, count, i, j;
    unsigned char *data, octet = 0, mask = 0x80;

    bitstr_len = bitstr->len;
    len = MIN(table_len, bitstr_len);

    /*
     * Get a count of how many bits are enabled.
     * Skip any undefined entries in the table.
     */
    count = 0;
    if (bitstr->data != NULL) {
        for (i = 0, data = bitstr->data; i < len; i++) {
            if ((i % 8) == 0) {
                octet = *data++;
                mask = 0x80;
            }
            if (octet & mask) {
                if (table[i].enum_description) { /* only if defined in table */
                    count++;
                }
            }
            mask >>= 1;
        }
    }

    if ((tuple = PyTuple_New(count)) == NULL) {
        return NULL;
    }

    if (count == 0) {
        return tuple;
    }

    /* Populate the tuple */
    for (i = j = 0, data = bitstr->data; i < len; i++) {
        if ((i % 8) == 0) {
            octet = *data++;
            mask = 0x80;
        }
        if (octet & mask) {
            if (table[i].enum_description) { /* only if defined in table */
                switch(repr_kind) {
                case AsEnum:
                    PyTuple_SetItem(tuple, j++, PyInt_FromLong(table[i].enum_value));
                    break;
                case AsEnumName:
                    PyTuple_SetItem(tuple, j++, PyString_FromString(table[i].enum_name));
                    break;
                case AsEnumDescription:
                    PyTuple_SetItem(tuple, j++, PyString_FromString(table[i].enum_description));
                    break;
                case AsIndex:
                    PyTuple_SetItem(tuple, j++, PyInt_FromLong(i));
                    break;
                default:
                    PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind);
                    Py_DECREF(tuple);
                    return NULL;
                    break;
                }
            }
        }
        mask >>= 1;
    }

    return tuple;
}

static PyObject *
crl_reason_bitstr_to_tuple(SECItem *bitstr, RepresentationKind repr_kind)
{
    size_t table_len;

    table_len = sizeof(CRLReasonDef) / sizeof(CRLReasonDef[0]);
    return bitstr_table_to_tuple(bitstr, CRLReasonDef, table_len, repr_kind);
}

static PyObject *
key_usage_bitstr_to_tuple(SECItem *bitstr, RepresentationKind repr_kind)
{
    size_t table_len;

    table_len = sizeof(KeyUsageDef) / sizeof(KeyUsageDef[0]);
    return bitstr_table_to_tuple(bitstr, KeyUsageDef, table_len, repr_kind);
}

static PyObject *
cert_type_bitstr_to_tuple(SECItem *bitstr, RepresentationKind repr_kind)
{
    size_t table_len;

    table_len = sizeof(CertTypeDef) / sizeof(CertTypeDef[0]);
    return bitstr_table_to_tuple(bitstr, CertTypeDef, table_len, repr_kind);
}

static PyObject *
decode_oid_sequence_to_tuple(SECItem *item, RepresentationKind repr_kind)
{
    int i, n_oids;
    PyObject *tuple;
    CERTOidSequence *os;
    SECItem **op;
    PyObject *py_oid;

    if (!item || !item->len || !item->data) {
        PyErr_SetString(PyExc_ValueError, "missing DER encoded OID data");
        return NULL;
    }

    if ((os = CERT_DecodeOidSequence(item)) == NULL) {
        return set_nspr_error("unable to decode OID sequence");
    }

    /* Get a count of how many OID's there were */
    for(op = os->oids, n_oids = 0; *op; op++, n_oids++);

    if ((tuple = PyTuple_New(n_oids)) == NULL) {
        CERT_DestroyOidSequence(os);
        return NULL;
    }

    /* Iterate over each OID and insert into tuple */
    for(op = os->oids, i = 0; *op; op++, i++) {
        switch(repr_kind) {
        case AsObject:
            if ((py_oid = SecItem_new_from_SECItem(*op, SECITEM_oid)) == NULL) {
                Py_DECREF(tuple);
                CERT_DestroyOidSequence(os);
                return NULL;
            }
            break;
        case AsString:
            if ((py_oid = oid_secitem_to_pystr_desc(*op)) == NULL) {
                Py_DECREF(tuple);
                CERT_DestroyOidSequence(os);
                return NULL;
            }
            break;
        case AsDottedDecimal:
            if ((py_oid = oid_secitem_to_pystr_dotted_decimal(*op)) == NULL) {
                Py_DECREF(tuple);
                CERT_DestroyOidSequence(os);
                return NULL;
            }
            break;
        case AsEnum:
            if ((py_oid = oid_secitem_to_pyint_tag(*op)) == NULL) {
                Py_DECREF(tuple);
                CERT_DestroyOidSequence(os);
                return NULL;
            }
            break;
        default:
            PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind);
            Py_DECREF(tuple);
            CERT_DestroyOidSequence(os);
            return NULL;
        }
        PyTuple_SetItem(tuple, i, py_oid);
    }
    CERT_DestroyOidSequence(os);

    return tuple;
}

static Py_ssize_t
CERTCertExtension_count(CERTCertExtension **extensions)
{
    Py_ssize_t count;

    if (extensions == NULL) return 0;
    for (count = 0; *extensions; extensions++, count++);
    return count;
}

static PyObject *
CERTCertExtension_tuple(CERTCertExtension **extensions, RepresentationKind repr_kind)
{
    Py_ssize_t n_extensions, i;
    PyObject *tuple=NULL, *py_ext=NULL, *py_obj=NULL;
    CERTCertExtension *ext;

    n_extensions = CERTCertExtension_count(extensions);

    if (n_extensions == 0) {
        Py_INCREF(empty_tuple);
        return empty_tuple;
    }

    if ((tuple = PyTuple_New(n_extensions)) == NULL) {
        return NULL;
    }

    for (i = 0; i < n_extensions; i++) {
        ext = extensions[i];
        if ((py_ext = CertificateExtension_new_from_CERTCertExtension(ext)) == NULL) {
            goto fail;
        }

        switch(repr_kind) {
        case AsObject:
            py_obj = py_ext;
            Py_INCREF(py_obj);
            break;
        case AsString:
            if ((py_obj = CertificateExtension_get_name((CertificateExtension *)py_ext, NULL)) == NULL) {
                goto fail;
            }
            break;
        case AsEnum:
            if ((py_obj = CertificateExtension_get_oid_tag((CertificateExtension *)py_ext, NULL)) == NULL) {
                goto fail;
            }
            break;
        default:
            PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind);
            goto fail;
        }
        PyTuple_SetItem(tuple, i, py_obj);
        Py_CLEAR(py_ext);
    }

    return tuple;

 fail:
    Py_XDECREF(tuple);
    Py_XDECREF(py_ext);
    return NULL;
}


static PyObject *
CERTCertList_to_tuple(CERTCertList *cert_list, bool add_reference)
{
    Py_ssize_t n_certs = 0;
    Py_ssize_t i = 0;
    CERTCertListNode *node = NULL;
    PyObject *py_cert = NULL;
    PyObject *tuple = NULL;

    for (node = CERT_LIST_HEAD(cert_list), n_certs = 0;
         !CERT_LIST_END(node, cert_list);
         node = CERT_LIST_NEXT(node), n_certs++);

    if ((tuple = PyTuple_New(n_certs)) == NULL) {
        return NULL;
    }

    for (node = CERT_LIST_HEAD(cert_list), i = 0;
         !CERT_LIST_END(node, cert_list);
         node = CERT_LIST_NEXT(node), i++) {
        if ((py_cert = Certificate_new_from_CERTCertificate(node->cert, add_reference)) == NULL) {
            Py_DECREF(tuple);
            return NULL;
        }
        PyTuple_SetItem(tuple, i, py_cert);
    }
    return tuple;
}

/* NSS WART: CERT_CopyAVA is hidden, but we need it, copied here from secname.c */
CERTAVA *
CERT_CopyAVA(PRArenaPool *arena, CERTAVA *from)
{
    CERTAVA *ava;
    int rv;

    ava = (CERTAVA*) PORT_ArenaZAlloc(arena, sizeof(CERTAVA));
    if (ava) {
	rv = SECITEM_CopyItem(arena, &ava->type, &from->type);
	if (rv) goto loser;
	rv = SECITEM_CopyItem(arena, &ava->value, &from->value);
	if (rv) goto loser;
    }
    return ava;

  loser:
    return NULL;
}

static SECStatus
CERT_CopyGeneralName(PRArenaPool *arena, CERTGeneralName **pdst, CERTGeneralName *src)
{
    SECStatus result = SECSuccess;
    void *mark = NULL;
    CERTGeneralName *dst;

    /*
     * NSS WART
     * There is no public API to create a CERTGeneralName, copy it, or free it.
     * You don't know what arena was used to create the general name.
     * GeneralNames are linked in a list, this makes it difficult for a
     * general name to exist independently, it would have been better if there
     * was a list container independent general names could be placed in,
     * then you wouldn't have to worry about the link fields in each independent name.
     *
     * The logic here is copied from cert_CopyOneGeneralName in certdb/genname.c
     */

    if (!arena) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (!src) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    mark = PORT_ArenaMark(arena);

    if ((dst = PORT_ArenaZNew(arena, CERTGeneralName)) == NULL) {
        result = SECFailure;
        goto exit;
    }

    dst->l.prev = dst->l.next = &dst->l;
    dst->type = src->type;

    switch (src->type) {
    case certDirectoryName:
	if ((result = SECITEM_CopyItem(arena, &dst->derDirectoryName,
                                       &src->derDirectoryName)) != SECSuccess) {
            goto exit;
        }
        if ((result = CERT_CopyName(arena, &dst->name.directoryName,
                                    &src->name.directoryName)) != SECSuccess) {
            goto exit;
        }
	break;

    case certOtherName:
	if ((result = SECITEM_CopyItem(arena, &dst->name.OthName.name,
                                       &src->name.OthName.name)) != SECSuccess) {
            goto exit;
        }
        if ((result = SECITEM_CopyItem(arena, &dst->name.OthName.oid,
                                       &src->name.OthName.oid)) != SECSuccess) {
            goto exit;
        }
	break;

    default:
	if ((result = SECITEM_CopyItem(arena, &dst->name.other,
                                       &src->name.other)) != SECSuccess) {
            goto exit;
        }
	break;

    }


 exit:
    if (result == SECSuccess) {
        *pdst = dst;
        PORT_ArenaUnmark(arena, mark);
    } else {
        *pdst = NULL;
        PORT_ArenaRelease(arena, mark);
    }
    return result;
}

static Py_ssize_t
CERTGeneralName_list_count(CERTGeneralName *head)
{
    CERTGeneralName *cur;
    Py_ssize_t count;

    count = 0;
    if (!head) {
        return count;
    }

    cur = head;
    do {
        count++;
        cur = CERT_GetNextGeneralName(cur);
    } while (cur != head);

    return count;
}

static PyObject *
CERTGeneralName_list_to_tuple(CERTGeneralName *head, RepresentationKind repr_kind)
{
    CERTGeneralName *cur;
    Py_ssize_t n_names, i;
    PyObject *names;

    n_names = CERTGeneralName_list_count(head);

    if ((names = PyTuple_New(n_names)) == NULL) {
        return NULL;
    }

    if (n_names == 0) {
        return names;
    }

    i = 0;
    cur = head;
    do {
        PyObject *name;

        switch(repr_kind) {
        case AsObject:
            name = GeneralName_new_from_CERTGeneralName(cur);
            break;
        case AsString:
            name = CERTGeneralName_to_pystr(cur);
            break;
        case AsTypeString:
            name = CERTGeneralName_type_string_to_pystr(cur);
            break;
        case AsTypeEnum:
            name = PyInt_FromLong(cur->type);
            break;
        case AsLabeledString:
            name = CERTGeneralName_to_pystr_with_label(cur);
            break;
        default:
            PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind);
            Py_DECREF(names);
            return NULL;
        }
        PyTuple_SetItem(names, i, name);
        cur = CERT_GetNextGeneralName(cur);
        i++;
    } while (cur != head);


    return names;
}

static SECStatus
CERT_CopyGeneralNameList(PRArenaPool *arena, CERTGeneralName **pdst, CERTGeneralName *src)
{
    SECStatus result = SECSuccess;
    void *mark = NULL;
    CERTGeneralName *src_head, *dst_head;
    CERTGeneralName *cur, *prev;

    /*
     * NSS WART
     * There is no publice API to copy a list of GeneralNames.
     *
     * GeneralNames are an exception to all other NSS data containers.
     * Normally homogeneous collections are stored in a array of pointers to
     * the items with the last array element being NULL. However GeneralNames are
     * exception, they embed a linked list for assembling them in a list. Not only
     * is this an awkward deviation but it means the GeneralName cannot belong to
     * more than one collection.
     *
     * The logic here is copied from CERT_CopyGeneralName in certdb/genname.c
     *
     * The linked list is circular. The logic to stop traversal is if the link
     * pointed to by CERT_GetNextGeneralName/CERT_GetPrevGeneralName is the same
     * as the GeneralName the traversal started with.
     */

    if (!arena) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (!src) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    mark = PORT_ArenaMark(arena);

    src_head = src;
    dst_head = cur = NULL;
    do {
        prev = cur;
        if (CERT_CopyGeneralName(arena, &cur, src) != SECSuccess) {
            result = SECFailure;
            goto exit;
        }
        if (dst_head == NULL) { /* first node */
            dst_head = cur;
            prev = cur;
        }

        cur->l.next = &dst_head->l; /* tail node's next points to head */
        cur->l.prev = &prev->l;     /* tail node's prev points to prev */
        dst_head->l.prev = &cur->l; /* head's prev points to tail node */
        prev->l.next = &cur->l;     /* prev node's next point to tail node */

        src = CERT_GetNextGeneralName(src);
    } while (src != src_head);

 exit:
    if (result == SECSuccess) {
        *pdst = dst_head;
        PORT_ArenaUnmark(arena, mark);
    } else {
        *pdst = NULL;
        PORT_ArenaRelease(arena, mark);
    }
    return result;
}

static SECStatus
CERT_CopyCRLDistributionPoint(PRArenaPool *arena, CRLDistributionPoint **pdst, CRLDistributionPoint *src)
{
    SECStatus result = SECSuccess;
    CERTRDN *rdn;
    void *mark = NULL;
    CRLDistributionPoint *dst;
    SECItem tmp_item;

    /*
     * NSS WART
     * There is no public API to create a CRLDistributionPoint or copy it.
     */
    mark = PORT_ArenaMark(arena);

    if ((dst = PORT_ArenaZNew(arena, CRLDistributionPoint)) == NULL) {
        result = SECFailure;
        goto exit;
    }

    switch((dst->distPointType = src->distPointType)) {
    case generalName:
        if ((result = CERT_CopyGeneralNameList(arena,
                                               &dst->distPoint.fullName,
                                               src->distPoint.fullName)) != SECSuccess) {
            goto exit;
        }
        break;
    case relativeDistinguishedName:
        if ((rdn = CERT_CreateRDN(arena, NULL)) == NULL) {
            result = SECFailure;
            goto exit;
        }
        dst->distPoint.relativeName = *rdn;
        if ((result = CERT_CopyRDN(arena,
                                   &dst->distPoint.relativeName,
                                   &src->distPoint.relativeName)) != SECSuccess) {
            goto exit;
        }
        break;
    default:
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        result = SECFailure;
        goto exit;
    }

    if ((result = SECITEM_CopyItem(arena, &dst->reasons, &src->reasons)) != SECSuccess) {
        goto exit;
    }

    /*
     * WARNING: NSS WART
     * src->bitsmap is a SECItem whose length is a bit count and whose data
     * omits the leading DER bitstring "unused" octet.
     */

    tmp_item = src->bitsmap;
    DER_ConvertBitString(&tmp_item); /* make len a byte count */
    if ((result = SECITEM_CopyItem(arena, &dst->bitsmap, &tmp_item)) != SECSuccess) {
        goto exit;
    }
    dst->bitsmap.len = src->bitsmap.len;

    if (src->crlIssuer) {
        if ((result = CERT_CopyGeneralName(arena, &dst->crlIssuer, src->crlIssuer)) != SECSuccess) {
            goto exit;
        }
    }

    /*
     * WARNING: we don't copy these because they're only used during decoding:
     * derDistPoint, derRelativeName, derCrlIssuer, derFullName
     */

 exit:
    if (result == SECSuccess) {
        *pdst = dst;
        PORT_ArenaUnmark(arena, mark);
    } else {
        *pdst = NULL;
        PORT_ArenaRelease(arena, mark);
    }
    return result;
}

/*
 * NSS WART
 * There is no public API to copy a CERTAuthKeyID
 */
static SECStatus
CERT_CopyAuthKeyID(PRArenaPool *arena, CERTAuthKeyID **pdst, CERTAuthKeyID *src)
{
    SECStatus result = SECSuccess;
    void *mark = NULL;
    CERTAuthKeyID *dst;

    mark = PORT_ArenaMark(arena);

    if ((dst = PORT_ArenaZNew(arena, CERTAuthKeyID)) == NULL) {
        result = SECFailure;
        goto exit;
    }

    if ((result = SECITEM_CopyItem(arena, &dst->keyID, &src->keyID)) != SECSuccess) {
        goto exit;
    }

    if ((result = CERT_CopyGeneralNameList(arena, &dst->authCertIssuer,
                                           src->authCertIssuer)) != SECSuccess) {
        goto exit;
    }

    if ((result = SECITEM_CopyItem(arena, &dst->authCertSerialNumber,
                                   &src->authCertSerialNumber)) != SECSuccess) {
        goto exit;
    }

 exit:
    if (result == SECSuccess) {
        *pdst = dst;
        PORT_ArenaUnmark(arena, mark);
    } else {
        *pdst = NULL;
        PORT_ArenaRelease(arena, mark);
    }
    return result;
}

/*
 * NSS WART
 * There is no public API to copy a CERTAuthInfoAccess
 */
static SECStatus
CERT_CopyAuthInfoAccess(PRArenaPool *arena, CERTAuthInfoAccess **pdst, CERTAuthInfoAccess *src)
{
    SECStatus result = SECSuccess;
    void *mark = NULL;
    CERTAuthInfoAccess *dst;

    mark = PORT_ArenaMark(arena);

    if ((dst = PORT_ArenaZNew(arena, CERTAuthInfoAccess)) == NULL) {
        result = SECFailure;
        goto exit;
    }

    if ((result = SECITEM_CopyItem(arena, &dst->method, &src->method)) != SECSuccess) {
        goto exit;
    }

    if ((result = SECITEM_CopyItem(arena, &dst->derLocation, &src->derLocation)) != SECSuccess) {
        goto exit;
    }

    if ((result = CERT_CopyGeneralName(arena, &dst->location, src->location)) != SECSuccess) {
        goto exit;
    }

 exit:
    if (result == SECSuccess) {
        *pdst = dst;
        PORT_ArenaUnmark(arena, mark);
    } else {
        *pdst = NULL;
        PORT_ArenaRelease(arena, mark);
    }
    return result;
}

static int
oid_tag_from_name(const char *name)
{
    PyObject *py_name;
    PyObject *py_lower_name;
    PyObject *py_value;
    int oid_tag;

    if ((py_name = PyString_FromString(name)) == NULL) {
        return -1;
    }

    if ((py_lower_name = PyObject_CallMethod(py_name, "lower", NULL)) == NULL) {
        Py_DECREF(py_name);
        return -1;
    }

    if ((py_value = PyDict_GetItem(sec_oid_name_to_value, py_lower_name)) == NULL) {
	PyErr_Format(PyExc_KeyError, "oid tag name not found: %s", PyString_AsString(py_name));
        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        return -1;
    }

    oid_tag = PyInt_AsLong(py_value);

    Py_DECREF(py_name);
    Py_DECREF(py_lower_name);

    return oid_tag;
}

static PyObject *
oid_tag_name_from_tag(int oid_tag)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyInt_FromLong(oid_tag)) == NULL) {
        return NULL;
    }

    if ((py_name = PyDict_GetItem(sec_oid_value_to_name, py_value)) == NULL) {
	PyErr_Format(PyExc_KeyError, "oid tag not found: %#x", oid_tag);
        Py_DECREF(py_value);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}

static int
get_oid_tag_from_object(PyObject *obj)
{
    int oid_tag = SEC_OID_UNKNOWN;

    if (PyString_Check(obj) || PyUnicode_Check(obj)) {
        PyObject *py_obj_string_utf8 = NULL;
        char *type_string;

        if (PyString_Check(obj)) {
            py_obj_string_utf8 = obj;
            Py_INCREF(py_obj_string_utf8);
        } else {
            py_obj_string_utf8 = PyUnicode_AsUTF8String(obj);
        }

        if ((type_string = PyString_AsString(py_obj_string_utf8)) == NULL) {
            Py_DECREF(py_obj_string_utf8);
            return -1;
        }

        /*
         * First see if it's a canonical name,
         * if not try a dotted-decimal OID,
         * if not then try tag name.
         */
        if ((oid_tag = ava_name_to_oid_tag(type_string)) == SEC_OID_UNKNOWN) {
            if (is_oid_string(type_string)) { /* is dotted-decimal OID */
                SECItem item;

                item.data = NULL;
                item.len = 0;

                /* Convert dotted-decimal OID string to SECItem */
                if (SEC_StringToOID(NULL, &item, type_string, 0) != SECSuccess) {
                    Py_DECREF(py_obj_string_utf8);
                    PyErr_Format(PyExc_ValueError, "failed to convert oid string \"%s\" to SECItem",
                                 type_string);
                    return -1;
                }
                /* Get the OID tag from the SECItem */
                if ((oid_tag = SECOID_FindOIDTag(&item)) == SEC_OID_UNKNOWN) {
                    Py_DECREF(py_obj_string_utf8);
                    SECITEM_FreeItem(&item, PR_FALSE);
                    PyErr_Format(PyExc_ValueError, "could not convert \"%s\" to OID tag", type_string);
                    return -1;
                }
                SECITEM_FreeItem(&item, PR_FALSE);
            } else {
                oid_tag = oid_tag_from_name(type_string);
            }
        }
	Py_DECREF(py_obj_string_utf8);
    } else if (PyInt_Check(obj)) {
        oid_tag = PyInt_AsLong(obj);
    } else if (PySecItem_Check(obj)) {
        oid_tag = SECOID_FindOIDTag(&((SecItem *)obj)->item);
    } else {
        PyErr_Format(PyExc_TypeError, "oid must be a string, an integer, or a SecItem, not %.200s",
                     Py_TYPE(obj)->tp_name);
        return -1;
    }

    return oid_tag;
}

static bool
is_oid_string(const char *oid_string)
{
    const char *p;
    int n_integers, n_dots;

    n_integers = n_dots = 0;
    p = oid_string;
    if (strncasecmp("OID.", p, 4) == 0) p += 4;    /* skip optional OID. prefix */
    while (*p) {
        if (isdigit(*p)) {
            n_integers++;
            for (p++; *p && isdigit(*p); p++); /* consume rest of digits in integer */
        } else if (*p == '.') {                /* found a dot */
            n_dots++;
            p++;
        } else {                               /* not a dot or digit */
            if (isspace(*p)) {                 /* permit trailing white space */
                for (p++; *p && isspace(*p); p++);
                if (!*p) break;
            }
            return false;
        }
    }

    return (n_integers > 0) && (n_integers == n_dots+1);
}

static const char *
ava_oid_tag_to_name(SECOidTag tag)
{
    const DnAvaProps *ava = dn_ava_props;

    for (ava = dn_ava_props;
         ava->oid_tag != tag && ava->oid_tag != SEC_OID_UNKNOWN;
         ava++);

    return (ava->oid_tag != SEC_OID_UNKNOWN) ? ava->name : NULL;
}

static int
ava_oid_tag_to_value_type(SECOidTag tag)
{
    const DnAvaProps *ava = dn_ava_props;

    for (ava = dn_ava_props;
         ava->oid_tag != tag && ava->oid_tag != SEC_OID_UNKNOWN;
         ava++);

    return (ava->oid_tag != SEC_OID_UNKNOWN) ? ava->value_type : SEC_ASN1_UTF8_STRING;
}

/*
 * Given a canonical ava name (e.g. "CN") return the oid tag for it. Case
 * is not significant. If not found SEC_OID_UNKNOWN is returned.
 */
static SECOidTag
ava_name_to_oid_tag(const char *name)
{
    const DnAvaProps *ava = dn_ava_props;

    for (ava = dn_ava_props;
         ava->oid_tag != SEC_OID_UNKNOWN && strcasecmp(ava->name, name);
         ava++);

    return ava->oid_tag;
}

static int
_AddIntConstantWithLookup(PyObject *module, const char *name, long value, const char *prefix,
                          PyObject *name_to_value, PyObject *value_to_name)
{
    PyObject *module_dict;
    PyObject *py_name = NULL;
    PyObject *py_name_sans_prefix = NULL;
    PyObject *py_lower_name = NULL;
    PyObject *py_value = NULL;

    if (!PyModule_Check(module)) {
        PyErr_SetString(PyExc_TypeError, "_AddIntConstantWithLookup() needs module as first arg");
        return -1;
    }

    if ((module_dict = PyModule_GetDict(module)) == NULL) {
        PyErr_Format(PyExc_SystemError, "module '%s' has no __dict__",
                     PyModule_GetName(module));
        return -1;
    }

    if ((py_name = PyString_FromString(name)) == NULL) {
        return -1;
    }

    if ((py_lower_name = PyObject_CallMethod(py_name, "lower", NULL)) == NULL) {
        Py_DECREF(py_name);
        return -1;
    }

    if ((py_value = PyInt_FromLong(value)) == NULL) {
        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        return -1;
    }

    if (PyDict_GetItem(module_dict, py_name)) {
        PyErr_Format(PyExc_SystemError, "module '%s' already contains %s",
                     PyModule_GetName(module), name);

        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        Py_DECREF(py_value);
        return -1;
    }

    if (PyDict_SetItem(module_dict, py_name, py_value) != 0) {
        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        Py_DECREF(py_value);
        return -1;
    }

    if (PyDict_SetItem(value_to_name, py_value, py_name) != 0) {
        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        Py_DECREF(py_value);
        return -1;
    }

    if (PyDict_SetItem(name_to_value, py_lower_name, py_value) != 0) {
        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        Py_DECREF(py_value);
        return -1;
    }

    if (prefix) {
        size_t prefix_len = strlen(prefix);

        if (strlen(name) > prefix_len &&
            strncasecmp(prefix, name, prefix_len) == 0) {

            if ((py_name_sans_prefix = PyString_FromString(PyString_AS_STRING(py_lower_name) + prefix_len)) == NULL) {
                Py_DECREF(py_name);
                Py_DECREF(py_lower_name);
                Py_DECREF(py_value);
                return -1;
            }

            if (PyDict_SetItem(name_to_value, py_name_sans_prefix, py_value) != 0) {
                Py_DECREF(py_name);
                Py_DECREF(py_name_sans_prefix);
                Py_DECREF(py_lower_name);
                Py_DECREF(py_value);
                return -1;
            }
        }
    }

    Py_DECREF(py_name);
    Py_XDECREF(py_name_sans_prefix);
    Py_DECREF(py_lower_name);
    Py_DECREF(py_value);
    return 0;
}

static int
_AddIntConstantAlias(const char *name, long value, PyObject *name_to_value)
{
    PyObject *py_name = NULL;
    PyObject *py_lower_name = NULL;
    PyObject *py_value = NULL;

    if ((py_name = PyString_FromString(name)) == NULL) {
        return -1;
    }

    if ((py_lower_name = PyObject_CallMethod(py_name, "lower", NULL)) == NULL) {
        Py_DECREF(py_name);
        return -1;
    }

    if ((py_value = PyInt_FromLong(value)) == NULL) {
        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        return -1;
    }

    if (PyDict_GetItem(name_to_value, py_name)) {
        PyErr_Format(PyExc_SystemError, "lookup dict already contains %s",
                     name);

        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        Py_DECREF(py_value);
        return -1;
    }

    if (PyDict_SetItem(name_to_value, py_lower_name, py_value) != 0) {
        Py_DECREF(py_name);
        Py_DECREF(py_lower_name);
        Py_DECREF(py_value);
        return -1;
    }


    Py_DECREF(py_name);
    Py_DECREF(py_lower_name);
    Py_DECREF(py_value);
    return 0;
}

/* Set object in thread local storage under name, return 0 for success, -1 on failure */
static int
set_thread_local(const char *name, PyObject *obj)
{
    PyObject *tdict;
    PyObject *thread_local_dict;

    /* Get this threads thread local dict */
    if ((tdict = PyThreadState_GetDict()) == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "cannot get thread state");
        return -1;
    }

    /* Get our (i.e. NSS's) thread local dict */
    if ((thread_local_dict = PyDict_GetItemString(tdict, NSS_THREAD_LOCAL_KEY)) == NULL) {
        /*
         * Our thread local dict does not yet exist so create it
         * and set it in the thread's thread local dict.
         */
        if ((thread_local_dict = PyDict_New()) == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "cannot create thread local data dict");
            return -1;
        }
        if (PyDict_SetItemString(tdict, NSS_THREAD_LOCAL_KEY, thread_local_dict) < 0) {
            Py_DECREF(thread_local_dict);
            PyErr_SetString(PyExc_RuntimeError, "cannot store thread local data dict");
            return -1;
        }
    }

    if (PyDict_SetItemString(thread_local_dict, name, obj) < 0) {
        PyErr_SetString(PyExc_RuntimeError, "cannot store object in thread local data dict");
        return -1;
    }

    return 0;
}

/* Same return behavior as PyDict_GetItem() */
static PyObject *
get_thread_local(const char *name)
{
    PyObject *tdict;
    PyObject *thread_local_dict;

    /* Get this threads thread local dict */
    if ((tdict = PyThreadState_GetDict()) == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "cannot get thread state");
        return NULL;
    }

    /* Get our (i.e. NSS's) thread local dict */
    if ((thread_local_dict = PyDict_GetItemString(tdict, NSS_THREAD_LOCAL_KEY)) == NULL) {
        /*
         * Our thread local dict does not yet exist thus the item can't be
         * in the dict, thus it's not found.
         */
        return NULL;
    }

    return PyDict_GetItemString(thread_local_dict, name);
}


/* Remove named item from thread local storage, return 0 for success, -1 on failure */
static int
del_thread_local(const char *name)
{
    PyObject *tdict;
    PyObject *thread_local_dict;

    /* Get this threads thread local dict */
    if ((tdict = PyThreadState_GetDict()) == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "cannot get thread state");
        return -1;
    }

    /* Get our (i.e. NSS's) thread local dict */
    if ((thread_local_dict = PyDict_GetItemString(tdict, NSS_THREAD_LOCAL_KEY)) == NULL) {
        /*
         * Our thread local dict does not yet exist thus the item can't be
         * in the dict, thus it cannot be deleted, implicit success.
         */
        return 0;
    }

    return PyDict_DelItemString(thread_local_dict, name);
}

static int
PRTimeConvert(PyObject *obj, PRTime *param)
{
    PRTime time;

    if (PyFloat_Check(obj)) {
        LL_D2L(time, PyFloat_AsDouble(obj));
        *param = time;
        return 1;
    }

    if (PyInt_Check(obj)) {
        LL_I2L(time, PyInt_AsLong(obj)); /* FIXME: should be PyLong_AsLongLong? */
        *param = time;
        return 1;
    }

    if (PyNone_Check(obj)) {
        time = PR_Now();
        *param = time;
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be int, float or None, not %.50s",
                 Py_TYPE(obj)->tp_name);
    return 0;
}

// FIXME, should invoke PK11_GetInternalKeySlot(), return PK11SlotInfo *slot;
static int
PK11SlotOrNoneConvert(PyObject *obj, PyObject **param)
{
    if (PyPK11Slot_Check(obj)) {
        *param = obj;
        return 1;
    }

    if (PyNone_Check(obj)) {
        *param = NULL;
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be %.50s or None, not %.50s",
                 PK11SlotType.tp_name, Py_TYPE(obj)->tp_name);
    return 0;
}

static int
SecItemOrNoneConvert(PyObject *obj, PyObject **param)
{
    if (PySecItem_Check(obj)) {
        *param = obj;
        return 1;
    }

    if (PyNone_Check(obj)) {
        *param = NULL;
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be %.50s or None, not %.50s",
                 SecItemType.tp_name, Py_TYPE(obj)->tp_name);
    return 0;
}

static int
CertDBOrNoneConvert(PyObject *obj, PyObject **param)
{
    if (PyCertDB_Check(obj)) {
        *param = obj;
        return 1;
    }

    if (PyNone_Check(obj)) {
        *param = NULL;
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be %.50s or None, not %.50s",
                 SecItemType.tp_name, Py_TYPE(obj)->tp_name);
    return 0;
}

static int
TupleOrNoneConvert(PyObject *obj, PyObject **param)
{
    if (PyTuple_Check(obj)) {
        *param = obj;
        return 1;
    }

    if (PyNone_Check(obj)) {
        *param = NULL;
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be %.50s or None, not %.50s",
                 PyTuple_Type.tp_name, Py_TYPE(obj)->tp_name);
    return 0;
}

static int
SymKeyOrNoneConvert(PyObject *obj, PyObject **param)
{
    if (PySymKey_Check(obj)) {
        *param = obj;
        return 1;
    }

    if (PyNone_Check(obj)) {
        *param = NULL;
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be %.50s or None, not %.50s",
                 PK11SymKeyType.tp_name, Py_TYPE(obj)->tp_name);
    return 0;
}

static int
UTF8OrNoneConvert(PyObject *obj, PyObject **param)
{
    if (!obj) {
        *param = NULL;
        return 1;
    }

    if (PyNone_Check(obj)) {
        *param = NULL;
        return 1;
    }

    if (PyString_Check(obj)) {
        Py_INCREF(obj);
        *param = obj;
        return 1;
    }

    if  (PyUnicode_Check(obj)) {
        if ((*param = PyUnicode_AsUTF8String(obj)) == NULL) {
            return 0;
        }
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be a string or None, not %.200s",
                 Py_TYPE(obj)->tp_name);

    return 0;
}

static const char *
pk11_disabled_reason_str(PK11DisableReasons reason)
{
    static char buf[80];

    switch(reason) {
    case PK11_DIS_NONE:
        return _("no reason");
    case PK11_DIS_USER_SELECTED:
        return _("user disabled");
    case PK11_DIS_COULD_NOT_INIT_TOKEN:
        return _("could not initialize token");
    case PK11_DIS_TOKEN_VERIFY_FAILED:
        return _("could not verify token");
    case PK11_DIS_TOKEN_NOT_PRESENT:
        return _("token not present");
    default:
        snprintf(buf, sizeof(buf), "unknown(%#x)", reason);
        return buf;
    }
}

static const char *
pk11_disabled_reason_name(PK11DisableReasons reason)
{
    static char buf[80];

    switch(reason) {
    case PK11_DIS_NONE:                 return "PK11_DIS_NONE";
    case PK11_DIS_USER_SELECTED:        return "PK11_DIS_USER_SELECTED";
    case PK11_DIS_COULD_NOT_INIT_TOKEN: return "PK11_DIS_COULD_NOT_INIT_TOKEN";
    case PK11_DIS_TOKEN_VERIFY_FAILED:  return "PK11_DIS_TOKEN_VERIFY_FAILED";
    case PK11_DIS_TOKEN_NOT_PRESENT:    return "PK11_DIS_TOKEN_NOT_PRESENT";
    default:
        snprintf(buf, sizeof(buf), "unknown(%#x)", reason);
        return buf;
    }
}

static const char *
key_type_str(KeyType key_type)
{
    static char buf[80];

    switch(key_type) {
    case nullKey:     return "NULL";
    case rsaKey:      return "RSA";
    case dsaKey:      return "DSA";
    case fortezzaKey: return "Fortezza";
    case dhKey:       return "Diffie Helman";
    case keaKey:      return "Key Exchange Algorithm";
    case ecKey:       return "Elliptic Curve";
    default:
        snprintf(buf, sizeof(buf), "unknown(%#x)", key_type);
        return buf;
    }
}


static const char *
oid_tag_str(SECOidTag tag)
{
    static char buf[80];

    SECOidData *oiddata;

    if ((oiddata = SECOID_FindOIDByTag(tag)) != NULL) {
	return oiddata->desc;
    }
    snprintf(buf, sizeof(buf), "unknown(%#x)", tag);
    return buf;
}

static PyObject *
obj_sprintf(const char *fmt, ...)
{
    va_list va;
    Py_ssize_t n_fmts, i;
    PyObject *args = NULL;
    PyObject *obj = NULL;
    PyObject *py_fmt = NULL;
    PyObject *result = NULL;
    const char *s;

    for (s = fmt, n_fmts = 0; *s; s++) {
        if (*s == '%') {
            if (s > fmt) {
                if (s[-1] != '%') {
                    n_fmts++;
                }
            } else {
                n_fmts++;
            }
        }
    }

    if ((args = PyTuple_New(n_fmts)) == NULL) {
        return NULL;
    }

    va_start(va, fmt);
    for (i = 0; i < n_fmts; i++) {
        obj = va_arg(va, PyObject *);
        Py_INCREF(obj);
        PyTuple_SetItem(args, i, obj);
    }
    va_end(va);

    if ((py_fmt = PyString_FromString(fmt)) == NULL) {
        Py_DECREF(args);
        return NULL;
    }

    result = PyString_Format(py_fmt, args);
    Py_DECREF(py_fmt);
    Py_DECREF(args);

    return result;
}

static PyObject *
obj_to_hex(PyObject *obj, int octets_per_line, char *separator)
{
    unsigned char *data = NULL;
    Py_ssize_t data_len;

    if (PyObject_AsReadBuffer(obj, (void *)&data, &data_len))
        return NULL;

    return raw_data_to_hex(data, data_len, octets_per_line, separator);

}

/* see cert_data_to_hex() for documentation */
static PyObject *
raw_data_to_hex(unsigned char *data, int data_len, int octets_per_line, char *separator)
{
    int separator_len = 0;
    char *separator_end = NULL;
    char *src=NULL, *dst=NULL;
    int line_size = 0;
    unsigned char octet = 0;
    int num_lines = 0;
    PyObject *lines = NULL;
    PyObject *line = NULL;
    int line_number, i, j;
    int num_octets = 0;

    if (octets_per_line < 0)
        octets_per_line = 0;

    if (!separator)
        separator = "";

    separator_len = strlen(separator);
    separator_end = separator + separator_len;

    if (octets_per_line == 0) {
        num_octets = data_len;
        line_size = (num_octets * 2) + ((num_octets-1) * separator_len);
        if (line_size < 0) line_size = 0;

        if ((line = PyString_FromStringAndSize(NULL, line_size)) == NULL) {
            return NULL;
        }
        dst = PyString_AS_STRING(line);
        for (i = 0; i < data_len; i++) {
            octet = data[i];
            *dst++ = hex_chars[(octet & 0xF0) >> 4];
            *dst++ = hex_chars[octet & 0xF];
            if (i < data_len-1)
                for (src = separator; src < separator_end; *dst++ = *src++);
        }
        return line;
    } else {
        num_lines = (data_len + octets_per_line - 1) / octets_per_line;
        if (num_lines < 0) num_lines = 0;

        if ((lines = PyList_New(num_lines)) == NULL) {
            return NULL;
        }

        for (i = line_number = 0; i < data_len;) {
            num_octets = data_len - i;
            if (num_octets > octets_per_line) {
                num_octets = octets_per_line;
                line_size = num_octets*(2+separator_len);
            } else {
                line_size = (num_octets * 2) + ((num_octets-1) * separator_len);
            }

            if (line_size < 0) line_size = 0;
            if ((line = PyString_FromStringAndSize(NULL, line_size)) == NULL) {
                Py_DECREF(lines);
                return NULL;
            }
            dst = PyString_AS_STRING(line);
            for (j = 0; j < num_octets && i < data_len; i++, j++) {
                octet = data[i];
                *dst++ = hex_chars[(octet & 0xF0) >> 4];
                *dst++ = hex_chars[octet & 0xF];
                if (i < data_len-1)
                    for (src = separator; src < separator_end; *dst++ = *src++);
            }
            PyList_SetItem(lines, line_number++, line);
        }
        return lines;
    }
}

PyDoc_STRVAR(cert_data_to_hex_doc,
"data_to_hex(data, octets_per_line=0, separator=':') -> string or list of strings\n\
\n\
:Parameters:\n\
    data : buffer\n\
        Binary data\n\
    octets_per_line : integer\n\
        Number of octets formatted on one line, if 0 then\n\
        return a single string instead of an array of lines\n\
    separator : string\n\
        String used to seperate each octet\n\
        If None it will be as if the empty string had been\n\
        passed and no separator will be used.\n\
\n\
Format the binary data as hex string(s).\n\
Either a list of strings is returned or a single string.\n\
\n\
If octets_per_line is greater than zero then a list of\n\
strings will be returned where each string contains\n\
octets_per_line number of octets (except for the last\n\
string in the list which will contain the remainder of the\n\
octets). Returning a list of \"lines\" makes it convenient\n\
for a caller to format a block of hexadecimal data with line\n\
wrapping. If octets_per_line is greater than zero indicating\n\
a list result is desired a list is always returned even if\n\
the number of octets would produce only a single line.\n\
\n\
If octets_per_line is zero then a single string is returned,\n\
(no line splitting is performed). This is the default.\n\
\n\
The separator string is used to separate each octet. If None\n\
it will be as if the empty string had been passed and no\n\
separator will be used.\n\
");

static PyObject *
cert_data_to_hex(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"data", "octets_per_line", "separator", NULL};
    PyObject *obj = NULL;
    int octets_per_line = 0;
    char *separator = HEX_SEPARATOR_DEFAULT;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|iz:cert_data_to_hex", kwlist,
                                     &obj, &octets_per_line, &separator))
        return NULL;

    return obj_to_hex(obj, octets_per_line, separator);
}

PyDoc_STRVAR(read_hex_doc,
"read_hex(input, separators=\" ,:\\t\\n\") -> buffer\n\
\n\
:Parameters:\n\
    input : string\n\
        string containing hexadecimal data\n\
    separators : string or None\n\
        string containing set of separator characters\n\
        Any character encountered during parsing which is in\n\
        this string will be skipped and considered a separator\n\
        between pairs of hexadecimal characters.\n\
\n\
Parse a string containing hexadecimal data and return a buffer\n\
object containing the binary octets. Each octet in the string is\n\
represented as a pair of case insensitive hexadecimal characters\n\
(0123456789abcdef). Each octet must be a pair of\n\
characters. Octets may optionally be preceded by 0x or 0X. Octets\n\
may be separated by separator characters specified in the\n\
separators string. The separators string is a set of\n\
characters. Any character in the separators character set will be\n\
ignored when it occurs between octets. If no separators should be\n\
considered then pass an empty string.\n\
\n\
Using the default separators each of these strings is valid input\n\
representing the same 8 octet sequence:\n\
\n\
01, 23, 45, 67, 89, ab, cd, ef\n\
01, 23, 45, 67, 89, AB, CD, EF\n\
0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef\n\
01:23:45:67:89:ab:cd:ef\n\
0123456789abcdef\n\
01 23 45 67 89 ab cd ef\n\
0x010x230x450x670x890xab0xcd0xef\n\
");
static PyObject *
read_hex(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"input", "separators", NULL};
    const char *input;
    const char *separators = " ,:\t\n";
    size_t input_len, separators_len;
    Py_ssize_t n_octets;
    unsigned char octet, *data;
    const char *src, *input_end;
    const char *sep, *separators_end;
    PyObject *py_out_buf;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|s:read_hex", kwlist,
                                     &input, &separators))
        return NULL;

    input_len = strlen(input);
    src = input;
    input_end = input + input_len;
    separators_len = strlen(separators);
    n_octets = 0;

    /*
     * The maximum number of octets is half the string length
     * because they must occur in pairs. If there are separators
     * in the string then the number of octets will be less than
     * half. Thus len/2 is an upper bound.
     */
    if ((data = PyMem_Malloc(input_len/2)) == NULL) {
        return PyErr_NoMemory();
    }

    separators_end = separators + separators_len;
    while (src < input_end) {
        for (; *src; src++) {
            for (sep = separators; sep < separators_end && *src != *sep; sep++);
            if (sep == separators_end) break;
        }
        if (!*src) break;
        if (src[0] == '0' && (tolower(src[1]) == 'x')) src +=2; /* skip 0x or 0X */
        octet = 0;
        switch (tolower(src[0])) {
        case '0': octet = 0x0 << 4; break;
        case '1': octet = 0x1 << 4; break;
        case '2': octet = 0x2 << 4; break;
        case '3': octet = 0x3 << 4; break;
        case '4': octet = 0x4 << 4; break;
        case '5': octet = 0x5 << 4; break;
        case '6': octet = 0x6 << 4; break;
        case '7': octet = 0x7 << 4; break;
        case '8': octet = 0x8 << 4; break;
        case '9': octet = 0x9 << 4; break;
        case 'a': octet = 0xa << 4; break;
        case 'b': octet = 0xb << 4; break;
        case 'c': octet = 0xc << 4; break;
        case 'd': octet = 0xd << 4; break;
        case 'e': octet = 0xe << 4; break;
        case 'f': octet = 0xf << 4; break;
        default:
            PyMem_Free(data);
            PyErr_Format(PyExc_ValueError, "invalid hexadecimal string beginning at offset %td \"%s\"",
                         src - input, src);
            return NULL;
        }
        switch (tolower(src[1])) {
        case '0': octet |= 0x0; break;
        case '1': octet |= 0x1; break;
        case '2': octet |= 0x2; break;
        case '3': octet |= 0x3; break;
        case '4': octet |= 0x4; break;
        case '5': octet |= 0x5; break;
        case '6': octet |= 0x6; break;
        case '7': octet |= 0x7; break;
        case '8': octet |= 0x8; break;
        case '9': octet |= 0x9; break;
        case 'a': octet |= 0xa; break;
        case 'b': octet |= 0xb; break;
        case 'c': octet |= 0xc; break;
        case 'd': octet |= 0xd; break;
        case 'e': octet |= 0xe; break;
        case 'f': octet |= 0xf; break;
        default:
            PyMem_Free(data);
            PyErr_Format(PyExc_ValueError, "invalid hexadecimal string beginning at offset %td \"%s\"",
                         src - input, src);
            return NULL;
        }
        src += 2;
        data[n_octets++] = octet;
    }

    if ((py_out_buf = PyString_FromStringAndSize((char *)data, n_octets)) == NULL) {
        PyMem_Free(data);
        return NULL;
    }
    PyMem_Free(data);

    return py_out_buf;
}

static SECStatus
sec_strip_tag_and_length(SECItem *item)
{
    unsigned int start;

    if (!item || !item->data || item->len < 2) { /* must be at least tag and length */
        return SECFailure;
    }
    start = ((item->data[1] & 0x80) ? (item->data[1] & 0x7f) + 2 : 2);
    if (item->len < start) {
        return SECFailure;
    }
    item->data += start;
    item->len  -= start;
    return SECSuccess;
}

/* ================== Convert NSS Object to Python String =================== */

static PyObject *
CERTName_to_pystr(CERTName *cert_name)
{
    char *name;
    PyObject *py_name = NULL;

    if (!cert_name) {
        return PyString_FromString("");
    }

    if ((name = CERT_NameToAscii(cert_name)) == NULL) {
        return PyString_FromString("");
    }

    py_name = PyString_FromString(name);
    PORT_Free(name);
    return py_name;
}


static PyObject *
der_context_specific_secitem_to_pystr(SECItem *item)
{
    PyObject *py_str = NULL;
    PyObject *hex_str = NULL;
    int type        = item->data[0] & SEC_ASN1_TAGNUM_MASK;
    int constructed = item->data[0] & SEC_ASN1_CONSTRUCTED;
    SECItem tmp;

    if (constructed) {
        py_str = PyString_FromFormat("[%d]", type);
    } else {
        tmp = *item;
        if (sec_strip_tag_and_length(&tmp) == SECSuccess) {
            if ((hex_str = raw_data_to_hex(tmp.data, tmp.len, 0, HEX_SEPARATOR_DEFAULT))) {
                py_str = PyString_FromFormat("[%d] %s", type, PyString_AsString(hex_str));
                Py_DECREF(hex_str);
            }
        }
        if (!py_str) {
            py_str = PyString_FromFormat("[%d]", type);
        }
    }

    return py_str;
}

static PyObject *
secitem_to_pystr_hex(SECItem *item)
{
    return raw_data_to_hex(item->data, item->len, 0, HEX_SEPARATOR_DEFAULT);
}

static PyObject *
der_any_secitem_to_pystr(SECItem *item)
{
    if (item && item->len && item->data) {
	switch (item->data[0] & SEC_ASN1_CLASS_MASK) {
	case SEC_ASN1_CONTEXT_SPECIFIC:
	    return der_context_specific_secitem_to_pystr(item);
	    break;
	case SEC_ASN1_UNIVERSAL:
	    return der_universal_secitem_to_pystr(item);
	    break;
	default:
	    return raw_data_to_hex(item->data, item->len, 0, HEX_SEPARATOR_DEFAULT);
	}
    }
    return PyString_FromString("(null)");
}


/* return a ASN1 SET or SEQUENCE as a list of strings */
static PyObject *
der_set_or_str_secitem_to_pylist_of_pystr(SECItem *item)
{
    int constructed = item->data[0] & SEC_ASN1_CONSTRUCTED;
    SECItem stripped_item = *item;
    PyObject *py_items = NULL;
    PyObject *py_item = NULL;

    if (!constructed) {
        return raw_data_to_hex(item->data, item->len, 0, HEX_SEPARATOR_DEFAULT);
    }

    if (sec_strip_tag_and_length(&stripped_item) != SECSuccess) {
        Py_RETURN_NONE;
    }

    if ((py_items = PyList_New(0)) == NULL) {
        return NULL;
    }

    while (stripped_item.len >= 2) {
	SECItem  tmp_item = stripped_item;

        if (tmp_item.data[1] & 0x80) {
	    unsigned int i;
	    unsigned int len = tmp_item.data[1] & 0x7f;
	    if (len > sizeof tmp_item.len)
	        break;
	    tmp_item.len = 0;
	    for (i = 0; i < len; i++) {
		tmp_item.len = (tmp_item.len << 8) | tmp_item.data[2+i];
	    }
	    tmp_item.len += len + 2;
	} else {
	    tmp_item.len = tmp_item.data[1] + 2;
	}
	if (tmp_item.len > stripped_item.len) {
	    tmp_item.len = stripped_item.len;
	}
	stripped_item.data += tmp_item.len;
	stripped_item.len  -= tmp_item.len;

        py_item = der_any_secitem_to_pystr(&tmp_item);
        PyList_Append(py_items, py_item);
    }

    return py_items;
}

static PyObject *
boolean_secitem_to_pystr(SECItem *item)
{
    int val = 0;

    if (item->data && item->len) {
	val = item->data[0];
    }

    if (val)
        return PyString_FromString("True");
    else
        return PyString_FromString("False");
}

static PyObject *
der_boolean_secitem_to_pystr(SECItem *item)
{
    PyObject *str = NULL;
    SECItem tmp_item = *item;

    if (sec_strip_tag_and_length(&tmp_item) == SECSuccess)
	str = boolean_secitem_to_pystr(&tmp_item);

    return str;
}

/*
 * Decodes ASN1 integer. Properly handles large magnitude.
 * PyInt object returned if value fits, PyLong object otherwise.
 *
 * item is a decoded ASN1 integer, if the integer is a DER encoded
 * integer with a tag and length then call encoded_integer_secitem_to_pylong
 */
static PyObject *
integer_secitem_to_pylong(SECItem *item)
{
    int len;
    unsigned char *data, octet;
    PyObject *l = NULL;
    PyObject *eight = NULL;
    PyObject *new_bits = NULL;
    PyObject *tmp = NULL;
    bool negative;

    if (!item || !item->len || !item->data) {
        return PyInt_FromLong(0);
    }

    len = item->len;
    data = item->data;
    octet = *data++;
    negative = octet & 0x80;

    if (negative) {
        if ((l = PyInt_FromLong(-1)) == NULL) {
            goto error;
        }
    } else {
        if ((l = PyInt_FromLong(0)) == NULL) {
            goto error;
        }
    }

    if ((eight = PyInt_FromLong(8)) == NULL) {
        return NULL;
    }

    while (1) {
        if ((new_bits = PyInt_FromLong(octet)) == NULL) {
            goto error;
        }

        if ((tmp = PyNumber_Lshift(l, eight)) == NULL) {
            goto error;
        }

        Py_CLEAR(l);

        if ((l = PyNumber_Or(tmp, new_bits)) == NULL) {
            goto error;
        }

        Py_CLEAR(tmp);
        Py_CLEAR(new_bits);

        if (--len) {
            octet = *data++;
        } else {
            goto exit;
        }
    }

 error:
    Py_CLEAR(l);
 exit:
    Py_XDECREF(eight);
    Py_XDECREF(new_bits);
    Py_XDECREF(tmp);
    return l;
}
#if 0
The following can be used to test integer_secitem_to_pylong()
#define ASN1_TEST(octets, expect)                                       \
{                                                                       \
        SECItem item;                                                   \
        PyObject *py_long = NULL;                                       \
        PyObject *py_str = NULL;                                        \
                                                                        \
        item.len = sizeof(octets);                                      \
        item.data = octets;                                             \
                                                                        \
        py_long = integer_secitem_to_pylong(&item);                     \
        py_str = PyObject_Str(py_long);                                 \
        printf("expect %8s got %8s\n", expect, PyString_AsString(py_str)); \
        Py_DECREF(py_long);                                             \
        Py_DECREF(py_str);                                              \
}
{
        unsigned char data1[] = {0x48};       /*     72 */
        unsigned char data2[] = {0x7F};       /*    127 */
        unsigned char data3[] = {0x80};       /*   -128 */
        unsigned char data4[] = {0x00, 0x80}; /*    128 */
        unsigned char data5[] = {0x96, 0x46}; /* -27066 */

        ASN1_TEST(data1, "72");
        ASN1_TEST(data2, "127");
        ASN1_TEST(data3, "-128");
        ASN1_TEST(data4, "128");
        ASN1_TEST(data5, "-27066");

    }
#endif

static PyObject *
integer_secitem_to_pystr(SECItem *item)
{
    PyObject *py_int = NULL;
    PyObject *py_str = NULL;

    if ((py_int = integer_secitem_to_pylong(item)) == NULL) {
        return NULL;
    }

    py_str = PyObject_Str(py_int);

    Py_DECREF(py_int);
    return py_str;
}

static PyObject *
der_integer_secitem_to_pystr(SECItem *item)
{
    PyObject *py_str = NULL;
    SECItem tmp_item = *item;

    if (sec_strip_tag_and_length(&tmp_item) == SECSuccess)
	py_str = integer_secitem_to_pystr(&tmp_item);

    return py_str;
}

static PyObject *
oid_secitem_to_pystr_desc(SECItem *oid)
{
    SECOidData *oiddata;
    char *oid_string = NULL;
    PyObject *py_oid_str = NULL;

    if ((oiddata = SECOID_FindOID(oid)) != NULL) {
	return PyString_FromString(oiddata->desc);
    }
    if ((oid_string = CERT_GetOidString(oid)) != NULL) {
        py_oid_str = PyString_FromString(oid_string);
	PR_smprintf_free(oid_string);
	return py_oid_str;
    }
    return obj_to_hex((PyObject *)oid, 0, HEX_SEPARATOR_DEFAULT);
}

static PyObject *
oid_secitem_to_pyint_tag(SECItem *oid)
{
    SECOidTag oid_tag;

    oid_tag = SECOID_FindOIDTag(oid);
    return PyInt_FromLong(oid_tag);
}

static PyObject *
oid_secitem_to_pystr_dotted_decimal(SECItem *oid)
{
    char *oid_string = NULL;
    PyObject *py_oid_string;

    if ((oid_string = CERT_GetOidString(oid)) == NULL) {
        return PyString_FromString("");
    }
    if ((py_oid_string = PyString_FromString(oid_string)) == NULL) {
        PR_smprintf_free(oid_string);
        return NULL;
    }
    PR_smprintf_free(oid_string);
    return py_oid_string;
}

static PyObject *
der_oid_secitem_to_pystr_desc(SECItem *item)
{
    PyObject *str = NULL;
    SECItem tmp_item = *item;

    if (sec_strip_tag_and_length(&tmp_item) == SECSuccess)
	str = oid_secitem_to_pystr_desc(&tmp_item);

    return str;
}

static PyObject *
der_utc_time_secitem_to_pystr(SECItem *item)
{
    PRTime pr_time = 0;
    PRExplodedTime exploded_time;
    char time_str[100];

    if ((DER_UTCTimeToTime(&pr_time, item) != SECSuccess)) {
        Py_RETURN_NONE;
    }
    PR_ExplodeTime(pr_time, PR_GMTParameters, &exploded_time);
    PR_FormatTime(time_str, sizeof(time_str), time_format, &exploded_time);

    return PyString_FromString(time_str);
}


static PyObject *
der_generalized_time_secitem_to_pystr(SECItem *item)
{
    PRTime pr_time = 0;
    PRExplodedTime exploded_time;
    char time_str[100];

    if ((DER_GeneralizedTimeToTime(&pr_time, item) != SECSuccess)) {
        Py_RETURN_NONE;
    }
    PR_ExplodeTime(pr_time, PR_GMTParameters, &exploded_time);
    PR_FormatTime(time_str, sizeof(time_str), time_format, &exploded_time);

    return PyString_FromString(time_str);
}


static PRTime
time_choice_secitem_to_prtime(SECItem *item)
{
    PRTime pr_time = 0;

    switch (item->type) {
    case siUTCTime:
        DER_UTCTimeToTime(&pr_time, item);
        break;
    case siGeneralizedTime:
        DER_GeneralizedTimeToTime(&pr_time, item);
        break;
    default:
        PyErr_SetString(PyExc_ValueError, "unknown sec ANS.1 time type");
    }
    return pr_time;
}

static PyObject *
time_choice_secitem_to_pystr(SECItem *item)
{
    PRTime pr_time = 0;
    PRExplodedTime exploded_time;
    char time_str[100];

    pr_time = time_choice_secitem_to_prtime(item);
    PR_ExplodeTime(pr_time, PR_GMTParameters, &exploded_time);
    PR_FormatTime(time_str, sizeof(time_str), time_format, &exploded_time);

    return PyString_FromString(time_str);
}

static PyObject *
der_octet_secitem_to_pystr(SECItem *item, int octets_per_line, char *separator)
{
    PyObject *str = NULL;
    SECItem tmp_item = *item;

    if (sec_strip_tag_and_length(&tmp_item) == SECSuccess)
        str = raw_data_to_hex(tmp_item.data, tmp_item.len, octets_per_line, separator);

    return str;
}

static PyObject *
der_bit_string_secitem_to_pystr(SECItem *item)
{
    PyObject *str = NULL;
    SECItem tmp_item = *item;
    int unused_bits;

    if (sec_strip_tag_and_length(&tmp_item) != SECSuccess || tmp_item.len < 2) {
        Py_RETURN_NONE;
    }

    unused_bits = *tmp_item.data++;
    tmp_item.len--;

    str = raw_data_to_hex(tmp_item.data, tmp_item.len, 0, HEX_SEPARATOR_DEFAULT);

    if (unused_bits) {
	PyString_ConcatAndDel(&str, PyString_FromFormat("(%d least significant bits unused)", unused_bits));
    }

    return str;
}

static PyObject *
ascii_string_secitem_to_escaped_ascii_pystr(SECItem *item)
{
    PyObject *py_str = NULL;
    size_t escaped_len;
    const unsigned char *s; /* must be unsigned for table indexing to work */
    char *escaped_str, *dst, *src;
    AsciiEscapes *encode;
    unsigned int len;

    escaped_len = ascii_encoded_strnlen((const char *)item->data, item->len);

    if ((py_str = PyString_FromStringAndSize(NULL, escaped_len)) == NULL) {
        return NULL;
    }

    escaped_str = PyString_AS_STRING(py_str);

    for (s = (unsigned char *)item->data, len = item->len, dst = escaped_str;
         len;
         s++, len--) {
        encode = &ascii_encoding_table[*s];
        for (src = encode->encoded; *src; src++) {
            *dst++ = *src;
        }
    }

    *dst = 0;                   /* shouldn't be necessary, PyString's are always NULL terminated */

    return py_str;
}

static PyObject *
der_ascii_string_secitem_to_escaped_ascii_pystr(SECItem *item)
{
    SECItem tmp_item = *item;

    if (sec_strip_tag_and_length(&tmp_item) != SECSuccess) {
        PyErr_SetString(PyExc_ValueError, "malformed raw ascii string buffer");
        return NULL;
    }

    return ascii_string_secitem_to_escaped_ascii_pystr(&tmp_item);
}

static PyObject *
der_utf8_string_secitem_to_pyunicode(SECItem *item)
{
    SECItem tmp_item = *item;

    if (sec_strip_tag_and_length(&tmp_item) != SECSuccess) {
        PyErr_SetString(PyExc_ValueError, "malformed raw ASN.1 BMP string buffer");
        return NULL;
    }

    return PyUnicode_DecodeUTF8((const char *)tmp_item.data, tmp_item.len, NULL);
}


static PyObject *
der_bmp_string_secitem_to_pyunicode(SECItem *item)
{
    SECItem tmp_item = *item;
    int byte_order = 1;         /* 1 = big endian, asn.1 DER is always big endian */

    if (sec_strip_tag_and_length(&tmp_item) != SECSuccess) {
        PyErr_SetString(PyExc_ValueError, "malformed raw ASN.1 BMP string buffer");
        return NULL;
    }

    if (tmp_item.len % 2) {
        PyErr_SetString(PyExc_ValueError, "raw ASN.1 BMP string length must be multiple of 2");
        return NULL;
    }

    return PyUnicode_DecodeUTF16((const char *)tmp_item.data, tmp_item.len,
                                 NULL, &byte_order);
}


static PyObject *
der_universal_string_secitem_to_pyunicode(SECItem *item)
{
    SECItem tmp_item = *item;
    int byte_order = 1;         /* 1 = big endian, asn.1 DER is always big endian */

    if (sec_strip_tag_and_length(&tmp_item) != SECSuccess) {
        PyErr_SetString(PyExc_ValueError, "malformed raw ASN.1 Universal string buffer");
        return NULL;
    }

    if (tmp_item.len % 4) {
        PyErr_SetString(PyExc_ValueError, "raw ASN.1 Universal string length must be multiple of 4");
        return NULL;
    }

    return PyUnicode_DecodeUTF32((const char *)tmp_item.data, tmp_item.len,
                                 NULL, &byte_order);
}

static PyObject *
der_universal_secitem_to_pystr(SECItem *item)
{
    switch (item->data[0] & SEC_ASN1_TAGNUM_MASK) {
    case SEC_ASN1_ENUMERATED:
    case SEC_ASN1_INTEGER:
        return der_integer_secitem_to_pystr(item);
    case SEC_ASN1_OBJECT_ID:
        return der_oid_secitem_to_pystr_desc(item);
    case SEC_ASN1_BOOLEAN:
        return der_boolean_secitem_to_pystr(item);
    case SEC_ASN1_UTF8_STRING:
        return der_utf8_string_secitem_to_pyunicode(item);
    case SEC_ASN1_PRINTABLE_STRING:
    case SEC_ASN1_VISIBLE_STRING:
    case SEC_ASN1_IA5_STRING:
    case SEC_ASN1_T61_STRING:
        return der_ascii_string_secitem_to_escaped_ascii_pystr(item);
    case SEC_ASN1_GENERALIZED_TIME:
        return der_generalized_time_secitem_to_pystr(item);
    case SEC_ASN1_UTC_TIME:
        return der_utc_time_secitem_to_pystr(item);
    case SEC_ASN1_NULL:
        return PyString_FromString("(null)");
    case SEC_ASN1_SET:
    case SEC_ASN1_SEQUENCE:
        return der_set_or_str_secitem_to_pylist_of_pystr(item);
    case SEC_ASN1_OCTET_STRING:
        return der_octet_secitem_to_pystr(item, 0, HEX_SEPARATOR_DEFAULT);
    case SEC_ASN1_BIT_STRING:
        der_bit_string_secitem_to_pystr(item);
        break;
    case SEC_ASN1_BMP_STRING:
        return der_bmp_string_secitem_to_pyunicode(item);
    case SEC_ASN1_UNIVERSAL_STRING:
        return der_universal_string_secitem_to_pyunicode(item);
    default:
        return raw_data_to_hex(item->data, item->len, 0, HEX_SEPARATOR_DEFAULT);
    }
    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_der_universal_secitem_fmt_lines_doc,
"der_universal_secitem_fmt_lines(sec_item, level=0, octets_per_line=0, separator=':') -> list of (indent, string) tuples\n\
\n\
:Parameters:\n\
    sec_item : SecItem object\n\
        A SecItem containing a DER encoded ASN1 universal type\n\
    level : integer\n\
        Initial indentation level, all subsequent indents are relative\n\
        to this starting level.\n\
    octets_per_line : integer\n\
        Number of octets formatted on one line, if 0 then\n\
        return a single string instead of an array of lines\n\
    separator : string\n\
        String used to seperate each octet\n\
        If None it will be as if the empty string had been\n\
        passed and no separator will be used.\n\
\n\
Given a SecItem in DER format which encodes a ASN.1 universal\n\
type convert the item to a string and return a list of\n\
(indent, string) tuples.\n\
");
static PyObject *
cert_der_universal_secitem_fmt_lines(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", "octets_per_line", "separator", NULL};
    SecItem *py_sec_item = NULL;
    int level = 0;
    int octets_per_line = OCTETS_PER_LINE_DEFAULT;
    char *hex_separator = HEX_SEPARATOR_DEFAULT;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    SECItem *item = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|iiz:der_universal_secitem_fmt_lines", kwlist,
                                     &SecItemType, &py_sec_item,
                                     &level, &octets_per_line, &hex_separator))
        return NULL;

    item = &py_sec_item->item;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    switch (item->data[0] & SEC_ASN1_TAGNUM_MASK) {
    case SEC_ASN1_ENUMERATED:
    case SEC_ASN1_INTEGER:
        obj = der_integer_secitem_to_pystr(item);
        break;
    case SEC_ASN1_OBJECT_ID:
        obj = der_oid_secitem_to_pystr_desc(item);
        break;
    case SEC_ASN1_BOOLEAN:
        obj = der_boolean_secitem_to_pystr(item);
        break;
    case SEC_ASN1_UTF8_STRING:
        obj = der_utf8_string_secitem_to_pyunicode(item);
        break;
    case SEC_ASN1_PRINTABLE_STRING:
    case SEC_ASN1_VISIBLE_STRING:
    case SEC_ASN1_IA5_STRING:
    case SEC_ASN1_T61_STRING:
        obj = der_ascii_string_secitem_to_escaped_ascii_pystr(item);
        break;
    case SEC_ASN1_GENERALIZED_TIME:
        obj = der_generalized_time_secitem_to_pystr(item);
        break;
    case SEC_ASN1_UTC_TIME:
        obj = der_utc_time_secitem_to_pystr(item);
        break;
    case SEC_ASN1_NULL:
        obj = PyString_FromString("(null)");
        break;
    case SEC_ASN1_SET:
    case SEC_ASN1_SEQUENCE:
        obj = der_set_or_str_secitem_to_pylist_of_pystr(item);
        break;
    case SEC_ASN1_OCTET_STRING:
        obj = der_octet_secitem_to_pystr(item, octets_per_line, hex_separator);
        break;
    case SEC_ASN1_BIT_STRING:
        der_bit_string_secitem_to_pystr(item);
        break;
    case SEC_ASN1_BMP_STRING:
        obj = der_bmp_string_secitem_to_pyunicode(item);
        break;
    case SEC_ASN1_UNIVERSAL_STRING:
        obj = der_universal_string_secitem_to_pyunicode(item);
        break;
    default:
        obj = raw_data_to_hex(item->data, item->len, octets_per_line, hex_separator);
        break;
    }

    if (obj) {
        if (PyList_Check(obj)) {
            APPEND_LINES_AND_CLEAR(lines, obj, level, fail);
        } else {
            FMT_OBJ_AND_APPEND(lines, NULL, obj, level, fail);
        }
    }

    return lines;

 fail:
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
secitem_integer_format_lines(SECItem *item, int level)
{
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *obj1 = NULL;
    PyObject *obj_lines = NULL;

    TraceMethodEnter(NULL);

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if (item->len > 8) {
        if ((obj_lines = SECItem_to_hex(item, OCTETS_PER_LINE_DEFAULT, HEX_SEPARATOR_DEFAULT)) == NULL) {
            goto fail;
        }
        APPEND_LINES_AND_CLEAR(lines, obj_lines, level, fail);
    } else {
        if ((obj = integer_secitem_to_pylong(item)) == NULL) {
            goto fail;
        }
        if ((obj1 = obj_sprintf("%d (%#x)", obj, obj)) == NULL) {
            goto fail;
        }
        Py_CLEAR(obj);
        FMT_OBJ_AND_APPEND(lines, NULL, obj1, level, fail);
        Py_CLEAR(obj1);
    }

    return lines;

 fail:
    Py_XDECREF(obj_lines);
    Py_XDECREF(obj);
    Py_XDECREF(obj1);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
fingerprint_format_lines(SECItem *item, int level)
{
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(NULL);

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    FMT_LABEL_AND_APPEND(lines, _("Fingerprint (MD5)"), level, fail);
    if ((obj = PyString_FromStringAndSize(NULL, MD5_LENGTH)) == NULL) {
        goto fail;
    }
    if (PK11_HashBuf(SEC_OID_MD5, (unsigned char *)PyString_AsString(obj),
                     item->data, item->len) != SECSuccess) {
        set_nspr_error(NULL);
    }
    APPEND_OBJ_TO_HEX_LINES_AND_CLEAR(lines, obj, level+1, fail);

    FMT_LABEL_AND_APPEND(lines, _("Fingerprint (SHA1)"), level, fail);
    if ((obj = PyString_FromStringAndSize(NULL, SHA1_LENGTH)) == NULL) {
        goto fail;
    }
    if (PK11_HashBuf(SEC_OID_SHA1, (unsigned char *)PyString_AsString(obj),
                     item->data, item->len) != SECSuccess) {
        set_nspr_error(NULL);
    }
    APPEND_OBJ_TO_HEX_LINES_AND_CLEAR(lines, obj, level+1, fail);

    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
CERTGeneralName_type_string_to_pystr(CERTGeneralName *general_name)
{

    switch(general_name->type) {
    case certOtherName: {
        PyObject *py_oid = oid_secitem_to_pystr_desc(&general_name->name.OthName.oid);
        if (py_oid) {
            PyObject *result = PyString_FromFormat(_("Other Name (%s)"), PyString_AS_STRING(py_oid));
            Py_DECREF(py_oid);
            return result;
        } else {
            return PyString_FromString(_("Other Name"));
        }
    }
    case certRFC822Name:
        return PyString_FromString(_("RFC822 Name"));
    case certDNSName:
        return PyString_FromString(_("DNS name"));
    case certX400Address:
        return PyString_FromString(_("X400 Address"));
    case certDirectoryName:
        return PyString_FromString(_("Directory Name"));
    case certEDIPartyName:
        return PyString_FromString(_("EDI Party"));
    case certURI:
        return PyString_FromString(_("URI"));
    case certIPAddress:
        return PyString_FromString(_("IP Address"));
    case certRegisterID:
        return PyString_FromString(_("Registered ID"));
    default:
	return PyString_FromFormat(_("unknown type [%d]"), (int)general_name->type - 1);
    }
}

static PyObject *
CERTGeneralName_to_pystr(CERTGeneralName *general_name)
{
    switch(general_name->type) {
    case certOtherName:
        return der_any_secitem_to_pystr(&general_name->name.OthName.name);
    case certRFC822Name:
        return ascii_string_secitem_to_escaped_ascii_pystr(&general_name->name.other);
    case certDNSName:
        return ascii_string_secitem_to_escaped_ascii_pystr(&general_name->name.other);
    case certX400Address:
        return der_any_secitem_to_pystr(&general_name->name.other);
    case certDirectoryName:
        return CERTName_to_pystr(&general_name->name.directoryName);
    case certEDIPartyName:
        return der_any_secitem_to_pystr(&general_name->name.other);
    case certURI:
        return ascii_string_secitem_to_escaped_ascii_pystr(&general_name->name.other);
    case certIPAddress:
        return ip_addr_secitem_to_pystr(&general_name->name.other);
    case certRegisterID:
        return oid_secitem_to_pystr_desc(&general_name->name.other);
    default:
        PyErr_Format(PyExc_ValueError, _("unknown type [%d]"), (int)general_name->type - 1);
        return NULL;

    }
}

static PyObject *
CERTGeneralName_to_pystr_with_label(CERTGeneralName *general_name)
{
    PyObject *py_label = NULL;
    PyObject *py_value = NULL;
    PyObject *result = NULL;

    if (!general_name) {
        return NULL;
    }

    py_label = CERTGeneralName_type_string_to_pystr(general_name);
    py_value = CERTGeneralName_to_pystr(general_name);

    if (py_label && py_value) {
        result = PyString_FromFormat("%s: %s",
                                     PyString_AS_STRING(py_label),
                                     PyString_AS_STRING(py_value));
    } else if (py_value) {
        Py_INCREF(py_value);
        result = py_value;
    }

    Py_XDECREF(py_label);
    Py_XDECREF(py_value);

    return result;
}

static PyObject *
CERTAVA_value_to_pystr(CERTAVA *ava)
{
    PyObject *result = NULL;
    SECOidTag oid_tag;
    const char *attr_name;
    char *oid_name;
    char value_buf[1024];
    SECItem *value_item;

    if (!ava) {
        return PyString_FromString("");
    }

    value_buf[0] = 0;
    attr_name = NULL;
    oid_name = NULL;

    /*
     * Get the AVA's attribute name (e.g. type) as a string.  If we
     * can't get the canonical name use a dotted-decimal OID
     * representation instead.
     */
    if ((oid_tag = CERT_GetAVATag(ava)) != -1) {
        attr_name = ava_oid_tag_to_name(oid_tag);
    }

    if (attr_name == NULL) {
        if ((oid_name = CERT_GetOidString(&ava->type)) == NULL) {
            return set_nspr_error("cannot convert AVA type to OID string");
        }
    }

    /* Get the AVA's attribute value as a string */
    if ((value_item = CERT_DecodeAVAValue(&ava->value)) == NULL) {
        if (oid_name) PR_smprintf_free(oid_name);
        return set_nspr_error("unable to decode AVA value");
    }
    if (CERT_RFC1485_EscapeAndQuote(value_buf, sizeof(value_buf),
                                    (char *)value_item->data,
                                    value_item->len) != SECSuccess) {
        if (oid_name) PR_smprintf_free(oid_name);
        SECITEM_FreeItem(value_item, PR_TRUE);
        return set_nspr_error("unable to escape AVA value string");
    }
    SECITEM_FreeItem(value_item, PR_TRUE);

    /* Format "name=value" */
    if ((result = PyString_FromFormat("%s=%s",
                                      attr_name ? attr_name : oid_name,
                                      value_buf)) == NULL) {
        if (oid_name) PR_smprintf_free(oid_name);
        return NULL;
    }

    if (oid_name) PR_smprintf_free(oid_name);

    return result;
}

static PyObject *
CERTRDN_to_pystr(CERTRDN *rdn)
{
    PyObject *result = NULL;
    CERTAVA **avas, *ava;
    SECOidTag oid_tag;
    const char *attr_name;
    char *oid_name;
    bool first;
    char value_buf[1024];
    SECItem *value_item;

    if (!rdn || !(avas = rdn->avas) || *avas == NULL) {
        return PyString_FromString("");
    }

    first = true;
    while ((ava = *avas++) != NULL) {
        value_buf[0] = 0;
        attr_name = NULL;
        oid_name = NULL;

        /*
         * Get the AVA's attribute name (e.g. type) as a string.  If we
         * can't get the canonical name use a dotted-decimal OID
         * representation instead.
         */
        if ((oid_tag = CERT_GetAVATag(ava)) != -1) {
            attr_name = ava_oid_tag_to_name(oid_tag);
        }

        if (attr_name == NULL) {
            if ((oid_name = CERT_GetOidString(&ava->type)) == NULL) {
                return set_nspr_error("cannot convert AVA type to OID string");
            }
        }

        /* Get the AVA's attribute value as a string */
        if ((value_item = CERT_DecodeAVAValue(&ava->value)) == NULL) {
            if (oid_name) PR_smprintf_free(oid_name);
            return set_nspr_error("unable to decode AVA value");
        }
        if (CERT_RFC1485_EscapeAndQuote(value_buf, sizeof(value_buf),
                                        (char *)value_item->data,
                                        value_item->len) != SECSuccess) {
            if (oid_name) PR_smprintf_free(oid_name);
            SECITEM_FreeItem(value_item, PR_TRUE);
            return set_nspr_error("unable to escape AVA value string");
        }
        SECITEM_FreeItem(value_item, PR_TRUE);

        /*
         * Format "name=value", if there is more than one AVA join them
         * together with a "+". Typically there is only one AVA.
         */
        if (first) {
            if ((result = PyString_FromFormat("%s=%s",
                                              attr_name ? attr_name : oid_name,
                                              value_buf)) == NULL) {
                if (oid_name) PR_smprintf_free(oid_name);
                return NULL;
            }
        } else {
            PyObject *temp;

            if ((temp = PyString_FromFormat("+%s=%s",
                                            attr_name ? attr_name : oid_name,
                                            value_buf)) == NULL) {
                if (oid_name) PR_smprintf_free(oid_name);
                return NULL;
            }
            PyString_ConcatAndDel(&result, temp);
            if (result == NULL) {
                if (oid_name) PR_smprintf_free(oid_name);
                return NULL;
            }
        }

        if (oid_name) PR_smprintf_free(oid_name);
        first = false;
    }
    return result;
}

static PyObject *
cert_trust_flags(unsigned int flags, RepresentationKind repr_kind)
{
    BIT_FLAGS_TO_LIST_PROLOGUE();

#if (NSS_VMAJOR > 3) || (NSS_VMAJOR == 3 && NSS_VMINOR >= 13)
    BIT_FLAGS_TO_LIST(CERTDB_TERMINAL_RECORD,   _("Terminal Record"));
#else
    BIT_FLAGS_TO_LIST(CERTDB_VALID_PEER,        _("Valid Peer"));
#endif
    BIT_FLAGS_TO_LIST(CERTDB_TRUSTED,           _("Trusted"));
    BIT_FLAGS_TO_LIST(CERTDB_SEND_WARN,         _("Warn When Sending"));
    BIT_FLAGS_TO_LIST(CERTDB_VALID_CA,          _("Valid CA"));
    BIT_FLAGS_TO_LIST(CERTDB_TRUSTED_CA,        _("Trusted CA"));
    BIT_FLAGS_TO_LIST(CERTDB_NS_TRUSTED_CA,     _("Netscape Trusted CA"));
    BIT_FLAGS_TO_LIST(CERTDB_USER,              _("User"));
    BIT_FLAGS_TO_LIST(CERTDB_TRUSTED_CLIENT_CA, _("Trusted Client CA"));
    BIT_FLAGS_TO_LIST(CERTDB_GOVT_APPROVED_CA,  _("Step-up"));

    BIT_FLAGS_TO_LIST_EPILOGUE();
}

static PyObject *
cert_usage_flags(unsigned int flags, RepresentationKind repr_kind)
{
    BIT_FLAGS_TO_LIST_PROLOGUE();

    BIT_FLAGS_TO_LIST(certificateUsageSSLClient,             _("SSL Client"));
    BIT_FLAGS_TO_LIST(certificateUsageSSLServer,             _("SSL Server"));
    BIT_FLAGS_TO_LIST(certificateUsageSSLServerWithStepUp,   _("SSL Server With StepUp"));
    BIT_FLAGS_TO_LIST(certificateUsageSSLCA,                 _("SSL CA"));
    BIT_FLAGS_TO_LIST(certificateUsageEmailSigner,           _("Email Signer"));
    BIT_FLAGS_TO_LIST(certificateUsageEmailRecipient,        _("Email Recipient"));
    BIT_FLAGS_TO_LIST(certificateUsageObjectSigner,          _("Object Signer"));
    BIT_FLAGS_TO_LIST(certificateUsageUserCertImport,        _("User Certificate Import"));
    BIT_FLAGS_TO_LIST(certificateUsageVerifyCA,              _("Verify CA"));
    BIT_FLAGS_TO_LIST(certificateUsageProtectedObjectSigner, _("Protected Object Signer"));
    BIT_FLAGS_TO_LIST(certificateUsageStatusResponder,       _("Status Responder"));
    BIT_FLAGS_TO_LIST(certificateUsageAnyCA,                 _("Any CA"));

    BIT_FLAGS_TO_LIST_EPILOGUE();
}

static PyObject *
key_usage_flags(unsigned int flags, RepresentationKind repr_kind)
{
    BIT_FLAGS_TO_LIST_PROLOGUE();

    BIT_FLAGS_TO_LIST(KU_DIGITAL_SIGNATURE, _("Digital Signature"));
    BIT_FLAGS_TO_LIST(KU_NON_REPUDIATION,   _("Non-Repudiation"));
    BIT_FLAGS_TO_LIST(KU_KEY_ENCIPHERMENT,  _("Key Encipherment"));
    BIT_FLAGS_TO_LIST(KU_DATA_ENCIPHERMENT, _("Data Encipherment"));
    BIT_FLAGS_TO_LIST(KU_KEY_AGREEMENT,     _("Key Agreement"));
    BIT_FLAGS_TO_LIST(KU_KEY_CERT_SIGN,     _("Certificate Signing"));
    BIT_FLAGS_TO_LIST(KU_CRL_SIGN,          _("CRL Signing"));
    BIT_FLAGS_TO_LIST(KU_ENCIPHER_ONLY,     _("Encipher Only"));
#ifdef KU_DECIPHER_ONLY
    BIT_FLAGS_TO_LIST(KU_DECIPHER_ONLY,     _("Decipher Only"));
#endif
    /*
     * The following flags are not present in certs but appear in
     * CERTVerifyNode when the error is
     * SEC_ERROR_INADEQUATE_KEY_USAGE. This rountine is also used
     * to print those flags.
     */
    BIT_FLAGS_TO_LIST(KU_DIGITAL_SIGNATURE_OR_NON_REPUDIATION, _("Digital Signature or Non-Repudiation"));
    BIT_FLAGS_TO_LIST(KU_KEY_AGREEMENT_OR_ENCIPHERMENT,        _("Key Agreement or Data Encipherment"));
    BIT_FLAGS_TO_LIST(KU_NS_GOVT_APPROVED,                     _("Government Approved"));

    BIT_FLAGS_TO_LIST_EPILOGUE();
}

static PyObject *
cert_type_flags(unsigned int flags, RepresentationKind repr_kind)
{
    BIT_FLAGS_TO_LIST_PROLOGUE();

    BIT_FLAGS_TO_LIST(NS_CERT_TYPE_SSL_CLIENT,        _("SSL Client"));
    BIT_FLAGS_TO_LIST(NS_CERT_TYPE_SSL_SERVER,        _("SSL Server"));
    BIT_FLAGS_TO_LIST(NS_CERT_TYPE_EMAIL,             _("Email"));
    BIT_FLAGS_TO_LIST(NS_CERT_TYPE_OBJECT_SIGNING,    _("Object Signing"));
    BIT_FLAGS_TO_LIST(NS_CERT_TYPE_RESERVED,          _("Reserved"));
    BIT_FLAGS_TO_LIST(NS_CERT_TYPE_SSL_CA,            _("SSL CA"));
    BIT_FLAGS_TO_LIST(NS_CERT_TYPE_EMAIL_CA,          _("Email CA"));
    BIT_FLAGS_TO_LIST(NS_CERT_TYPE_OBJECT_SIGNING_CA, _("Object Signing CA"));
    /*
     * The following flags are not actual cert types but they get
     * OR'ed into a cert type bitmask.
     */
   BIT_FLAGS_TO_LIST(EXT_KEY_USAGE_TIME_STAMP,        _("Key Usage Timestamp"));
   BIT_FLAGS_TO_LIST(EXT_KEY_USAGE_STATUS_RESPONDER,  _("Key Usage Status Responder"));

   BIT_FLAGS_TO_LIST_EPILOGUE();
}

static PyObject *
nss_init_flags(unsigned int flags, RepresentationKind repr_kind)
{
    BIT_FLAGS_TO_LIST_PROLOGUE();

    BIT_FLAGS_TO_LIST(NSS_INIT_READONLY,       _("Read Only"));
    BIT_FLAGS_TO_LIST(NSS_INIT_NOCERTDB,       _("No Certificate Database"));
    BIT_FLAGS_TO_LIST(NSS_INIT_NOMODDB,        _("No Module Database"));
    BIT_FLAGS_TO_LIST(NSS_INIT_FORCEOPEN,      _("Force Open"));
    BIT_FLAGS_TO_LIST(NSS_INIT_NOROOTINIT,     _("No Root Init"));
    BIT_FLAGS_TO_LIST(NSS_INIT_OPTIMIZESPACE,  _("Optimize Space"));
    BIT_FLAGS_TO_LIST(NSS_INIT_PK11THREADSAFE, _("PK11 Thread Safe"));
    BIT_FLAGS_TO_LIST(NSS_INIT_PK11RELOAD,     _("PK11 Reload"));
    BIT_FLAGS_TO_LIST(NSS_INIT_NOPK11FINALIZE, _("No PK11 Finalize"));
    BIT_FLAGS_TO_LIST(NSS_INIT_RESERVED,       _("Reserved"));

    BIT_FLAGS_TO_LIST_EPILOGUE();
}


static PyObject *
ip_addr_secitem_to_pystr(SECItem *item)
{
    PRNetAddr  addr;
    char buf[1024];

    memset(&addr, 0, sizeof(addr));
    if (item->len == 4) {
	addr.inet.family = PR_AF_INET;
	memcpy(&addr.inet.ip, item->data, item->len);
    } else if (item->len == 16) {
	addr.ipv6.family = PR_AF_INET6;
	memcpy(addr.ipv6.ip.pr_s6_addr, item->data, item->len);
	if (PR_IsNetAddrType(&addr, PR_IpAddrV4Mapped)) {
	    /* convert to IPv4.  */
	    addr.inet.family = PR_AF_INET;
	    memcpy(&addr.inet.ip, &addr.ipv6.ip.pr_s6_addr[12], 4);
	    memset(&addr.inet.pad[0], 0, sizeof addr.inet.pad);
	}
    } else {
        return secitem_to_pystr_hex(item);
    }

    if (PR_NetAddrToString(&addr, buf, sizeof(buf)) != PR_SUCCESS) {
        return secitem_to_pystr_hex(item);
    }

    return PyString_FromString(buf);
}

static PyObject *
SECItem_to_hex(SECItem *item, int octets_per_line, char *separator)
{
    return raw_data_to_hex(item->data, item->len, octets_per_line, separator);
}

static PyObject *
SECItem_der_to_hex(SECItem *item, int octets_per_line, char *separator)
{
    SECItem tmp_item = *item;

    if (sec_strip_tag_and_length(&tmp_item) != SECSuccess) {
        PyErr_SetString(PyExc_ValueError, "malformed ASN.1 DER data");
        return NULL;
    }

    return raw_data_to_hex(tmp_item.data, tmp_item.len, octets_per_line, separator);
}

/* ========================================================================== */
/* =============================== SecItem Class ============================ */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
SecItem_get_type(SecItem *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->item.type);
}

static PyObject *
SecItem_get_len(SecItem *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->item.len);
}

static PyObject *
SecItem_get_data(SecItem *self, void *closure)
{
    TraceMethodEnter(self);

    return PyString_FromStringAndSize((const char *)self->item.data, self->item.len);
}

static
PyGetSetDef SecItem_getseters[] = {
    {"type",       (getter)SecItem_get_type,    (setter)NULL,
     "the SecItem type (si* constant)", NULL},
    {"len",        (getter)SecItem_get_len,     (setter)NULL,
     "number of octets in SecItem buffer", NULL},
    {"data",       (getter)SecItem_get_data,    (setter)NULL,
     "contents of SecItem buffer", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef SecItem_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(SecItem_get_oid_sequence_doc,
"get_oid_sequence(repr_kind=AsString) -> (obj, ...)\n\
\n\
:Parameters:\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsObject\n\
            Each extended key usage will be a SecItem object embedding\n\
            the OID in DER format.\n\
        AsString\n\
            Each extended key usage will be a descriptive string.\n\
            (e.g. \"TLS Web Server Authentication Certificate\")\n\
        AsDottedDecimal\n\
            Each extended key usage will be OID rendered as a dotted decimal string.\n\
            (e.g. \"OID.1.3.6.1.5.5.7.3.1\")\n\
        AsEnum\n\
            Each extended key usage will be OID tag enumeration constant (int).\n\
            (e.g. nss.SEC_OID_EXT_KEY_USAGE_SERVER_AUTH)\n\
\n\
Return a tuple of OID's according the representation kind.\n\
");
static PyObject *
SecItem_get_oid_sequence(SecItem *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"repr_kind", NULL};
    int repr_kind = AsString;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:get_oid_sequence", kwlist,
                                     &repr_kind))
        return NULL;

    return decode_oid_sequence_to_tuple(&self->item, repr_kind);
}

PyDoc_STRVAR(SecItem_get_integer_doc,
"get_integer() -> int or long\n\
\n\
If the SecItem contains an ASN.1 integer in DER format return\n\
a Python integer (or long)\n\
");
static PyObject *
SecItem_get_integer(SecItem *self, PyObject *args)
{
    return integer_secitem_to_pylong(&self->item);
}

PyDoc_STRVAR(SecItem_to_hex_doc,
"to_hex(octets_per_line=0, separator=':') -> string or list of strings\n\
\n\
:Parameters:\n\
    octets_per_line : integer\n\
        Number of octets formatted on one line, if 0 then\n\
        return a single string instead of an array of lines\n\
    separator : string\n\
        String used to seperate each octet\n\
        If None it will be as if the empty string had been\n\
        passed and no separator will be used.\n\
\n\
Equivalent to calling data_to_hex(sec_item)\n\
");

static PyObject *
SecItem_to_hex(SecItem *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"octets_per_line", "separator", NULL};
    int octets_per_line = 0;
    char *separator = HEX_SEPARATOR_DEFAULT;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iz:to_hex", kwlist,
                                     &octets_per_line, &separator))
        return NULL;

    return raw_data_to_hex(self->item.data, self->item.len, octets_per_line, separator);
}

PyDoc_STRVAR(SecItem_to_base64_doc,
"to_base64(chars_per_line=64, pem_type=) -> string or list of strings\n\
\n\
:Parameters:\n\
    chars_per_line : integer\n\
        Number of characters formatted on one line, if 0 then\n\
        return a single string instead of an array of lines\n\
    pem_type : string\n\
        If supplied the base64 encoded data will be wrapped with\n\
        a PEM header and footer whose type is the string.\n\
\n\
Format the binary data in the SecItem as base64 string(s).\n\
Either a list of strings is returned or a single string.\n\
\n\
If chars_per_line is greater than zero then a list of\n\
strings will be returned where each string contains\n\
chars_per_line number of characters (except for the last\n\
string in the list which will contain the remainder of the\n\
characters). Returning a list of \"lines\" makes it convenient\n\
for a caller to format a block of base64 data with line\n\
wrapping. If chars_per_line is greater than zero indicating\n\
a list result is desired a list is always returned even if\n\
the number of characters would produce only a single line.\n\
\n\
If chars_per_line is zero then a single string is returned,\n\
(no line splitting is performed).\n\
\n\
Examples:\n\
\n\
If data is:\n\
\n\
::\n\
\n\
    c8:94:00:9f:c2:8d:a2:5a:61:92:f2:cd:39:75:73:f4\n\
\n\
data.to_hex(0) will return the single string:\n\
\n\
::\n\
\n\
    'yJQAn8KNolphkvLNOXVz9A=='\n\
\n\
data.to_hex(5) will return a list of strings where each string has\n\
a length of 5 (except the last string which may be shorter):\n\
\n\
::\n\
\n\
    [\n\
         'yJQAn',\n\
         '8KNol',\n\
         'phkvL',\n\
         'NOXVz',\n\
         '9A=='\n\
    ]\n\
\n\
If you specify the pem_type optional parameter the return value\n\
will be a list of strings whose first and last strings will be a\n\
PEM header and footer. For example if pem_type='CERTIFICATE'\n\
then the return value will be like this:\n\
\n\
::\n\
\n\
    [\n\
        '-----BEGIN CERTIFICATE-----',\n\
        'yJQAn8KNolphkvLNOXVz9A=='\n\
        '-----END CERTIFICATE-----'\n\
    ]\n\
\n\
When a list of strings is returned it is easy to form a single\n\
text block using the line ending of your choice, for example:\n\
\n\
::\n\
\n\
    '\\n'.join(data.to_base64())\n\
\n\
Thus a PEM block can be formed like this:\n\
\n\
::\n\
\n\
    '\\n'.join(data.to_base64(pem_type='CERTIFICATE'))\n\
\n\
");

static PyObject *
SecItem_to_base64(SecItem *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"chars_per_line", "pem_type", NULL};
    int chars_per_line = 64;
    char *pem_type = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|is:to_base64", kwlist,
                                     &chars_per_line, &pem_type))
        return NULL;

    return SECItem_to_base64(&self->item, chars_per_line, pem_type);
}

PyDoc_STRVAR(SecItem_der_to_hex_doc,
"der_to_hex(octets_per_line=0, separator=':') -> string or list of strings\n\
\n\
:Parameters:\n\
    octets_per_line : integer\n\
        Number of octets formatted on one line, if 0 then\n\
        return a single string instead of an array of lines\n\
    separator : string\n\
        String used to seperate each octet\n\
        If None it will be as if the empty string had been\n\
        passed and no separator will be used.\n\
\n\
Interpret the SecItem as containing DER encoded data consisting\n\
of a <type,length,value> triplet (e.g. TLV). This function skips\n\
the type and length components and returns the value component as\n\
a hexadecimal string or a list of hexidecimal strings with a\n\
maximum of octets_per_line in each list element. See data_to_hex()\n\
for a more detailed explanation.\n\
");

static PyObject *
SecItem_der_to_hex(SecItem *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"octets_per_line", "separator", NULL};
    int octets_per_line = 0;
    char *separator = HEX_SEPARATOR_DEFAULT;
    SECItem tmp_item = self->item;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iz:der_to_hex", kwlist,
                                     &octets_per_line, &separator))
        return NULL;


    tmp_item = self->item;
    if (sec_strip_tag_and_length(&tmp_item) != SECSuccess) {
        PyErr_SetString(PyExc_ValueError, "malformed ASN.1 DER data");
        return NULL;
    }

    return raw_data_to_hex(tmp_item.data, tmp_item.len, octets_per_line, separator);
}

static PyObject *
SecItem_format_lines(SecItem *self, PyObject *args, PyObject *kwds)
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

    FMT_LABEL_AND_APPEND(lines, _("Data"), level, fail);
    if ((obj1 = SecItem_get_data(self, NULL)) == NULL) {
        goto fail;
    }
    APPEND_OBJ_TO_HEX_LINES_AND_CLEAR(lines, obj1, level+1, fail);

    return lines;
 fail:
    Py_XDECREF(obj1);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
SecItem_format(SecItem *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)SecItem_format_lines, (PyObject *)self, args, kwds);
}

static PyMethodDef SecItem_methods[] = {
    {"format_lines",     (PyCFunction)SecItem_format_lines,     METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",           (PyCFunction)SecItem_format,           METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {"get_oid_sequence", (PyCFunction)SecItem_get_oid_sequence, METH_VARARGS|METH_KEYWORDS, SecItem_get_oid_sequence_doc},
    {"get_integer",      (PyCFunction)SecItem_get_integer,      METH_NOARGS,                SecItem_get_integer_doc},
    {"to_hex",           (PyCFunction)SecItem_to_hex,           METH_VARARGS|METH_KEYWORDS, SecItem_to_hex_doc},
    {"to_base64",        (PyCFunction)SecItem_to_base64,        METH_VARARGS|METH_KEYWORDS, SecItem_to_base64_doc},
    {"der_to_hex",       (PyCFunction)SecItem_der_to_hex,       METH_VARARGS|METH_KEYWORDS, SecItem_der_to_hex_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
SecItem_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    SecItem *self;

    TraceObjNewEnter(type);

    if ((self = (SecItem *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }
    self->item.type = 0;
    self->item.len = 0;
    self->item.data = NULL;
    self->kind = SECITEM_unknown;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
SecItem_dealloc(SecItem* self)
{
    TraceMethodEnter(self);

    if (self->item.data) {
        /* zero out memory block before freeing */
        memset(self->item.data, 0, self->item.len);
        PyMem_FREE(self->item.data);
    }

    self->ob_type->tp_free((PyObject*)self);
}

static void
SecItem_decref(SecItem* self)
{
    TraceMethodEnter(self);

    Py_XDECREF(self);
}

PyDoc_STRVAR(SecItem_doc,
"SecItem(data=None, type=siBuffer, ascii=False)\n\
\n\
:Parameters:\n\
    data : any read buffer compatible object (e.g. buffer or string)\n\
        raw data to initialize from\n\
    type : int\n\
        SECItemType constant (e.g. si*)\n\
    ascii : bool\n\
        If true then data is interpretted as base64 encoded.\n\
        A PEM header and footer is permissible, if present the\n\
        base64 data will be found inside the PEM delimiters.\n\
\n\
A SecItem is a block of binary data. It contains the data, a count of\n\
the number of octets in the data and optionally a type describing the\n\
contents of the data. SecItem's are used throughout NSS to pass blocks\n\
of binary data back and forth. Because the binary data is often DER\n\
(Distinguished Encoding Rule) ASN.1 data the data is often referred to\n\
as 'der'.\n\
\n\
SecItem's are often returned by NSS functions.\n\
\n\
You can create and initialize a SecItem yourself by passing the data\n\
to the SecItem constructor. If you do initialize the data you may either\n\
pass binary data or text (when ascii == True). When you pass ascii data\n\
it will be interpreted as base64 encoded binary data. The base64 text may\n\
optionally be wrapped inside PEM delimiters, but PEM format is not required.\n\
");
static int
SecItem_init(SecItem *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"data", "type", "ascii", NULL};
    const void *buffer = NULL;
    Py_ssize_t buffer_len;
    int type = siBuffer;
    int ascii = 0;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|z#ii:SecItem", kwlist,
                                     &buffer, &buffer_len, &type, &ascii))
        return -1;

    if (buffer) {
        self->kind = SECITEM_buffer;
        self->item.type = type;
        if (ascii) {
            if (base64_to_SECItem(&self->item, (char *)buffer, buffer_len) != SECSuccess) {
                return -1;
            }
        } else {
            self->item.len = buffer_len;
            if ((self->item.data = PyMem_MALLOC(buffer_len)) == NULL) {
                PyErr_Format(PyExc_MemoryError, "not enough memory to copy buffer of size %zd into SecItem",
                             buffer_len);
                return -1;
            }
            memmove(self->item.data, buffer, buffer_len);
        }
    } else {                    /* empty buffer */
        self->kind = SECITEM_buffer;
        self->item.type = siBuffer;
        self->item.len = 0;
        self->item.data = NULL;
    }

    return 0;
}

static PyObject *
SecItem_repr(SecItem *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyObject *
SecItem_str(SecItem *self)
{
    PyObject *return_value = NULL;

    switch(self->kind) {
    case SECITEM_dist_name:
        {
            char *name;

            if ((name = CERT_DerNameToAscii(&self->item)) == NULL) {
                return set_nspr_error(NULL);
            }
            return_value = PyString_FromString(name);
            PORT_Free(name);
        }
        break;
    case SECITEM_algorithm:
        return oid_secitem_to_pystr_desc(&self->item);
    case SECITEM_buffer:
        return secitem_to_pystr_hex(&self->item);
    default:
        return der_any_secitem_to_pystr(&self->item);
        break;
    }
    return return_value;
}

static int
SecItem_compare(SecItem *self, SecItem *other)
{
    if (!PySecItem_Check(other)) {
        PyErr_SetString(PyExc_TypeError, "Bad type, must be SecItem");
        return -1;
    }

    if (self->item.data == NULL && other->item.data == NULL) {
        return 0;
    }

    if (self->item.len == 0 && other->item.len == 0) {
        return 0;
    }

    if (self->item.len > other->item.len) {
        return 1;
    }

    if (self->item.len < other->item.len) {
        return -1;
    }

    if (self->item.data != NULL && other->item.data != NULL) {
        return memcmp(self->item.data, other->item.data, self->item.len);
    }

    return 0;
}

/* =========================== Buffer Protocol ========================== */

static Py_ssize_t
SecItem_buffer_getbuf(PyObject *obj, Py_ssize_t index, void **ptr)
{
    SecItem *self = (SecItem *) obj;
    if (index != 0) {
        PyErr_SetString(PyExc_SystemError, "Accessing non-existent segment");
        return -1;
    }
    *ptr = self->item.data;
    return self->item.len;
}

static Py_ssize_t
SecItem_buffer_getsegcount(PyObject *obj, Py_ssize_t *lenp)
{
    if (lenp)
        *lenp = 1;
    return 1;
}

static PyBufferProcs SecItem_as_buffer = {
    SecItem_buffer_getbuf,			/* bf_getreadbuffer */
    SecItem_buffer_getbuf,			/* bf_getwritebuffer */
    SecItem_buffer_getsegcount,			/* bf_getsegcount */
    NULL,					/* bf_getcharbuffer */
};

static Py_ssize_t
SecItem_length(SecItem *self)
{
    return self->item.len;
}

static PyObject *
SecItem_item(SecItem *self, register Py_ssize_t i)
{
    char octet;

    if (i < 0 || i >= self->item.len) {
        PyErr_SetString(PyExc_IndexError, "SecItem index out of range");
        return NULL;
    }
    octet = self->item.data[i];
    return PyString_FromStringAndSize(&octet, 1);
}

/* slice a[i:j] consists of octets a[i] ... a[j-1], j -- may be negative! */
static PyObject *
SecItem_slice(SecItem *a, Py_ssize_t i, Py_ssize_t j)
{
    if (i < 0)
        i = 0;
    if (j < 0)
        j = 0;
    if (j > SecItem_GET_SIZE(a))
        j = SecItem_GET_SIZE(a);
    if (j < i)
        j = i;
    return PyString_FromStringAndSize((const char *)(a->item.data + i), j-i);
}

static PyObject*
SecItem_subscript(SecItem *self, PyObject* item)
{
    if (PyIndex_Check(item)) {
        Py_ssize_t i = PyNumber_AsSsize_t(item, PyExc_IndexError);
        if (i == -1 && PyErr_Occurred())
            return NULL;
        if (i < 0)
            i += SecItem_GET_SIZE(self);
        return SecItem_item(self, i);
    }
    else if (PySlice_Check(item)) {
        Py_ssize_t start, stop, step, slice_len, cur, i;
        unsigned char* src;
        unsigned char* dst;
        PyObject* result;

        if (PySlice_GetIndicesEx((PySliceObject*)item, SecItem_GET_SIZE(self),
				 &start, &stop, &step, &slice_len) < 0) {
            return NULL;
        }

        if (slice_len <= 0) {
            return PyString_FromStringAndSize("", 0);
        } else if (step == 1) {
            return PyString_FromStringAndSize((char *)self->item.data + start, slice_len);
        } else {
            src = self->item.data;
            if ((result = PyString_FromStringAndSize(NULL, slice_len)) == NULL) {
                return NULL;
            }
            dst = (unsigned char *)PyString_AsString(result);
            for (cur = start, i = 0; i < slice_len; cur += step, i++) {
                dst[i] = src[cur];
            }
            return result;
        }
    } else {
        PyErr_Format(PyExc_TypeError, "SecItem indices must be integers, not %.200s",
                     Py_TYPE(item)->tp_name);
        return NULL;
    }
}

static PySequenceMethods SecItem_as_sequence = {
    (lenfunc)SecItem_length,			/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)SecItem_item,			/* sq_item */
    (ssizessizeargfunc)SecItem_slice,		/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyMappingMethods SecItem_as_mapping = {
    (lenfunc)SecItem_length,			/* mp_length */
    (binaryfunc)SecItem_subscript,		/* mp_subscript */
    0,						/* mp_ass_subscript */
};

static PyTypeObject SecItemType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.SecItem",				/* tp_name */
    sizeof(SecItem),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)SecItem_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    (cmpfunc)SecItem_compare,			/* tp_compare */
    (reprfunc)SecItem_repr,			/* tp_repr */
    0,						/* tp_as_number */
    &SecItem_as_sequence,			/* tp_as_sequence */
    &SecItem_as_mapping,			/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)SecItem_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    &SecItem_as_buffer,				/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    SecItem_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    SecItem_methods,				/* tp_methods */
    SecItem_members,				/* tp_members */
    SecItem_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)SecItem_init,			/* tp_init */
    0,						/* tp_alloc */
    SecItem_new,				/* tp_new */
};

/*
 * NSS WART - We always have to copy the SECItem because there are
 * more than 1 way to free a SECItem pointer depending on how it was
 * allocated.
 */

static PyObject *
SecItem_new_from_SECItem(const SECItem *item, SECItemKind kind)
{
    SecItem *self = NULL;

    TraceObjNewEnter(NULL);

    if (!item) {
        return NULL;
    }

    if ((self = (SecItem *) SecItemType.tp_new(&SecItemType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->item.type = item->type;
    self->item.len = item->len;
    if ((self->item.data = PyMem_MALLOC(item->len)) == NULL) {
        Py_CLEAR(self);
        return PyErr_NoMemory();
    }
    memmove(self->item.data, item->data, item->len);

    self->kind = kind;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

static PyObject *
SecItem_new_alloc(size_t len, SECItemType type, SECItemKind kind)
{
    SecItem *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (SecItem *) SecItemType.tp_new(&SecItemType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->item.type = type;
    self->item.len = len;
    if ((self->item.data = PyMem_MALLOC(len)) == NULL) {
        Py_CLEAR(self);
        return PyErr_NoMemory();
    }

    self->kind = kind;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ============================ AlgorithmID Class =========================== */
/* ========================================================================== */

/*
 * NSS WART BEGIN
 *
 * The following have no public definition, copied from secutil.c
 */
typedef struct secuPBEParamsStr {
    SECItem salt;
    SECItem iterationCount;
    SECItem keyLength;
    SECAlgorithmID cipherAlg;
    SECAlgorithmID kdfAlg;
} secuPBEParams;

SEC_ASN1_MKSUB(SECOID_AlgorithmIDTemplate);

/* SECOID_PKCS5_PBKDF2 */
const SEC_ASN1Template secuKDF2Params[] =
{
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(secuPBEParams) },
    { SEC_ASN1_OCTET_STRING, offsetof(secuPBEParams, salt) },
    { SEC_ASN1_INTEGER, offsetof(secuPBEParams, iterationCount) },
    { SEC_ASN1_INTEGER, offsetof(secuPBEParams, keyLength) },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN, offsetof(secuPBEParams, kdfAlg),
        SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { 0 }
};

/* PKCS5v1 & PKCS12 */
const SEC_ASN1Template secuPBEParamsTemp[] =
{
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(secuPBEParams) },
    { SEC_ASN1_OCTET_STRING, offsetof(secuPBEParams, salt) },
    { SEC_ASN1_INTEGER, offsetof(secuPBEParams, iterationCount) },
    { 0 }
};

/* SEC_OID_PKCS5_PBES2, SEC_OID_PKCS5_PBMAC1 */
const SEC_ASN1Template secuPBEV2Params[] =
{
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(secuPBEParams)},
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN, offsetof(secuPBEParams, kdfAlg),
        SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN, offsetof(secuPBEParams, cipherAlg),
        SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { 0 }
};

/*
 * NSS WART END
 */

#ifdef HAVE_RSA_PSS
static PyObject *
RSAPSSParams_format_lines(SECItem *item, int level)
{
    SECKEYRSAPSSParams params;
    SECAlgorithmID mask_hash_alg;
    PRArenaPool *arena = NULL;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *obj1 = NULL;

    /* allocate an arena to use */
    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL ) {
        set_nspr_error(NULL);
        return NULL;
    }

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    PORT_Memset(&params, 0, sizeof params);

    if (SEC_QuickDERDecodeItem(arena, &params,
                               SEC_ASN1_GET(SECKEY_RSAPSSParamsTemplate),
                               item) != SECSuccess) {
        goto fail;
    }

    if (params.hashAlg) {
        obj = oid_secitem_to_pystr_desc(&params.hashAlg->algorithm);
    } else {
        obj = PyString_FromString("default, SHA-1");
    }
    FMT_OBJ_AND_APPEND(lines, _("Hash algorithm"), obj, level, fail);
    Py_CLEAR(obj);

    if (params.maskAlg) {
        obj = oid_secitem_to_pystr_desc(&params.maskAlg->algorithm);
        if (SEC_QuickDERDecodeItem(arena, &mask_hash_alg,
                                   SEC_ASN1_GET(SECOID_AlgorithmIDTemplate),
                                   &params.maskAlg->parameters) == SECSuccess) {
            obj1 = oid_secitem_to_pystr_desc(&mask_hash_alg.algorithm);
        } else {
            obj1 = PyString_FromString("Invalid mask generation algorithm parameters");
        }
    } else {
        obj = PyString_FromString("default, MGF1");
        obj1 = PyString_FromString("default, SHA-1");
    }
    FMT_OBJ_AND_APPEND(lines, _("Mask Algorithm"), obj, level, fail);
    Py_CLEAR(obj);

    FMT_OBJ_AND_APPEND(lines, _("Mask hash algorithm"), obj1, level, fail);
    Py_CLEAR(obj1);

    if (params.saltLength.data) {
        obj = integer_secitem_to_pystr(&params.saltLength);
    } else {
        obj = PyString_FromString("default, 20");
    }
    FMT_OBJ_AND_APPEND(lines, _("Salt length"), obj, level, fail);
    Py_CLEAR(obj);

    PORT_FreeArena(arena, PR_FALSE);
    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(obj1);
    Py_XDECREF(lines);
    PORT_FreeArena(arena, PR_FALSE);
    return NULL;
}
#endif

static PyObject *
KDF2Params_format_lines(SECItem *item, int level)
{
    secuPBEParams params;
    PRArenaPool *arena = NULL;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(NULL);

    /* allocate an arena to use */
    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL ) {
        set_nspr_error(NULL);
        return NULL;
    }

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    PORT_Memset(&params, 0, sizeof params);

    if (SEC_QuickDERDecodeItem(arena, &params, secuKDF2Params, item) != SECSuccess) {
        goto fail;
    }

    obj = secitem_to_pystr_hex(&params.salt);
    FMT_OBJ_AND_APPEND(lines, _("Salt"), obj, level, fail);
    Py_CLEAR(obj);

    obj = integer_secitem_to_pystr(&params.iterationCount);
    FMT_OBJ_AND_APPEND(lines, _("Iteration Count"), obj, level, fail);
    Py_CLEAR(obj);

    obj = integer_secitem_to_pystr(&params.keyLength);
    FMT_OBJ_AND_APPEND(lines, _("Key Length"), obj, level, fail);
    Py_CLEAR(obj);

    obj = AlgorithmID_new_from_SECAlgorithmID(&params.kdfAlg);
    FMT_LABEL_AND_APPEND(lines, _("KDF Algorithm"), level, fail);
    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+1, fail);
    Py_CLEAR(obj);

    PORT_FreeArena(arena, PR_FALSE);
    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    PORT_FreeArena(arena, PR_FALSE);
    return NULL;
}

static PyObject *
PKCS5V2Params_format_lines(SECItem *item, int level)
{
    secuPBEParams params;
    PRArenaPool *arena = NULL;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(NULL);

    /* allocate an arena to use */
    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL ) {
        set_nspr_error(NULL);
        return NULL;
    }

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    PORT_Memset(&params, 0, sizeof params);

    if (SEC_QuickDERDecodeItem(arena, &params, secuPBEV2Params, item) != SECSuccess) {
        goto fail;
    }

    obj = AlgorithmID_new_from_SECAlgorithmID(&params.kdfAlg);
    FMT_LABEL_AND_APPEND(lines, _("KDF"), level, fail);
    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+1, fail);
    Py_CLEAR(obj);

    obj = AlgorithmID_new_from_SECAlgorithmID(&params.cipherAlg);
    FMT_LABEL_AND_APPEND(lines, _("Cipher"), level, fail);
    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+1, fail);
    Py_CLEAR(obj);

    PORT_FreeArena(arena, PR_FALSE);
    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    PORT_FreeArena(arena, PR_FALSE);
    return NULL;
}

static PyObject *
PBEParams_format_lines(SECItem *item, int level)
{
    secuPBEParams params;
    PRArenaPool *arena = NULL;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(NULL);

    /* allocate an arena to use */
    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL ) {
        set_nspr_error(NULL);
        return NULL;
    }

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    PORT_Memset(&params, 0, sizeof params);

    if (SEC_QuickDERDecodeItem(arena, &params, secuPBEParamsTemp, item) != SECSuccess) {
        goto fail;
    }

    obj = secitem_to_pystr_hex(&params.salt);
    FMT_OBJ_AND_APPEND(lines, _("Salt"), obj, level, fail);
    Py_CLEAR(obj);

    obj = integer_secitem_to_pystr(&params.iterationCount);
    FMT_OBJ_AND_APPEND(lines, _("Iteration Count"), obj, level, fail);
    Py_CLEAR(obj);

    PORT_FreeArena(arena, PR_FALSE);
    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    PORT_FreeArena(arena, PR_FALSE);
    return NULL;
}

/* ============================ Attribute Access ============================ */

static PyObject *
AlgorithmID_get_id_oid(AlgorithmID *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_id);
    return self->py_id;
}

static PyObject *
AlgorithmID_get_id_tag(AlgorithmID *self, void *closure)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pyint_tag(&self->id.algorithm);
}

static PyObject *
AlgorithmID_get_id_str(AlgorithmID *self, void *closure)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pystr_desc(&self->id.algorithm);
}

static PyObject *
AlgorithmID_get_parameters(AlgorithmID *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_parameters);
    return self->py_parameters;
}

static
PyGetSetDef AlgorithmID_getseters[] = {
    {"id_oid",     (getter)AlgorithmID_get_id_oid,     (setter)NULL, "algorithm id OID as SecItem", NULL},
    {"id_tag",     (getter)AlgorithmID_get_id_tag,     (setter)NULL, "algorithm id TAG as a enumerated constant (e.g. tag)", NULL},
    {"id_str",     (getter)AlgorithmID_get_id_str,     (setter)NULL, "algorithm id as string description", NULL},
    {"parameters", (getter)AlgorithmID_get_parameters, (setter)NULL, "algorithm parameters as SecItem", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef AlgorithmID_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
AlgorithmID_format_lines(AlgorithmID *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    SECOidTag alg_tag;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    obj = oid_secitem_to_pystr_desc(&self->id.algorithm);
    FMT_OBJ_AND_APPEND(lines, _("Algorithm"), obj, level, fail);
    Py_CLEAR(obj);

    alg_tag = SECOID_GetAlgorithmTag(&self->id);
    if (SEC_PKCS5IsAlgorithmPBEAlgTag(alg_tag)) {
	switch (alg_tag) {
	case SEC_OID_PKCS5_PBKDF2:
            FMT_LABEL_AND_APPEND(lines, _("Parameters"), level, fail);
            obj = KDF2Params_format_lines(&self->id.parameters, level+1);
            APPEND_LINE_TUPLES_AND_CLEAR(lines, obj, fail);
	    break;
	case SEC_OID_PKCS5_PBES2:
            FMT_LABEL_AND_APPEND(lines, _("Encryption"), level, fail);
            obj = PKCS5V2Params_format_lines(&self->id.parameters, level+1);
            APPEND_LINE_TUPLES_AND_CLEAR(lines, obj, fail);
	    break;
	case SEC_OID_PKCS5_PBMAC1:
            FMT_LABEL_AND_APPEND(lines, _("MAC"), level, fail);
            obj = PKCS5V2Params_format_lines(&self->id.parameters, level+1);
            APPEND_LINE_TUPLES_AND_CLEAR(lines, obj, fail);
	    break;
	default:
            FMT_LABEL_AND_APPEND(lines, _("Parameters"), level, fail);
            obj = PBEParams_format_lines(&self->id.parameters, level+1);
            APPEND_LINE_TUPLES_AND_CLEAR(lines, obj, fail);
	    break;
	}
    }

#ifdef HAVE_RSA_PSS
    if (alg_tag == SEC_OID_PKCS1_RSA_PSS_SIGNATURE) {
        FMT_LABEL_AND_APPEND(lines, _("Parameters"), level, fail);
        obj = RSAPSSParams_format_lines(&self->id.parameters, level+1);
        APPEND_LINE_TUPLES_AND_CLEAR(lines, obj, fail);
    }
#endif

    if ((self->id.parameters.len == 0) ||
	(self->id.parameters.len == 2 && memcmp(self->id.parameters.data, "\005\000", 2) == 0)) {
	/* No arguments or NULL argument */
    } else {
	/* Print args to algorithm */
        PyObject *hex_lines = NULL;

        if ((hex_lines = raw_data_to_hex(self->id.parameters.data, self->id.parameters.len,
                                         OCTETS_PER_LINE_DEFAULT, HEX_SEPARATOR_DEFAULT)) != NULL) {
            FMT_LABEL_AND_APPEND(lines, _("Raw Parameter Data"), level, fail);
            APPEND_LINES_AND_CLEAR(lines, hex_lines, level+1, fail);
        }
    }

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
AlgorithmID_format(AlgorithmID *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)AlgorithmID_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
AlgorithmID_str(AlgorithmID *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  AlgorithmID_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

PyDoc_STRVAR(AlgorithmID_get_pbe_crypto_mechanism_doc,
"get_pbe_crypto_mechanism(sym_key, padded=True) -> (mechanism, params)\n\
\n\
:Parameters:\n\
    sym_key : PK11SymKey object\n\
        The symmetric key returned from `PK11Slot.pbe_key_gen()`\n\
    padded : bool\n\
        Block ciphers require the input data to be a multiple of the cipher\n\
        block size. The necessary padding can be performed internally,\n\
        this is controlled by selecting a pad vs. non-pad cipher mechanism.\n\
        If the padded flag is True the returned mechanism will support\n\
        padding if possible. If you know you do not need or want a padded\n\
        mechanism set this flag to False. Selection of a padded mechanism\n\
        is performed internally by calling `nss.get_pad_mechanism()`.\n\
\n\
This function generates the parameters needed for\n\
`nss.create_context_by_sym_key()`, for example:\n\
\n\
    alg_id = nss.create_pbev2_algorithm_id()\n\
    sym_key = slot.pbe_key_gen(alg_id, password)\n\
    mechanism, params = alg_id.get_pbe_crypto_mechanism(sym_key)\n\
    encrypt_ctx = nss.create_context_by_sym_key(mechanism, nss.CKA_ENCRYPT, sym_key, params)\n\
\n\
");

static PyObject *
AlgorithmID_get_pbe_crypto_mechanism(AlgorithmID *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"alg_id", "padded", NULL};
    PyPK11SymKey *py_sym_key = NULL;
    PyObject *py_padded = NULL;
    PRBool padded = PR_TRUE;
    CK_MECHANISM_TYPE mechanism;
    SecItem *py_pwitem = NULL;
    SECItem *params = NULL;
    PyObject *py_params = NULL;
    PyObject *tuple = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|O!:get_pbe_crypto_mechanism", kwlist,
                                      &PK11SymKeyType, &py_sym_key,
                                      &PyBool_Type, &py_padded))
        return NULL;

    if (py_padded) {
        padded = PyBoolAsPRBool(py_padded);
    }

    /*
     * PK11Slot_pbe_key_gen
     */

    py_pwitem = (SecItem *)PK11_GetSymKeyUserData(py_sym_key->pk11_sym_key);


    if ((mechanism = PK11_GetPBECryptoMechanism(&self->id, &params,
                                                &py_pwitem->item)) == CKM_INVALID_MECHANISM) {

        return set_nspr_error(NULL);
    }

    if (padded) {
        mechanism = PK11_GetPadMechanism(mechanism);
    }

    if ((py_params = SecItem_new_from_SECItem(params, SECITEM_sym_key_params)) == NULL) {
        if (params) {
            SECITEM_ZfreeItem(params, PR_TRUE);
        }
        return NULL;
    }
    if (params) {
        SECITEM_ZfreeItem(params, PR_TRUE);
    }

    if ((tuple = PyTuple_New(2)) == NULL) {
        return NULL;
    }

    PyTuple_SetItem(tuple, 0, PyInt_FromLong(mechanism));
    PyTuple_SetItem(tuple, 1, py_params);

    return tuple;
}

PyDoc_STRVAR(AlgorithmID_get_pbe_iv_doc,
"get_pbe_iv(password) -> SecItem\n\
\n\
:Parameters:\n\
    password : string\n\
        the password used to create the PBE Key\n\
\n\
Returns the IV (Initialization Vector) used for the PBE cipher.\n\
");

static PyObject *
AlgorithmID_get_pbe_iv(AlgorithmID *self, PyObject *args)
{
    char *password = NULL;
    Py_ssize_t password_len = 0;
    SECItem pwitem;
    SECItem *iv;
    PyObject *py_iv = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "s#:get_pbe_iv",
                          &password, &password_len))
        return NULL;

    pwitem.data = (unsigned char *)password;
    pwitem.len = password_len;

    if ((iv = PK11_GetPBEIV(&self->id, &pwitem)) == NULL) {
        return set_nspr_error(NULL);
    }

    py_iv = SecItem_new_from_SECItem(iv, SECITEM_iv_param);
    SECITEM_FreeItem(iv, PR_TRUE);
    return py_iv;
}

static PyMethodDef AlgorithmID_methods[] = {
    {"format_lines",             (PyCFunction)AlgorithmID_format_lines,             METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",                   (PyCFunction)AlgorithmID_format,                   METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {"get_pbe_crypto_mechanism", (PyCFunction)AlgorithmID_get_pbe_crypto_mechanism, METH_VARARGS|METH_KEYWORDS, AlgorithmID_get_pbe_crypto_mechanism_doc},
    {"get_pbe_iv",               (PyCFunction)AlgorithmID_get_pbe_iv,               METH_VARARGS,               AlgorithmID_get_pbe_iv_doc},
    {NULL, NULL}  /* Sentinel */
};


/* =========================== Class Construction =========================== */

static PyObject *
AlgorithmID_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    AlgorithmID *self;

    TraceObjNewEnter(type);

    if ((self = (AlgorithmID *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    memset(&self->id, 0, sizeof(self->id));
    self->py_id = NULL;
    self->py_parameters = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
AlgorithmID_traverse(AlgorithmID *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_id);
    Py_VISIT(self->py_parameters);
    return 0;
}

static int
AlgorithmID_clear(AlgorithmID* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_id);
    Py_CLEAR(self->py_parameters);
    return 0;
}

static void
AlgorithmID_dealloc(AlgorithmID* self)
{
    TraceMethodEnter(self);

    AlgorithmID_clear(self);
    SECOID_DestroyAlgorithmID(&self->id, PR_FALSE);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(AlgorithmID_doc,
"An object representing a signature algorithm");

static int
AlgorithmID_init(AlgorithmID *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return 0;
}

static PyObject *
AlgorithmID_repr(AlgorithmID *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject AlgorithmIDType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.AlgorithmID",			/* tp_name */
    sizeof(AlgorithmID),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)AlgorithmID_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)AlgorithmID_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)AlgorithmID_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    AlgorithmID_doc,				/* tp_doc */
    (traverseproc)AlgorithmID_traverse,		/* tp_traverse */
    (inquiry)AlgorithmID_clear,			/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    AlgorithmID_methods,			/* tp_methods */
    AlgorithmID_members,			/* tp_members */
    AlgorithmID_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)AlgorithmID_init,			/* tp_init */
    0,						/* tp_alloc */
    AlgorithmID_new,				/* tp_new */
};

PyObject *
AlgorithmID_new_from_SECAlgorithmID(SECAlgorithmID *id)
{
    AlgorithmID *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (AlgorithmID *) AlgorithmIDType.tp_new(&AlgorithmIDType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (SECOID_CopyAlgorithmID(NULL, &self->id, id) != SECSuccess) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_id = SecItem_new_from_SECItem(&id->algorithm, SECITEM_algorithm)) == NULL) {
        SECOID_DestroyAlgorithmID(&self->id, PR_FALSE);
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_parameters = SecItem_new_from_SECItem(&id->parameters, SECITEM_unknown)) == NULL) {
        SECOID_DestroyAlgorithmID(&self->id, PR_FALSE);
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* =========================== RSAGenParams Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
RSAGenParams_get_key_size(RSAGenParams *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->params.keySizeInBits);

}

static int
RSAGenParams_set_key_size(RSAGenParams *self, PyObject *value, void *closure)
{
    TraceMethodEnter(self);

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the key_size attribute");
        return -1;
    }

    if (!PyInt_Check(value)) {
        PyErr_Format(PyExc_TypeError, "key_size must be a integer, not %.200s",
                     Py_TYPE(value)->tp_name);
        return -1;
    }

    self->params.keySizeInBits = PyInt_AsLong(value);

    return 0;
}

static PyObject *
RSAGenParams_get_public_exponent(RSAGenParams *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->params.keySizeInBits);

}

static int
RSAGenParams_set_public_exponent(RSAGenParams *self, PyObject *value, void *closure)
{
    TraceMethodEnter(self);

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the public_exponent attribute");
        return -1;
    }

    if (!PyInt_Check(value)) {
        PyErr_Format(PyExc_TypeError, "public_exponent must be a integer, not %.200s",
                     Py_TYPE(value)->tp_name);
        return -1;
    }

    self->params.pe = PyInt_AsLong(value);

    return 0;
}

static
PyGetSetDef RSAGenParams_getseters[] = {
    {"key_size", (getter)RSAGenParams_get_key_size,    (setter)RSAGenParams_set_key_size,
     "key size in bits (integer)", NULL},
    {"public_exponent", (getter)RSAGenParams_get_public_exponent,    (setter)RSAGenParams_set_public_exponent,
     "public exponent (integer)", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef RSAGenParams_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyMethodDef RSAGenParams_methods[] = {
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
RSAGenParams_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    RSAGenParams *self;

    TraceObjNewEnter(type);

    if ((self = (RSAGenParams *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    memset(&self->params, 0, sizeof(self->params));

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
RSAGenParams_dealloc(RSAGenParams* self)
{
    TraceMethodEnter(self);

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(RSAGenParams_doc,
"RSAGenParams(key_size=1024, public_exponent=0x10001)\n\
\n\
:Parameters:\n\
    key_size : integer\n\
        RSA key size in bits.\n\
    public_exponent : integer\n\
        public exponent.\n\
\n\
An object representing RSAGenParams.\n\
");

static int
RSAGenParams_init(RSAGenParams *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key_size", "exponent", NULL};
    int key_size = 1024;
    unsigned long public_exponent = 0x10001;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ik:RSAGenParams", kwlist,
                                     &key_size, &public_exponent))
        return -1;

    self->params.keySizeInBits = key_size;
    self->params.pe = public_exponent;

    return 0;
}

static PyObject *
RSAGenParams_str(RSAGenParams *self)
{
    TraceMethodEnter(self);

    return PyString_FromFormat("key_size=%d public_exponent=%lu",
                               self->params.keySizeInBits,
                               self->params.pe);
}

static PyTypeObject RSAGenParamsType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.RSAGenParams",				/* tp_name */
    sizeof(RSAGenParams),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)RSAGenParams_dealloc,		/* tp_dealloc */
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
    (reprfunc)RSAGenParams_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    RSAGenParams_doc,				/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    RSAGenParams_methods,				/* tp_methods */
    RSAGenParams_members,				/* tp_members */
    RSAGenParams_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)RSAGenParams_init,			/* tp_init */
    0,						/* tp_alloc */
    RSAGenParams_new,				/* tp_new */
};

/* ========================================================================== */
/* ============================ KEYPQGParams Class ========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
KEYPQGParams_get_prime(KEYPQGParams *self, void *closure)
{
    TraceMethodEnter(self);

    return SecItem_new_from_SECItem(&self->params.prime, SECITEM_unknown);
}

static PyObject *
KEYPQGParams_get_subprime(KEYPQGParams *self, void *closure)
{
    TraceMethodEnter(self);

    return SecItem_new_from_SECItem(&self->params.subPrime, SECITEM_unknown);
}

static PyObject *
KEYPQGParams_get_base(KEYPQGParams *self, void *closure)
{
    TraceMethodEnter(self);

    return SecItem_new_from_SECItem(&self->params.base, SECITEM_unknown);
}

static
PyGetSetDef KEYPQGParams_getseters[] = {
    {"prime",    (getter)KEYPQGParams_get_prime,    (setter)NULL, "key prime value, also known as p", NULL},
    {"subprime", (getter)KEYPQGParams_get_subprime, (setter)NULL, "key subprime value, also known as q", NULL},
    {"base",     (getter)KEYPQGParams_get_base,     (setter)NULL, "key base value, also known as g", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef KEYPQGParams_members[] = {
    {NULL}  /* Sentinel */
};
/* ============================== Class Methods ============================= */

PyObject *
KEYPQGParams_format_lines(KEYPQGParams *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *obj_lines = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }


    if ((obj = KEYPQGParams_get_prime(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_SEC_INT_OBJ_APPEND_AND_CLEAR(lines, _("Prime"), obj, level, fail);

    if ((obj = KEYPQGParams_get_subprime(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_SEC_INT_OBJ_APPEND_AND_CLEAR(lines, _("SubPrime"), obj, level, fail);

    if ((obj = KEYPQGParams_get_base(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_SEC_INT_OBJ_APPEND_AND_CLEAR(lines, _("Base"), obj, level, fail);

    return lines;

 fail:
    Py_XDECREF(obj_lines);
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
KEYPQGParams_format(KEYPQGParams *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)KEYPQGParams_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
KEYPQGParams_str(KEYPQGParams *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  KEYPQGParams_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef KEYPQGParams_methods[] = {
    {"format_lines", (PyCFunction)KEYPQGParams_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)KEYPQGParams_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
KEYPQGParams_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    KEYPQGParams *self;

    TraceObjNewEnter(type);

    if ((self = (KEYPQGParams *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    memset(&self->params, 0, sizeof(self->params));

    if ((self->params.arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
KEYPQGParams_dealloc(KEYPQGParams* self)
{
    TraceMethodEnter(self);

    if (self->params.arena) {
        PORT_FreeArena(self->params.arena, PR_FALSE);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(KEYPQGParams_doc,
"KEYPQGParams(prime=None, subprime=None, base=None)\n\
\n\
:Parameters:\n\
    prime : SecItem or str or any buffer compatible object or None\n\
        prime (also known as p)\n\
    subprime : SecItem or str or any buffer compatible object or None\n\
        subprime (also known as q)\n\
    base : SecItem or str or any buffer compatible object or None\n\
        base (also known as g)\n\
\n\
An object representing DSA key parameters\n\
    - prime (also known as p)\n\
    - subprime (also known as q)\n\
    - base (also known as g)\n\
\n\
If no parameters are passed the default PQG the KeyPQGParams will\n\
be intialized to default values. If you pass any initialization\n\
parameters then they must all be passed.\n\
");

static int
KEYPQGParams_init(KEYPQGParams *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"prime", "subprime", "base", NULL};
    PyObject *py_prime = NULL;
    SECItem prime_tmp_item;
    SECItem *prime_item = NULL;

    PyObject *py_subprime = NULL;
    SECItem subprime_tmp_item;
    SECItem *subprime_item = NULL;

    PyObject *py_base = NULL;
    SECItem base_tmp_item;
    SECItem *base_item = NULL;

    TraceMethodEnter(self);

    // FIXME: prime, subprime & base are really large ASN.1 integers
    // we should accept a python int or python long and convert to a SecItem

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOO:KEYPQGParams", kwlist,
                                     &py_prime, &py_subprime, &py_base))
        return -1;

    // FIXME: doc says None is OK, but SECITEM_PARAM none_ok is false
    SECITEM_PARAM(py_prime, prime_item, prime_tmp_item, false, "prime");
    SECITEM_PARAM(py_subprime, subprime_item, subprime_tmp_item, false, "subprime");
    SECITEM_PARAM(py_base, base_item, base_tmp_item, false, "base");

    if (py_prime == NULL && py_subprime == NULL && py_base == NULL) {
        if ((KEYPQGParams_init_from_SECKEYPQGParams(self, &default_pqg_params)) == NULL) {
            return -1;
        }
    } else if (py_prime != NULL && py_subprime != NULL && py_base != NULL) {
        SECKEYPQGParams params;

        params.arena = NULL;
        params.prime = *prime_item;
        params.subPrime = *subprime_item;
        params.base = *base_item;

        if ((KEYPQGParams_init_from_SECKEYPQGParams(self, &params)) == NULL) {
            return -1;
        }
    } else {
        PyErr_SetString(PyExc_ValueError, "prime, subprime and base must all be provided or none of them provided, not a mix");
    }

    return 0;
}

static PyObject *
KEYPQGParams_repr(KEYPQGParams *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject KEYPQGParamsType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.KEYPQGParams",			/* tp_name */
    sizeof(KEYPQGParams),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)KEYPQGParams_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)KEYPQGParams_repr,		/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)KEYPQGParams_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    KEYPQGParams_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    KEYPQGParams_methods,			/* tp_methods */
    KEYPQGParams_members,			/* tp_members */
    KEYPQGParams_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)KEYPQGParams_init,		/* tp_init */
    0,						/* tp_alloc */
    KEYPQGParams_new,				/* tp_new */
};

PyObject *
KEYPQGParams_init_from_SECKEYPQGParams(KEYPQGParams *self, const SECKEYPQGParams *params)
{

    SECITEM_FreeItem(&self->params.prime, PR_FALSE);
    if (SECITEM_CopyItem(self->params.arena, &self->params.prime, &params->prime) != SECSuccess) {
        return NULL;
    }

    SECITEM_FreeItem(&self->params.subPrime, PR_FALSE);
    if (SECITEM_CopyItem(self->params.arena, &self->params.subPrime, &params->subPrime) != SECSuccess) {
        return NULL;
    }

    SECITEM_FreeItem(&self->params.base, PR_FALSE);
    if (SECITEM_CopyItem(self->params.arena, &self->params.base, &params->base) != SECSuccess) {
        return NULL;
    }


    return (PyObject *) self;
}

PyObject *
KEYPQGParams_new_from_SECKEYPQGParams(const SECKEYPQGParams *params)
{
    KEYPQGParams *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (KEYPQGParams *) KEYPQGParamsType.tp_new(&KEYPQGParamsType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if ((KEYPQGParams_init_from_SECKEYPQGParams(self, params) == NULL)) {
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* =========================== RSAPublicKey Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

// FIXME - shouldn these return a pyLong instead of a SecItem?
// via integer_secitem_to_pylong()

static PyObject *
RSAPublicKey_get_modulus(RSAPublicKey *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_modulus);
    return self->py_modulus;
}

static PyObject *
RSAPublicKey_get_exponent(RSAPublicKey *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_exponent);
    return self->py_exponent;
}

static
PyGetSetDef RSAPublicKey_getseters[] = {
    {"modulus",  (getter)RSAPublicKey_get_modulus,  (setter)NULL, "RSA modulus", NULL},
    {"exponent", (getter)RSAPublicKey_get_exponent, (setter)NULL, "RSA exponent", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef RSAPublicKey_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
RSAPublicKey_format_lines(RSAPublicKey *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if ((obj = RSAPublicKey_get_modulus(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_SEC_INT_OBJ_APPEND_AND_CLEAR(lines, _("Modulus"), obj, level, fail);

    if ((obj = RSAPublicKey_get_exponent(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_SEC_INT_OBJ_APPEND_AND_CLEAR(lines, _("Exponent"), obj, level, fail);

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
RSAPublicKey_format(RSAPublicKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)RSAPublicKey_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
RSAPublicKey_str(RSAPublicKey *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  RSAPublicKey_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef RSAPublicKey_methods[] = {
    {"format_lines", (PyCFunction)RSAPublicKey_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)RSAPublicKey_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
RSAPublicKey_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    RSAPublicKey *self;

    TraceObjNewEnter(type);

    if ((self = (RSAPublicKey *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->py_modulus = NULL;
    self->py_exponent = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
RSAPublicKey_traverse(RSAPublicKey *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_modulus);
    Py_VISIT(self->py_exponent);
    return 0;
}

static int
RSAPublicKey_clear(RSAPublicKey* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_modulus);
    Py_CLEAR(self->py_exponent);
    return 0;
}

static void
RSAPublicKey_dealloc(RSAPublicKey* self)
{
    TraceMethodEnter(self);

    RSAPublicKey_clear(self);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(RSAPublicKey_doc,
"An object representing an RSA Public Key");

static int
RSAPublicKey_init(RSAPublicKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return 0;
}

static PyObject *
RSAPublicKey_repr(RSAPublicKey *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject RSAPublicKeyType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.RSAPublicKey",			/* tp_name */
    sizeof(RSAPublicKey),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)RSAPublicKey_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)RSAPublicKey_repr,		/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)RSAPublicKey_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    RSAPublicKey_doc,				/* tp_doc */
    (traverseproc)RSAPublicKey_traverse,	/* tp_traverse */
    (inquiry)RSAPublicKey_clear,		/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    RSAPublicKey_methods,			/* tp_methods */
    RSAPublicKey_members,			/* tp_members */
    RSAPublicKey_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)RSAPublicKey_init,		/* tp_init */
    0,						/* tp_alloc */
    RSAPublicKey_new,				/* tp_new */
};

PyObject *
RSAPublicKey_new_from_SECKEYRSAPublicKey(SECKEYRSAPublicKey *rsa)
{
    RSAPublicKey *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (RSAPublicKey *) RSAPublicKeyType.tp_new(&RSAPublicKeyType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if ((self->py_modulus = SecItem_new_from_SECItem(&rsa->modulus, SECITEM_unknown)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_exponent = SecItem_new_from_SECItem(&rsa->publicExponent, SECITEM_unknown)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* =========================== DSAPublicKey Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
DSAPublicKey_get_pqg_params(DSAPublicKey *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_pqg_params);
    return self->py_pqg_params;
}

static PyObject *
DSAPublicKey_get_public_value(DSAPublicKey *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_public_value);
    return self->py_public_value;
}

static
PyGetSetDef DSAPublicKey_getseters[] = {
    {"pqg_params",   (getter)DSAPublicKey_get_pqg_params,   (setter)NULL, "DSA P,Q,G params as a KEYPQGParams object", NULL},
    {"public_value", (getter)DSAPublicKey_get_public_value, (setter)NULL, "DSA public_value", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef DSAPublicKey_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
DSAPublicKey_format_lines(DSAPublicKey *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *exponent = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if ((obj = DSAPublicKey_get_pqg_params(self, NULL)) == NULL) {
        goto fail;
    }
    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = DSAPublicKey_get_public_value(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_SEC_INT_OBJ_APPEND_AND_CLEAR(lines, _("Public Value"), obj, level, fail);
    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(exponent);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
DSAPublicKey_format(DSAPublicKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)DSAPublicKey_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
DSAPublicKey_str(DSAPublicKey *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  DSAPublicKey_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef DSAPublicKey_methods[] = {
    {"format_lines", (PyCFunction)DSAPublicKey_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)DSAPublicKey_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
DSAPublicKey_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    DSAPublicKey *self;

    TraceObjNewEnter(type);

    if ((self = (DSAPublicKey *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->py_pqg_params = NULL;
    self->py_public_value = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
DSAPublicKey_traverse(DSAPublicKey *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_pqg_params);
    Py_VISIT(self->py_public_value);
    return 0;
}

static int
DSAPublicKey_clear(DSAPublicKey* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_pqg_params);
    Py_CLEAR(self->py_public_value);
    return 0;
}

static void
DSAPublicKey_dealloc(DSAPublicKey* self)
{
    TraceMethodEnter(self);

    DSAPublicKey_clear(self);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(DSAPublicKey_doc,
"A object representing a DSA Public Key");

static int
DSAPublicKey_init(DSAPublicKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return 0;
}

static PyObject *
DSAPublicKey_repr(DSAPublicKey *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject DSAPublicKeyType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.DSAPublicKey",			/* tp_name */
    sizeof(DSAPublicKey),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)DSAPublicKey_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)DSAPublicKey_repr,		/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)DSAPublicKey_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    DSAPublicKey_doc,				/* tp_doc */
    (traverseproc)DSAPublicKey_traverse,	/* tp_traverse */
    (inquiry)DSAPublicKey_clear,		/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    DSAPublicKey_methods,			/* tp_methods */
    DSAPublicKey_members,			/* tp_members */
    DSAPublicKey_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)DSAPublicKey_init,		/* tp_init */
    0,						/* tp_alloc */
    DSAPublicKey_new,				/* tp_new */
};

PyObject *
DSAPublicKey_new_from_SECKEYDSAPublicKey(SECKEYDSAPublicKey *dsa)
{
    DSAPublicKey *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (DSAPublicKey *) DSAPublicKeyType.tp_new(&DSAPublicKeyType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if ((self->py_pqg_params = KEYPQGParams_new_from_SECKEYPQGParams(&dsa->params)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_public_value = SecItem_new_from_SECItem(&dsa->publicValue, SECITEM_unknown)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ============================= SignedData Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
SignedData_get_der(SignedData *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_der);
    return self->py_der;
}

static PyObject *
SignedData_get_data(SignedData *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_data);
    return self->py_data;
}

static PyObject *
SignedData_get_algorithm(SignedData *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_algorithm);
    return self->py_algorithm;
}

static PyObject *
SignedData_get_signature(SignedData *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_signature);
    return self->py_signature;
}

static
PyGetSetDef SignedData_getseters[] = {
    {"der",        (getter)SignedData_get_der,        (setter)NULL, "original der encoded ASN1 signed data as a SecItem object", NULL},
    {"data",       (getter)SignedData_get_data,       (setter)NULL, "signed data as a SecItem object", NULL},
    {"algorithm",  (getter)SignedData_get_algorithm,  (setter)NULL, "signature algorithm as a AlgorithmID object", NULL},
    {"signature",  (getter)SignedData_get_signature,  (setter)NULL, "signature as a SecItem object", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef SignedData_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
SignedData_format_lines(SignedData *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if ((obj = SignedData_get_algorithm(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_LABEL_AND_APPEND(lines, _("Signature Algorithm"), level, fail);
    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+1, fail);
    Py_CLEAR(obj);

    FMT_LABEL_AND_APPEND(lines, _("Signature"), level, fail);

    if ((obj = SignedData_get_signature(self, NULL)) == NULL) {
        goto fail;
    }
    APPEND_OBJ_TO_HEX_LINES_AND_CLEAR(lines, obj, level+1, fail);

    obj = fingerprint_format_lines(&((SecItem *)self->py_der)->item, level);
    APPEND_LINE_TUPLES_AND_CLEAR(lines, obj, fail);

    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
SignedData_format(SignedData *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)SignedData_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
SignedData_str(SignedData *self)
{
    PyObject *py_formatted_result = NULL;

    py_formatted_result =  SignedData_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef SignedData_methods[] = {
    {"format_lines", (PyCFunction)SignedData_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)SignedData_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
SignedData_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    SignedData *self;

    TraceObjNewEnter(type);

    if ((self = (SignedData *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->py_der = NULL;
    self->py_data = NULL;
    self->py_algorithm = NULL;
    self->py_signature = NULL;

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL ) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    memset(&self->signed_data, 0, sizeof(self->signed_data));

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
SignedData_traverse(SignedData *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_der);
    Py_VISIT(self->py_data);
    Py_VISIT(self->py_algorithm);
    Py_VISIT(self->py_signature);
    return 0;
}

static int
SignedData_clear(SignedData* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_der);
    Py_CLEAR(self->py_data);
    Py_CLEAR(self->py_algorithm);
    Py_CLEAR(self->py_signature);
    return 0;
}

static void
SignedData_dealloc(SignedData* self)
{
    TraceMethodEnter(self);

    SignedData_clear(self);
    PORT_FreeArena(self->arena, PR_FALSE);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(SignedData_doc,
"A object representing a signature");

static int
SignedData_init(SignedData *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return 0;
}

static PyObject *
SignedData_repr(SignedData *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject SignedDataType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.SignedData",			/* tp_name */
    sizeof(SignedData),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)SignedData_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)SignedData_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)SignedData_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    SignedData_doc,				/* tp_doc */
    (traverseproc)SignedData_traverse,		/* tp_traverse */
    (inquiry)SignedData_clear,			/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    SignedData_methods,				/* tp_methods */
    SignedData_members,				/* tp_members */
    SignedData_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)SignedData_init,			/* tp_init */
    0,						/* tp_alloc */
    SignedData_new,				/* tp_new */
};

PyObject *
SignedData_new_from_SECItem(SECItem *item)
{
    SignedData *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (SignedData *) SignedDataType.tp_new(&SignedDataType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (SEC_ASN1DecodeItem(self->arena, &self->signed_data,
                           SEC_ASN1_GET(CERT_SignedDataTemplate), item) != SECSuccess) {
        set_nspr_error("cannot decode DER encoded signed data");
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_der =
         SecItem_new_from_SECItem(item, SECITEM_signed_data)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_data =
         SecItem_new_from_SECItem(&self->signed_data.data, SECITEM_unknown)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_algorithm =
         AlgorithmID_new_from_SECAlgorithmID(&self->signed_data.signatureAlgorithm)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    DER_ConvertBitString(&self->signed_data.signature);
    if ((self->py_signature =
         SecItem_new_from_SECItem(&self->signed_data.signature, SECITEM_signature)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ============================= PublicKey Class ============================ */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
PublicKey_get_key_type(PublicKey *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->pk->keyType);
}

static PyObject *
PublicKey_get_key_type_str(PublicKey *self, void *closure)
{
    TraceMethodEnter(self);

    return PyString_FromString(key_type_str(self->pk->keyType));
}

static PyObject *
PublicKey_get_rsa(PublicKey *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->pk->keyType == rsaKey) {
        Py_INCREF(self->py_rsa_key);
        return self->py_rsa_key;
    } else {
        PyErr_Format(PyExc_AttributeError, "when '%.50s' object has key_type=%s there is no attribute 'rsa'",
                     Py_TYPE(self)->tp_name, key_type_str(self->pk->keyType));
        return NULL;
    }
}

static PyObject *
PublicKey_get_dsa(PublicKey *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->pk->keyType == dsaKey) {
        Py_INCREF(self->py_dsa_key);
        return self->py_dsa_key;
    } else {
        PyErr_Format(PyExc_AttributeError, "when '%.50s' object has key_type=%s there is no attribute 'dsa'",
                     Py_TYPE(self)->tp_name, key_type_str(self->pk->keyType));
        return NULL;
    }
}

static
PyGetSetDef PublicKey_getseters[] = {
    {"key_type",     (getter)PublicKey_get_key_type,     (setter)NULL, "key type (e.g. rsaKey, dsaKey, etc.) as an int", NULL},
    {"key_type_str", (getter)PublicKey_get_key_type_str, (setter)NULL, "key type as a string", NULL},
    {"rsa",          (getter)PublicKey_get_rsa,          (setter)NULL, "RSA key as a RSAPublicKey object", NULL},
    {"dsa",          (getter)PublicKey_get_dsa,          (setter)NULL, "RSA key as a RSAPublicKey object", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef PublicKey_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
PublicKey_format_lines(PublicKey *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *py_key = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        goto fail;
    }

    switch(self->pk->keyType) {       /* FIXME: handle the other cases */
    case rsaKey:
        FMT_LABEL_AND_APPEND(lines, _("RSA Public Key"), level, fail);
        CALL_FORMAT_LINES_AND_APPEND(lines, self->py_rsa_key, level+1, fail);
        break;
    case dsaKey:
        FMT_LABEL_AND_APPEND(lines, _("DSA Public Key"), level, fail);
        CALL_FORMAT_LINES_AND_APPEND(lines, self->py_dsa_key, level+1, fail);
        break;
    case fortezzaKey:
    case dhKey:
    case keaKey:
    case ecKey:
    case rsaPssKey:
    case rsaOaepKey:
    case nullKey:
        if ((obj = PublicKey_get_key_type_str(self, NULL)) == NULL) {
            goto fail;
        }
        FMT_OBJ_AND_APPEND(lines, _("Key Type"), obj, level, fail);
        Py_CLEAR(obj);
        break;
    }

    return lines;

 fail:
    Py_XDECREF(lines);
    Py_XDECREF(obj);
    Py_XDECREF(py_key);
    return NULL;
}

static PyObject *
PublicKey_format(PublicKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)PublicKey_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
PublicKey_str(PublicKey *self)
{
    PyObject *py_formatted_result = NULL;

    py_formatted_result = PublicKey_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef PublicKey_methods[] = {
    {"format_lines", (PyCFunction)PublicKey_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)PublicKey_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
PublicKey_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PublicKey *self;

    TraceObjNewEnter(type);

    if ((self = (PublicKey *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->py_rsa_key = NULL;
    self->py_dsa_key = NULL;

    memset(&self->pk, 0, sizeof(self->pk));

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
PublicKey_traverse(PublicKey *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_rsa_key);
    Py_VISIT(self->py_dsa_key);
    return 0;
}

static int
PublicKey_clear(PublicKey* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_rsa_key);
    Py_CLEAR(self->py_dsa_key);
    return 0;
}

static void
PublicKey_dealloc(PublicKey* self)
{
    TraceMethodEnter(self);

    PublicKey_clear(self);
    SECKEY_DestroyPublicKey(self->pk);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(PublicKey_doc,
"An object representing a Public Key");

static int
PublicKey_init(PublicKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return 0;
}

static PyObject *
PublicKey_repr(PublicKey *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject PublicKeyType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.PublicKey",			/* tp_name */
    sizeof(PublicKey),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)PublicKey_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)PublicKey_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)PublicKey_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    PublicKey_doc,				/* tp_doc */
    (traverseproc)PublicKey_traverse,		/* tp_traverse */
    (inquiry)PublicKey_clear,			/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    PublicKey_methods,				/* tp_methods */
    PublicKey_members,				/* tp_members */
    PublicKey_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)PublicKey_init,			/* tp_init */
    0,						/* tp_alloc */
    PublicKey_new,				/* tp_new */
};

PyObject *
PublicKey_new_from_SECKEYPublicKey(SECKEYPublicKey *pk)
{
    PublicKey *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (PublicKey *) PublicKeyType.tp_new(&PublicKeyType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->pk = pk;

    switch(pk->keyType) {       /* FIXME: handle the other cases */
    case rsaKey:
        if ((self->py_rsa_key = RSAPublicKey_new_from_SECKEYRSAPublicKey(&pk->u.rsa)) == NULL) {
            Py_CLEAR(self);
            return NULL;
        }
        break;
    case dsaKey:
        if ((self->py_dsa_key = DSAPublicKey_new_from_SECKEYDSAPublicKey(&pk->u.dsa)) == NULL) {
            Py_CLEAR(self);
            return NULL;
        }
        break;
    case fortezzaKey:
    case dhKey:
    case keaKey:
    case ecKey:
    case rsaPssKey:
    case rsaOaepKey:
    case nullKey:
        break;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ======================= SubjectPublicKeyInfo Class ======================= */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
SubjectPublicKeyInfo_get_algorithm(SubjectPublicKeyInfo *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_algorithm);
    return self->py_algorithm;
}

static PyObject *
SubjectPublicKeyInfo_get_public_key(SubjectPublicKeyInfo *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_public_key);
    return self->py_public_key;
}

static
PyGetSetDef SubjectPublicKeyInfo_getseters[] = {
    {"algorithm",  (getter)SubjectPublicKeyInfo_get_algorithm,  (setter)NULL, "algorithm", NULL},
    {"public_key", (getter)SubjectPublicKeyInfo_get_public_key, (setter)NULL, "PublicKey object", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef SubjectPublicKeyInfo_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
SubjectPublicKeyInfo_format_lines(SubjectPublicKeyInfo *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *py_public_key = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if ((obj = SubjectPublicKeyInfo_get_algorithm(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_LABEL_AND_APPEND(lines, _("Public Key Algorithm"), level, fail);
    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+1, fail);
    Py_CLEAR(obj);

    if ((py_public_key = SubjectPublicKeyInfo_get_public_key(self, NULL)) == NULL) {
        goto fail;
    }

    CALL_FORMAT_LINES_AND_APPEND(lines, py_public_key, level, fail);
    Py_CLEAR(py_public_key);

    return lines;
 fail:
    Py_XDECREF(lines);
    Py_XDECREF(py_public_key);
    return NULL;
}

static PyObject *
SubjectPublicKeyInfo_format(SubjectPublicKeyInfo *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)SubjectPublicKeyInfo_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
SubjectPublicKeyInfo_str(SubjectPublicKeyInfo *self)
{
    PyObject *py_formatted_result = NULL;

    py_formatted_result =  SubjectPublicKeyInfo_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef SubjectPublicKeyInfo_methods[] = {
    {"format_lines", (PyCFunction)SubjectPublicKeyInfo_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)SubjectPublicKeyInfo_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
SubjectPublicKeyInfo_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    SubjectPublicKeyInfo *self;

    TraceObjNewEnter(type);

    if ((self = (SubjectPublicKeyInfo *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->py_algorithm = NULL;
    self->py_public_key = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
SubjectPublicKeyInfo_traverse(SubjectPublicKeyInfo *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_algorithm);
    Py_VISIT(self->py_public_key);
    return 0;
}

static int
SubjectPublicKeyInfo_clear(SubjectPublicKeyInfo* self)
{
    TraceMethodEnter(self);

    DumpRefCount(self->py_public_key);
    Py_CLEAR(self->py_algorithm);
    Py_CLEAR(self->py_public_key);
    return 0;
}

static void
SubjectPublicKeyInfo_dealloc(SubjectPublicKeyInfo* self)
{
    TraceMethodEnter(self);

    SubjectPublicKeyInfo_clear(self);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(SubjectPublicKeyInfo_doc,
"An object representing a Subject Public Key");

static int
SubjectPublicKeyInfo_init(SubjectPublicKeyInfo *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return 0;
}

static PyObject *
SubjectPublicKeyInfo_repr(SubjectPublicKeyInfo *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject SubjectPublicKeyInfoType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.SubjectPublicKeyInfo",		/* tp_name */
    sizeof(SubjectPublicKeyInfo),		/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)SubjectPublicKeyInfo_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)SubjectPublicKeyInfo_repr,	/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)SubjectPublicKeyInfo_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    SubjectPublicKeyInfo_doc,			/* tp_doc */
    (traverseproc)SubjectPublicKeyInfo_traverse, /* tp_traverse */
    (inquiry)SubjectPublicKeyInfo_clear,	/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    SubjectPublicKeyInfo_methods,		/* tp_methods */
    SubjectPublicKeyInfo_members,		/* tp_members */
    SubjectPublicKeyInfo_getseters,		/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)SubjectPublicKeyInfo_init,	/* tp_init */
    0,						/* tp_alloc */
    SubjectPublicKeyInfo_new,			/* tp_new */
};

PyObject *
SubjectPublicKeyInfo_new_from_CERTSubjectPublicKeyInfo(CERTSubjectPublicKeyInfo *spki)
{
    SubjectPublicKeyInfo *self = NULL;
    SECKEYPublicKey *pk = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (SubjectPublicKeyInfo *) SubjectPublicKeyInfoType.tp_new(&SubjectPublicKeyInfoType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if ((self->py_algorithm = AlgorithmID_new_from_SECAlgorithmID(&spki->algorithm)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    if ((pk = SECKEY_ExtractPublicKey(spki)) == NULL) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_public_key = PublicKey_new_from_SECKEYPublicKey(pk)) == NULL) {
	SECKEY_DestroyPublicKey(pk);
        Py_CLEAR(self);
        return NULL;
    }
    DumpRefCount(self->py_public_key);

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ============================== Utilities ============================= */

static CERTDistNames *
cert_distnames_as_CERTDistNames(PyObject *py_distnames)
{
    PRArenaPool *arena = NULL;
    CERTDistNames *names = NULL;
    int i;
    SecItem *py_sec_item;

    if (!(PyList_Check(py_distnames) || PyTuple_Check(py_distnames))) {
        PyErr_SetString(PyExc_TypeError, "cert distnames must be a list or tuple");
        return NULL;
    }

    /* allocate an arena to use */
    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL ) {
        set_nspr_error(NULL);
        return NULL;
    }

    /* allocate the header structure */
    if ((names = (CERTDistNames *)PORT_ArenaAlloc(arena, sizeof(CERTDistNames))) == NULL) {
        PORT_FreeArena(arena, PR_FALSE);
        PyErr_NoMemory();
        return NULL;
    }

    /* initialize the header struct */
    names->arena = arena;
    names->head = NULL;
    names->nnames = PySequence_Size(py_distnames);
    names->names = NULL;

    /* construct the array from the list */
    if (names->nnames) {
	names->names = (SECItem *)PORT_ArenaAlloc(arena, names->nnames * sizeof(SECItem));

	if (names->names == NULL) {
            PORT_FreeArena(arena, PR_FALSE);
            PyErr_NoMemory();
            return NULL;
	}

	for (i = 0; i < names->nnames; i++) {
            py_sec_item = (SecItem *)PySequence_GetItem(py_distnames, i); /* new reference */
            if ((!PySecItem_Check(py_sec_item)) || (py_sec_item->kind != SECITEM_dist_name)) {
                PyErr_Format(PyExc_TypeError, "item must be a %s containing a DistName",
                             SecItemType.tp_name);
                Py_DECREF(py_sec_item);
                PORT_FreeArena(arena, PR_FALSE);
                return NULL;
            }
            if (SECITEM_CopyItem(arena, &names->names[i], &py_sec_item->item) != SECSuccess) {
                Py_DECREF(py_sec_item);
                PORT_FreeArena(arena, PR_FALSE);
                return NULL;
            }
            Py_DECREF(py_sec_item);
	}
    }
    return names;
}

/* ========================================================================== */
/* =============================== CertDB Class ============================= */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static
PyGetSetDef CertDB_getseters[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef CertDB_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(CertDB_find_crl_by_name_doc,
"find_crl_by_name(name, type=SEC_CRL_TYPE) -> SignedCRL object\n\
\n\
:Parameters:\n\
    name : string\n\
        name to lookup\n\
    type : int\n\
        revocation list type\n\
        \n\
        may be one of:\n\
          - SEC_CRL_TYPE\n\
          - SEC_KRL_TYPE\n\
\n\
Returns a SignedCRL object found in the database given a name and revocation list type.\n\
"
);
static PyObject *
CertDB_find_crl_by_name(CertDB *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"name", "type", NULL};
    char *name;
    int type = SEC_CRL_TYPE;
    CERTName *cert_name;
    SECItem *der_name;
    CERTSignedCrl *signed_crl;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|i:find_crl_by_name", kwlist,
                                     &name, &type))
        return NULL;

    if ((cert_name = CERT_AsciiToName(name)) == NULL) {
        return set_nspr_error(NULL);
    }

    if ((der_name = SEC_ASN1EncodeItem (NULL, NULL, (void *)cert_name,
                                        SEC_ASN1_GET(CERT_NameTemplate))) == NULL) {
        CERT_DestroyName(cert_name);
        return set_nspr_error(NULL);
    }
    CERT_DestroyName(cert_name);

    if ((signed_crl = SEC_FindCrlByName(self->handle, der_name, type)) == NULL) {
        SECITEM_FreeItem(der_name, PR_TRUE);
        return set_nspr_error(NULL);
    }
    SECITEM_FreeItem(der_name, PR_TRUE);

    return SignedCRL_new_from_CERTSignedCRL(signed_crl);
}

PyDoc_STRVAR(CertDB_find_crl_by_cert_doc,
"find_crl_by_cert(cert, type=SEC_CRL_TYPE) -> SignedCRL object\n\
\n\
:Parameters:\n\
    cert : Certificate object\n\
        certificate used to lookup the CRL.\n\
    type : int\n\
        revocation list type\n\
        \n\
        may be one of:\n\
          - SEC_CRL_TYPE\n\
          - SEC_KRL_TYPE\n\
\n\
Returns a SignedCRL object found in the database given a certificate and revocation list type.\n\
"
);
static PyObject *
CertDB_find_crl_by_cert(CertDB *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"cert", "type", NULL};
    int type = SEC_CRL_TYPE;
    Certificate *py_cert = NULL;
    SECItem *der_cert;
    CERTSignedCrl *signed_crl;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|i:find_crl_by_cert", kwlist,
                                     &CertificateType, &py_cert, &type))
        return NULL;

    der_cert = &py_cert->cert->derCert;
    if ((signed_crl = SEC_FindCrlByDERCert(self->handle, der_cert, type)) == NULL) {
        return set_nspr_error(NULL);
    }

    return SignedCRL_new_from_CERTSignedCRL(signed_crl);
}


static PyMethodDef CertDB_methods[] = {
    {"find_crl_by_name", (PyCFunction)CertDB_find_crl_by_name, METH_VARARGS|METH_KEYWORDS, CertDB_find_crl_by_name_doc},
    {"find_crl_by_cert", (PyCFunction)CertDB_find_crl_by_cert, METH_VARARGS|METH_KEYWORDS, CertDB_find_crl_by_cert_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
CertDB_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    CertDB *self;

    TraceObjNewEnter(type);

    if ((self = (CertDB *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }
    self->handle = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
CertDB_dealloc(CertDB* self)
{
    TraceMethodEnter(self);

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(CertDB_doc,
"An object representing a Certificate Database");

static int
CertDB_init(CertDB *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);
    return 0;
}

static PyTypeObject CertDBType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.CertDB",				/* tp_name */
    sizeof(CertDB),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CertDB_dealloc,			/* tp_dealloc */
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
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    CertDB_doc,					/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    CertDB_methods,				/* tp_methods */
    CertDB_members,				/* tp_members */
    CertDB_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)CertDB_init,			/* tp_init */
    0,						/* tp_alloc */
    CertDB_new,					/* tp_new */
};

PyObject *
CertDB_new_from_CERTCertDBHandle(CERTCertDBHandle *certdb_handle)
{
    CertDB *self = NULL;

    TraceObjNewEnter(NULL);
    if ((self = (CertDB *) CertDBType.tp_new(&CertDBType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->handle = certdb_handle;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

static PyObject *
cert_distnames_new_from_CERTDistNames(CERTDistNames *names)
{
    PyObject *py_distnames = NULL;
    PyObject *py_sec_item = NULL;
    int i, len;

    len = names->nnames;
    if ((py_distnames = PyTuple_New(len)) == NULL) {
        return NULL;
    }

    for (i = 0; i< names->nnames; i++) {
        if ((py_sec_item = SecItem_new_from_SECItem(&names->names[i], SECITEM_dist_name)) == NULL) {
            Py_DECREF(py_distnames);
            return NULL;
        }
        PyTuple_SetItem(py_distnames, i, py_sec_item);
    }

    return py_distnames;
}

/* ========================================================================== */
/* ======================== CertificateExtension Class ====================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
CertificateExtension_get_name(CertificateExtension *self, void *closure)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pystr_desc(&self->py_oid->item);
}

static PyObject *
CertificateExtension_get_critical(CertificateExtension *self, void *closure)
{
    TraceMethodEnter(self);

    return PyBool_FromLong(self->critical);
}

static PyObject *
CertificateExtension_get_oid(CertificateExtension *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_oid);
    return (PyObject *)self->py_oid;
}

static PyObject *
CertificateExtension_get_oid_tag(CertificateExtension *self, void *closure)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pyint_tag(&self->py_oid->item);
}

static PyObject *
CertificateExtension_get_value(CertificateExtension *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_value);
    return (PyObject *)self->py_value;
}

static
PyGetSetDef CertificateExtension_getseters[] = {
    {"name",     (getter)CertificateExtension_get_name,     (setter)NULL, "name of extension", NULL},
    {"critical", (getter)CertificateExtension_get_critical, (setter)NULL, "extension is critical flag (boolean)", NULL},
    {"oid",      (getter)CertificateExtension_get_oid,      (setter)NULL, "oid of extension as SecItem", NULL},
    {"oid_tag",  (getter)CertificateExtension_get_oid_tag,  (setter)NULL, "oid of extension as a enumerated constant (e.g. tag)", NULL},
    {"value",    (getter)CertificateExtension_get_value,    (setter)NULL, "extension data as SecItem", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef CertificateExtension_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
CertificateExtension_format_lines(CertificateExtension *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *obj1 = NULL;
    SECOidTag oid_tag;
    PyObject *obj_lines = NULL;
    PyObject *tmp_args = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        goto fail;
    }

    if ((obj = CertificateExtension_get_name(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Name"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = CertificateExtension_get_critical(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Critical"), obj, level, fail);
    Py_CLEAR(obj);

    oid_tag = SECOID_FindOIDTag(&self->py_oid->item);

    switch(oid_tag) {
    case SEC_OID_PKCS12_KEY_USAGE:
        FMT_LABEL_AND_APPEND(lines, _("Usages"), level, fail);
        if ((tmp_args = Py_BuildValue("(O)", self->py_value)) == NULL) {
            goto fail;
        }
        if ((obj = cert_x509_key_usage(NULL, tmp_args, NULL)) == NULL) {
            goto fail;
        }
        Py_CLEAR(tmp_args);
        if ((obj_lines = make_line_fmt_tuples(level+1, obj)) == NULL) {
            goto fail;
        }
        APPEND_LINE_TUPLES_AND_CLEAR(lines, obj_lines, fail);
        break;

    case SEC_OID_NS_CERT_EXT_CERT_TYPE:
        FMT_LABEL_AND_APPEND(lines, _("Types"), level, fail);
        if ((tmp_args = Py_BuildValue("(O)", self->py_value)) == NULL) {
            goto fail;
        }
        if ((obj = cert_x509_cert_type(NULL, tmp_args, NULL)) == NULL) {
            goto fail;
        }
        Py_CLEAR(tmp_args);
        if ((obj_lines = make_line_fmt_tuples(level+1, obj)) == NULL) {
            goto fail;
        }
        APPEND_LINE_TUPLES_AND_CLEAR(lines, obj_lines, fail);
        break;

    case SEC_OID_X509_SUBJECT_KEY_ID:
        FMT_LABEL_AND_APPEND(lines, _("Data"), level, fail);
        if ((obj_lines = SECItem_der_to_hex(&self->py_value->item,
                                            OCTETS_PER_LINE_DEFAULT, HEX_SEPARATOR_DEFAULT)) == NULL) {
            goto fail;
        }
        APPEND_LINES_AND_CLEAR(lines, obj_lines, level+1, fail);
        break;

    case SEC_OID_X509_CRL_DIST_POINTS:
        if ((obj = CRLDistributionPts_new_from_SECItem(&self->py_value->item)) == NULL) {
            goto fail;
        }
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level, fail);
        Py_CLEAR(obj);
        break;

    case SEC_OID_X509_AUTH_INFO_ACCESS:
        if ((obj = AuthorityInfoAccesses_new_from_SECItem(&self->py_value->item)) == NULL) {
            goto fail;
        }
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level, fail);
        Py_CLEAR(obj);
        break;

    case SEC_OID_X509_AUTH_KEY_ID:
        if ((obj = AuthKeyID_new_from_SECItem(&self->py_value->item)) == NULL) {
            goto fail;
        }
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level, fail);
        Py_CLEAR(obj);

        break;

    case SEC_OID_X509_EXT_KEY_USAGE:
        FMT_LABEL_AND_APPEND(lines, _("Usages"), level, fail);
        if ((tmp_args = Py_BuildValue("(O)", self->py_value)) == NULL) {
            goto fail;
        }
        if ((obj = cert_x509_ext_key_usage(NULL, tmp_args, NULL)) == NULL) {
            goto fail;
        }
        Py_CLEAR(tmp_args);
        if ((obj_lines = make_line_fmt_tuples(level+1, obj)) == NULL) {
            goto fail;
        }
        APPEND_LINE_TUPLES_AND_CLEAR(lines, obj_lines, fail);
        break;

    case SEC_OID_X509_BASIC_CONSTRAINTS:
        if ((obj = BasicConstraints_new_from_SECItem(&self->py_value->item)) == NULL) {
            goto fail;
        }
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level, fail);
        Py_CLEAR(obj);

        break;

    case SEC_OID_X509_SUBJECT_ALT_NAME:
    case SEC_OID_X509_ISSUER_ALT_NAME:
        FMT_LABEL_AND_APPEND(lines, _("Names"), level, fail);
        if ((tmp_args = Py_BuildValue("(O)", self->py_value)) == NULL) {
            goto fail;
        }
        if ((obj = cert_x509_alt_name(NULL, tmp_args, NULL)) == NULL) {
            goto fail;
        }
        Py_CLEAR(tmp_args);
        if ((obj_lines = make_line_fmt_tuples(level+1, obj)) == NULL) {
            goto fail;
        }
        APPEND_LINE_TUPLES_AND_CLEAR(lines, obj_lines, fail);
        break;

    default:
        break;
    }

    return lines;

 fail:
    Py_XDECREF(lines);
    Py_XDECREF(obj);
    Py_XDECREF(obj1);
    Py_XDECREF(obj_lines);
    Py_XDECREF(tmp_args);
    return NULL;
}

static PyObject *
CertificateExtension_format(CertificateExtension *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)CertificateExtension_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
CertificateExtension_repr(CertificateExtension *self)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pystr_desc(&self->py_oid->item);
}

static PyObject *
CertificateExtension_str(CertificateExtension *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  CertificateExtension_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef CertificateExtension_methods[] = {
    {"format_lines", (PyCFunction)CertificateExtension_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)CertificateExtension_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
CertificateExtension_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    CertificateExtension *self;

    TraceObjNewEnter(type);

    if ((self = (CertificateExtension *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->py_oid = NULL;
    self->py_value = NULL;
    self->critical = 0;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
CertificateExtension_traverse(CertificateExtension *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_oid);
    Py_VISIT(self->py_value);
    return 0;
}

static int
CertificateExtension_clear(CertificateExtension* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_oid);
    Py_CLEAR(self->py_value);
    return 0;
}

static void
CertificateExtension_dealloc(CertificateExtension* self)
{
    TraceMethodEnter(self);

    CertificateExtension_clear(self);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(CertificateExtension_doc,
"An object representing a certificate extension");

static int
CertificateExtension_init(CertificateExtension *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);
    return 0;
}

static PyTypeObject CertificateExtensionType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.CertificateExtension",		/* tp_name */
    sizeof(CertificateExtension),		/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CertificateExtension_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)CertificateExtension_repr,	/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)CertificateExtension_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    CertificateExtension_doc,			/* tp_doc */
    (traverseproc)CertificateExtension_traverse,/* tp_traverse */
    (inquiry)CertificateExtension_clear,	/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    CertificateExtension_methods,		/* tp_methods */
    CertificateExtension_members,		/* tp_members */
    CertificateExtension_getseters,		/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)CertificateExtension_init,	/* tp_init */
    0,						/* tp_alloc */
    CertificateExtension_new,			/* tp_new */
};

PyObject *
CertificateExtension_new_from_CERTCertExtension(CERTCertExtension *extension)
{
    CertificateExtension *self = NULL;

    TraceObjNewEnter(NULL);
    if ((self = (CertificateExtension *) CertificateExtensionType.tp_new(&CertificateExtensionType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if ((self->py_oid = (SecItem *)
         SecItem_new_from_SECItem(&extension->id, SECITEM_cert_extension_oid)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    if ((self->py_value = (SecItem *)
         SecItem_new_from_SECItem(&extension->value, SECITEM_cert_extension_value)) == NULL) {
        Py_CLEAR(self);
        return NULL;
    }

    if (extension->critical.data && extension->critical.len) {
	self->critical = extension->critical.data[0];
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ============================ Certificate Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
Certificate_get_valid_not_before(Certificate *self, void *closure)
{
    PRTime pr_time = 0;
    double d_time;

    TraceMethodEnter(self);

    pr_time = time_choice_secitem_to_prtime(&self->cert->validity.notBefore);
    LL_L2D(d_time, pr_time);

    return PyFloat_FromDouble(d_time);
}

static PyObject *
Certificate_get_valid_not_before_str(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return time_choice_secitem_to_pystr(&self->cert->validity.notBefore);
}

static PyObject *
Certificate_get_valid_not_after(Certificate *self, void *closure)
{
    PRTime pr_time = 0;
    double d_time;

    TraceMethodEnter(self);

    pr_time = time_choice_secitem_to_prtime(&self->cert->validity.notAfter);
    LL_L2D(d_time, pr_time);

    return PyFloat_FromDouble(d_time);
}

static PyObject *
Certificate_get_valid_not_after_str(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return time_choice_secitem_to_pystr(&self->cert->validity.notAfter);
}

static PyObject *
Certificate_get_subject(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return DN_new_from_CERTName(&self->cert->subject);
}

static PyObject *
Certificate_get_subject_common_name(Certificate *self, void *closure)
{
    char *cn;
    PyObject *py_cn = NULL;

    TraceMethodEnter(self);

    if ((cn = CERT_GetCommonName(&self->cert->subject)) == NULL) {
        Py_RETURN_NONE;
    }

    py_cn = PyString_FromString(cn);
    PORT_Free(cn);

    return py_cn;
}

static PyObject *
Certificate_get_issuer(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return DN_new_from_CERTName(&self->cert->issuer);
}

static PyObject *
Certificate_get_version(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return integer_secitem_to_pylong(&self->cert->version);
}

static PyObject *
Certificate_get_serial_number(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return integer_secitem_to_pylong(&self->cert->serialNumber);
}

// FIXME: should this come from SignedData?
static PyObject *
Certificate_get_signature_algorithm(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return AlgorithmID_new_from_SECAlgorithmID(&self->cert->signature);
}

static PyObject *
Certificate_get_signed_data(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return SignedData_new_from_SECItem(&self->cert->derCert);
}

static PyObject *
Certificate_get_der_data(Certificate *self, void *closure)
{
    SECItem der;

    TraceMethodEnter(self);

    der = self->cert->derCert;
    return PyString_FromStringAndSize((char *)der.data, der.len);
}

static PyObject *
Certificate_get_ssl_trust_str(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->cert->trust)
        return cert_trust_flags(self->cert->trust->sslFlags, AsEnumDescription);
    else
        Py_RETURN_NONE;
}

static PyObject *
Certificate_get_email_trust_str(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->cert->trust)
        return cert_trust_flags(self->cert->trust->emailFlags, AsEnumDescription);
    else
        Py_RETURN_NONE;
}

static PyObject *
Certificate_get_signing_trust_str(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->cert->trust)
        return cert_trust_flags(self->cert->trust->objectSigningFlags, AsEnumDescription);
    else
        Py_RETURN_NONE;
}

static PyObject *
Certificate_get_ssl_trust_flags(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->cert->trust)
        return PyInt_FromLong(self->cert->trust->sslFlags);
    else
        Py_RETURN_NONE;
}

static PyObject *
Certificate_get_email_trust_flags(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->cert->trust)
        return PyInt_FromLong(self->cert->trust->emailFlags);
    else
        Py_RETURN_NONE;
}

static PyObject *
Certificate_get_signing_trust_flags(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->cert->trust)
        return PyInt_FromLong(self->cert->trust->objectSigningFlags);
    else
        Py_RETURN_NONE;
}

static PyObject *
Certificate_get_subject_public_key_info(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return SubjectPublicKeyInfo_new_from_CERTSubjectPublicKeyInfo(
               &self->cert->subjectPublicKeyInfo);
}

static PyObject *
Certificate_get_extensions(Certificate *self, void *closure)
{
    return CERTCertExtension_tuple(self->cert->extensions, AsObject);
}

static PyObject *
Certificate_get_cert_type(Certificate *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->cert->nsCertType);
}

static
PyGetSetDef Certificate_getseters[] = {
    {"valid_not_before",        (getter)Certificate_get_valid_not_before,        NULL,
     "certificate not valid before this time (floating point value expressed as microseconds since the epoch, midnight January 1st 1970 UTC)", NULL},

    {"valid_not_before_str",    (getter)Certificate_get_valid_not_before_str,    NULL,
     "certificate not valid before this time (string value expressed, UTC)", NULL},

    {"valid_not_after",         (getter)Certificate_get_valid_not_after,         NULL,
     "certificate not valid after this time (floating point value expressed as microseconds since the epoch, midnight January 1st 1970, UTC)", NULL},

    {"valid_not_after_str",     (getter)Certificate_get_valid_not_after_str,     NULL,
     "certificate not valid after this time (string value expressed, UTC)", NULL},

    {"subject",                 (getter)Certificate_get_subject,                 NULL,
     "certificate subject as a `DN` object", NULL},

    {"subject_common_name",     (getter)Certificate_get_subject_common_name,     NULL,
     "certificate subject", NULL},

    {"issuer",                  (getter)Certificate_get_issuer,                  NULL,
     "certificate issuer as a `DN` object",  NULL},

    {"version",                 (getter)Certificate_get_version,                 NULL,
     "certificate version",  NULL},

    {"serial_number",           (getter)Certificate_get_serial_number,           NULL,
     "certificate serial number",  NULL},

    {"signature_algorithm",     (getter)Certificate_get_signature_algorithm,     NULL,
     "certificate signature algorithm",  NULL},

    {"signed_data",             (getter)Certificate_get_signed_data,             NULL,
     "certificate signature as SignedData object",  NULL},

    {"der_data",                (getter)Certificate_get_der_data,                NULL,
     "raw certificate DER data as data buffer",  NULL},

    {"ssl_trust_str",           (getter)Certificate_get_ssl_trust_str,           NULL,
     "certificate SSL trust flags as array of strings, or None if trust is not defined",  NULL},

    {"email_trust_str",         (getter)Certificate_get_email_trust_str,         NULL,
     "certificate email trust flags as array of strings, or None if trust is not defined",  NULL},

    {"signing_trust_str",       (getter)Certificate_get_signing_trust_str,       NULL,
     "certificate object signing trust flags as array of strings, or None if trust is not defined",  NULL},

    {"ssl_trust_flags",           (getter)Certificate_get_ssl_trust_flags,           NULL,
     "certificate SSL trust flags as integer bitmask, or None if not defined",  NULL},

    {"email_trust_flags",         (getter)Certificate_get_email_trust_flags,         NULL,
     "certificate email trust flags as integer bitmask, or None if not defined",  NULL},

    {"signing_trust_flags",       (getter)Certificate_get_signing_trust_flags,       NULL,
     "certificate object signing trust flags as integer bitmask, or None if not defined",  NULL},

    {"subject_public_key_info", (getter)Certificate_get_subject_public_key_info, NULL,
     "certificate public info as SubjectPublicKeyInfo object",  NULL},

    {"extensions", (getter)Certificate_get_extensions, NULL,
     "certificate extensions as a tuple of CertificateExtension objects",  NULL},

    {"cert_type",               (getter)Certificate_get_cert_type,                NULL,
     "integer bitmask of NS_CERT_TYPE_* flags, see `nss.cert_type_flags()`",  NULL},

    {NULL}  /* Sentinel */
};

static PyMemberDef Certificate_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(Certificate_trust_flags_doc,
"trust_flags(flags, repr_kind=AsEnumDescription) -> ['flag_name', ...]\n\
\n\
:Parameters:\n\
    flags : int\n\
        certificate trust integer bitmask\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned list will be.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsEnumDescription\n\
            A friendly human readable description of the enumerated constant as a string.\n\
\n\
Given an integer with trust flags encoded as a bitmask\n\
return a sorted list of their values as specified in the repr_kind\n\
\n\
This is a class method.\n\
");

static PyObject *
Certificate_trust_flags(PyObject *cls, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"flags", "repr_kind", NULL};
    int flags = 0;
    RepresentationKind repr_kind = AsEnumDescription;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|i:trust_flags", kwlist,
                                     &flags, &repr_kind))
        return NULL;

    return cert_trust_flags(flags, repr_kind);
}

PyDoc_STRVAR(Certificate_set_trust_attributes_doc,
"set_trust_attributes(trust, certdb, slot, [user_data1, ...])\n\
\n\
:Parameters:\n\
    string : trust\n\
        NSS trust string\n\
    certdb : CertDB object or None\n\
        CertDB certificate database object, if None then the default\n\
        certdb will be supplied by calling `nss.get_default_certdb()`.\n\
    slot : `PK11Slot` object\n\
        The PK11 slot to use. If None defaults to internal\n\
        slot, see `nss.get_internal_key_slot()`\n\
    user_dataN : object\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
");

static PyObject *
Certificate_set_trust_attributes(Certificate *self, PyObject *args)
{
    Py_ssize_t n_base_args = 3;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    char *trust_string = NULL;
    CertDB *py_certdb = NULL;
    CERTCertDBHandle *certdb_handle = NULL;
    PyObject *py_slot = Py_None;
    PK11SlotInfo *slot = NULL;
    CERTCertTrust *trust = NULL;
    SECStatus result = SECFailure;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "sO&O&:set_trust_attributes",
                          &trust_string,
                          CertDBOrNoneConvert, &py_certdb,
                          PK11SlotOrNoneConvert, &py_slot)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    if (py_certdb) {
        certdb_handle = py_certdb->handle;
    } else {
        certdb_handle = CERT_GetDefaultCertDB();
    }

    if (PyNone_Check(py_slot)) {
	slot = PK11_GetInternalKeySlot();
    } else {
        slot = ((PK11Slot *)py_slot)->slot;
    }

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    if ((trust = (CERTCertTrust *)PORT_ZAlloc(sizeof(CERTCertTrust))) == NULL) {
        PyErr_NoMemory();
        goto exit;
    }

    if ((result = CERT_DecodeTrustString(trust, trust_string)) != SECSuccess) {
        set_nspr_error("cannot decode trust string '%s'", trust_string);
        goto exit;
    }

    /*
     * CERT_ChangeCertTrust API does not have a way to pass in a
     * context, so NSS can't prompt for the password if it needs to.
     * check to see if the failure was token not logged in and log in
     * if need be.
     */
    Py_BEGIN_ALLOW_THREADS
    if ((result = CERT_ChangeCertTrust(certdb_handle, self->cert, trust)) != SECSuccess) {
	if (PORT_GetError() == SEC_ERROR_TOKEN_NOT_LOGGED_IN) {
	    if ((result = PK11_Authenticate(slot, PR_TRUE, pin_args)) != SECSuccess) {
                set_nspr_error("Unable to authenticate");
            } else {
                if ((result = CERT_ChangeCertTrust(certdb_handle, self->cert, trust)) != SECSuccess) {
                    set_nspr_error(NULL);
                }
            }
        }
    }
    Py_END_ALLOW_THREADS

 exit:
    Py_DECREF(pin_args);
    PORT_Free(trust);
    if (result == SECSuccess) {
        Py_RETURN_NONE;
    } else {
        return NULL;
    }
}

PyDoc_STRVAR(Certificate_find_kea_type_doc,
"find_kea_type() -> kea_type\n\
Returns key exchange type of the keys in an SSL server certificate.\n\
\n\
May be one of the following:\n\
    - ssl_kea_null\n\
    - ssl_kea_rsa\n\
    - ssl_kea_dh\n\
    - ssl_kea_fortezza (deprecated)\n\
    - ssl_kea_ecdh\n\
"
);
static PyObject *
Certificate_find_kea_type(Certificate *self, PyObject *args)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(NSS_FindCertKEAType(self->cert));
}


PyDoc_STRVAR(Certificate_make_ca_nickname_doc,
"make_ca_nickname() -> string\n\
Returns a nickname for the certificate guaranteed to be unique\n\
within the the current NSS database.\n\
\n\
The nickname is composed thusly:\n\
\n\
A. Establish a name by trying in order:\n\
\n\
   1. subject's common name (i.e. CN)\n\
   2. subject's organizational unit name (i.e. OU)\n\
\n\
B. Establish a realm by trying in order:\n\
\n\
   1. issuer's organization name (i.e. O)\n\
   2. issuer's distinguished name (i.e. DN)\n\
   3. set to \"Unknown CA\"\n\
\n\
C. If name exists the nickname will be \"name - realm\",\n\
   else the nickname will be \"realm\"\n\
\n\
D. Then the nickname will be tested for existence in the database.\n\
   If it does not exist it will be returned as the nickname.\n\
   Else a loop is entered where the nickname will have \" #%d\" appended\n\
   to it where %d is an integer beginning at 1. The generated nickname is\n\
   tested for existence in the dabase until a unique name is found.\n\
\n\
"
);
static PyObject *
Certificate_make_ca_nickname(Certificate *self, PyObject *args)
{
    char *nickname = NULL;
    PyObject *py_nickname = NULL;

    TraceMethodEnter(self);

    if ((nickname = CERT_MakeCANickname(self->cert)) == NULL) {
        return set_nspr_error(NULL);
    }

    py_nickname = PyString_FromString(nickname);
    PR_smprintf_free(nickname);
    return py_nickname;
}


PyDoc_STRVAR(Certificate_verify_hostname_doc,
"verify_hostname(hostname) -> bool\n\
\n\
A restricted regular expression syntax is used to test if the common\n\
name specified in the subject DN of the certificate is a match,\n\
returning True if so, False otherwise.\n\
\n\
The regular expression systax is:\n\
    \\*\n\
        matches anything\n\
    \\?\n\
        matches one character\n\
    \\\\ (backslash)\n\
        escapes a special character\n\
    \\$\n\
         matches the end of the string\n\
    [abc]\n\
        matches one occurrence of a, b, or c. The only character\n\
        that needs to be escaped in this is ], all others are not special.\n\
    [a-z]\n\
        matches any character between a and z\n\
    [^az]\n\
        matches any character except a or z\n\
    \\~\n\
        followed by another shell expression removes any pattern matching\n\
        the shell expression from the match list\n\
    (foo|bar)\n\
        matches either the substring foo or the substring bar.\n\
        These can be shell expressions as well.\n\
");

static PyObject *
Certificate_verify_hostname(Certificate *self, PyObject *args)
{
    char *hostname;
    SECStatus sec_status;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "s:verify_hostname", &hostname))
        return NULL;

    sec_status = CERT_VerifyCertName(self->cert, hostname);

    if (sec_status == SECSuccess)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

PyDoc_STRVAR(Certificate_has_signer_in_ca_names_doc,
"has_signer_in_ca_names(ca_names) -> bool\n\
\n\
:Parameters:\n\
    ca_names : (SecItem, ...)\n\
        Sequence of CA distinguished names. Each item in the sequence must\n\
        be a SecItem object containing a distinguished name.\n\
\n\
Returns True if any of the signers in the certificate chain for a\n\
specified certificate are in the list of CA names, False\n\
otherwise.\n\
");

static PyObject *
Certificate_has_signer_in_ca_names(Certificate *self, PyObject *args)
{
    PyObject *py_ca_names = NULL;
    CERTDistNames *ca_names = NULL;
    SECStatus sec_status;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:has_signer_in_ca_names",
                          &py_ca_names))
        return NULL;

    if ((ca_names = cert_distnames_as_CERTDistNames(py_ca_names)) == NULL) {
        return NULL;
    }

    sec_status = NSS_CmpCertChainWCANames(self->cert, ca_names);
    CERT_FreeDistNames(ca_names);

    if (sec_status == SECSuccess)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}

PyDoc_STRVAR(Certificate_check_valid_times_doc,
"check_valid_times(time=now, allow_override=False) --> validity\n\
\n\
:Parameters:\n\
    time : number or None\n\
        an optional point in time as number of microseconds\n\
        since the NSPR epoch, midnight (00:00:00) 1 January\n\
        1970 UTC, either as an integer or a float. If time \n\
        is None the current time is used.\n\
    allow_override : bool\n\
        If True then check to see if the invalidity has\n\
        been overridden by the user, defaults to False.\n\
\n\
Checks whether a specified time is within a certificate's validity\n\
period.\n\
\n\
Returns one of:\n\
\n\
- secCertTimeValid\n\
- secCertTimeExpired\n\
- secCertTimeNotValidYet\n\
");

static PyObject *
Certificate_check_valid_times(Certificate *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"time", "allow_override", NULL};
    PRTime pr_time = 0;
    PyObject *py_allow_override = NULL;
    PRBool allow_override = PR_FALSE;
    SECCertTimeValidity validity;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O&O!:check_valid_times", kwlist,
                                     PRTimeConvert, &pr_time,
                                     &PyBool_Type, &py_allow_override))
        return NULL;

    if (!pr_time) {
        pr_time = PR_Now();
    }

    if (py_allow_override) {
        allow_override = PyBoolAsPRBool(py_allow_override);
    }

    validity = CERT_CheckCertValidTimes(self->cert, pr_time, allow_override);

    return PyInt_FromLong(validity);
}

PyDoc_STRVAR(Certificate_is_ca_cert_doc,
"is_ca_cert(return_cert_type=False) -> boolean\n\
is_ca_cert(True) -> boolean, cert_type\n\
\n\
:Parameters:\n\
    return_cert_type : boolean\n\
        If True returns both boolean result and certficate\n\
        type bitmask. If False return only boolean result\n\
\n\
Returns True if the cert is a CA cert, False otherwise.\n\
\n\
The function optionally can return a bitmask of NS_CERT_TYPE_*\n\
flags if return_cert_type is True. This is the updated cert type\n\
after applying logic in the context of deciding if the cert is a\n\
CA cert or not. Hint: the cert_type value can be converted to text\n\
with `nss.cert_type_flags()`. Hint: the unmodified cert type flags\n\
can be obtained with the `Certificate.cert_type` property.\n\
\n\
");
static PyObject *
Certificate_is_ca_cert(Certificate *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"return_cert_type", NULL};
    int return_cert_type = false;
    PRBool is_ca = PR_FALSE;
    unsigned int cert_type = 0;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:is_ca_cert", kwlist,
                                     &return_cert_type))
        return NULL;

    is_ca = CERT_IsCACert(self->cert, return_cert_type ? &cert_type : NULL);


    if (return_cert_type) {
        return Py_BuildValue("NI", PyBool_FromLong(is_ca), cert_type);
    } else {
        return PyBool_FromLong(is_ca);
    }
}

PyDoc_STRVAR(Certificate_verify_now_doc,
"verify_now(certdb, check_sig, required_usages, [user_data1, ...]) -> valid_usages\n\
\n\
:Parameters:\n\
    certdb : CertDB object\n\
        CertDB certificate database object\n\
    check_sig : bool\n\
        True if certificate signatures should be checked\n\
    required_usages : integer\n\
        A bitfield of all cert usages that are required for verification\n\
        to succeed. If zero return all possible valid usages.\n\
    user_dataN : object\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Verify a certificate by checking if it's valid and that we\n\
trust the issuer.\n\
\n\
Possible usage bitfield values are:\n\
    - certificateUsageCheckAllUsages\n\
    - certificateUsageSSLClient\n\
    - certificateUsageSSLServer\n\
    - certificateUsageSSLServerWithStepUp\n\
    - certificateUsageSSLCA\n\
    - certificateUsageEmailSigner\n\
    - certificateUsageEmailRecipient\n\
    - certificateUsageObjectSigner\n\
    - certificateUsageUserCertImport\n\
    - certificateUsageVerifyCA\n\
    - certificateUsageProtectedObjectSigner\n\
    - certificateUsageStatusResponder\n\
    - certificateUsageAnyCA\n\
\n\
Returns valid_usages, a bitfield of certificate usages.  If\n\
required_usages is non-zero, the returned bitmap is only for those\n\
required usages, otherwise it is for all possible usages.\n\
\n\
Hint: You can obtain a printable representation of the usage flags\n\
via `cert_usage_flags`.\n\
\n\
Note: See the `Certificate.verify` documentation for details on how\n\
the Certificate verification functions handle errors.\n\
");

static PyObject *
Certificate_verify_now(Certificate *self, PyObject *args)
{
    Py_ssize_t n_base_args = 3;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    CertDB *py_certdb = NULL;
    PyObject *py_check_sig = NULL;
    PRBool check_sig = 0;
    long required_usages = 0;
    SECCertificateUsage returned_usages = 0;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "O!O!l:verify_now",
                          &CertDBType, &py_certdb,
                          &PyBool_Type, &py_check_sig,
                          &required_usages)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    check_sig = PyBoolAsPRBool(py_check_sig);
    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if (CERT_VerifyCertificateNow(py_certdb->handle, self->cert, check_sig,
                                  required_usages, pin_args, &returned_usages) != SECSuccess) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_cert_verify_error(returned_usages, NULL, NULL);
    }
    Py_END_ALLOW_THREADS
    Py_DECREF(pin_args);

    return PyInt_FromLong(returned_usages);
}

PyDoc_STRVAR(Certificate_verify_doc,
"verify(certdb, check_sig, required_usages, time, [user_data1, ...]) -> valid_usages\n\
\n\
:Parameters:\n\
    certdb : CertDB object\n\
        CertDB certificate database object\n\
    check_sig : bool\n\
        True if certificate signatures should be checked\n\
    required_usages : integer\n\
        A bitfield of all cert usages that are required for verification\n\
        to succeed. If zero return all possible valid usages.\n\
    time : number or None\n\
        an optional point in time as number of microseconds\n\
        since the NSPR epoch, midnight (00:00:00) 1 January\n\
        1970 UTC, either as an integer or a float. If time \n\
        is None the current time is used.\n\
    user_dataN : object\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Verify a certificate by checking if it's valid and that we\n\
trust the issuer.\n\
\n\
Possible usage bitfield values are:\n\
    - certificateUsageCheckAllUsages\n\
    - certificateUsageSSLClient\n\
    - certificateUsageSSLServer\n\
    - certificateUsageSSLServerWithStepUp\n\
    - certificateUsageSSLCA\n\
    - certificateUsageEmailSigner\n\
    - certificateUsageEmailRecipient\n\
    - certificateUsageObjectSigner\n\
    - certificateUsageUserCertImport\n\
    - certificateUsageVerifyCA\n\
    - certificateUsageProtectedObjectSigner\n\
    - certificateUsageStatusResponder\n\
    - certificateUsageAnyCA\n\
\n\
Returns valid_usages, a bitfield of certificate usages.\n\
\n\
If required_usages is non-zero, the returned bitmap is only for those\n\
required usages, otherwise it is for all possible usages.\n\
\n\
Hint: You can obtain a printable representation of the usage flags\n\
via `cert_usage_flags`.\n\
\n\
Note: Anytime a NSPR or NSS function returns an error in python-nss it\n\
raises a NSPRError exception. When an exception is raised the normal\n\
return values are discarded because the flow of control continues at\n\
the first except block prepared to catch the exception. Normally this\n\
is what is desired because the return values would be invalid due to\n\
the error. However the certificate verification functions are an\n\
exception (no pun intended). An error might be returned indicating the\n\
cert failed verification but you may still need access to the returned\n\
usage bitmask and the log (if using the log variant). To handle this a\n\
special error exception `CertVerifyError` (derived from `NSPRError`)\n\
is defined which in addition to the normal NSPRError fields will also\n\
contain the returned usages and optionally the CertVerifyLog\n\
object. If no exception is raised these are returned as normal return\n\
values.\n\
");

static PyObject *
Certificate_verify(Certificate *self, PyObject *args)
{
    Py_ssize_t n_base_args = 4;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    CertDB *py_certdb = NULL;
    PyObject *py_check_sig = NULL;
    PRBool check_sig = 0;
    PRTime pr_time = 0;
    long required_usages = 0;
    SECCertificateUsage returned_usages = 0;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "O!O!lO&:verify",
                          &CertDBType, &py_certdb,
                          &PyBool_Type, &py_check_sig,
                          &required_usages,
                          PRTimeConvert, &pr_time)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    check_sig = PyBoolAsPRBool(py_check_sig);
    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if (CERT_VerifyCertificate(py_certdb->handle, self->cert, check_sig,
                               required_usages, pr_time, pin_args,
                               NULL, &returned_usages) != SECSuccess) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_cert_verify_error(returned_usages, NULL, NULL);
    }
    Py_END_ALLOW_THREADS
    Py_DECREF(pin_args);

    return PyInt_FromLong(returned_usages);
}

PyDoc_STRVAR(Certificate_verify_with_log_doc,
"verify_with_log(certdb, check_sig, required_usages, time, [user_data1, ...]) -> valid_usages, log\n\
\n\
:Parameters:\n\
    certdb : CertDB object\n\
        CertDB certificate database object\n\
    check_sig : bool\n\
        True if certificate signatures should be checked\n\
    required_usages : integer\n\
        A bitfield of all cert usages that are required for verification\n\
        to succeed. If zero return all possible valid usages.\n\
    time : number or None\n\
        an optional point in time as number of microseconds\n\
        since the NSPR epoch, midnight (00:00:00) 1 January\n\
        1970 UTC, either as an integer or a float. If time \n\
        is None the current time is used.\n\
    user_dataN : object\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Verify a certificate by checking if it's valid and that we\n\
trust the issuer.\n\
\n\
Possible usage bitfield values are:\n\
    - certificateUsageCheckAllUsages\n\
    - certificateUsageSSLClient\n\
    - certificateUsageSSLServer\n\
    - certificateUsageSSLServerWithStepUp\n\
    - certificateUsageSSLCA\n\
    - certificateUsageEmailSigner\n\
    - certificateUsageEmailRecipient\n\
    - certificateUsageObjectSigner\n\
    - certificateUsageUserCertImport\n\
    - certificateUsageVerifyCA\n\
    - certificateUsageProtectedObjectSigner\n\
    - certificateUsageStatusResponder\n\
    - certificateUsageAnyCA\n\
\n\
Returns valid_usages, a bitfield of certificate usages and a `nss.CertVerifyLog`\n\
object with diagnostic information detailing the reasons for a validation failure.\n\
\n\
If required_usages is non-zero, the returned bitmap is only for those\n\
required usages, otherwise it is for all possible usages.\n\
\n\
Hint: You can obtain a printable representation of the usage flags\n\
via `cert_usage_flags`.\n\
\n\
Note: See the `Certificate.verify` documentation for details on how\n\
the Certificate verification functions handle errors.\n\
");

static PyObject *
Certificate_verify_with_log(Certificate *self, PyObject *args)
{
    Py_ssize_t n_base_args = 4;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    CertDB *py_certdb = NULL;
    PyObject *py_check_sig = NULL;
    PRBool check_sig = 0;
    PRTime pr_time = 0;
    CertVerifyLog *py_log = NULL;
    long required_usages = 0;
    SECCertificateUsage returned_usages = 0;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "O!O!lO&:verify_with_log",
                          &CertDBType, &py_certdb,
                          &PyBool_Type, &py_check_sig,
                          &required_usages,
                          PRTimeConvert, &pr_time)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    check_sig = PyBoolAsPRBool(py_check_sig);
    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    if ((py_log = (CertVerifyLog *)CertVerifyLog_new(&CertVerifyLogType, NULL, NULL)) == NULL) {
        Py_DECREF(pin_args);
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if (CERT_VerifyCertificate(py_certdb->handle, self->cert, check_sig,
                               required_usages, pr_time, pin_args,
                               &py_log->log, &returned_usages) != SECSuccess) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_cert_verify_error(returned_usages, (PyObject *)py_log, NULL);
    }
    Py_END_ALLOW_THREADS
    Py_DECREF(pin_args);

    return Py_BuildValue("KN", returned_usages, py_log);
}

PyDoc_STRVAR(Certificate_check_ocsp_status_doc,
"check_ocsp_status(certdb, time, [user_data1, ...]) -> boolean\n\
\n\
:Parameters:\n\
    certdb : CertDB object\n\
        CertDB certificate database object.\n\
    time : number or None\n\
        Time for which status is to be determined.\n\
        Time as number of microseconds since the NSPR epoch, midnight\n\
        (00:00:00) 1 January 1970 UTC, either as an integer or a\n\
        float. If time is None the current time is used.\n\
    user_dataN : object\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Checks the status of a certificate via OCSP.  Will only check status for\n\
a certificate that has an AIA (Authority Information Access) extension\n\
for OCSP or when a \"default responder\" is specified and enabled.\n\
(If no AIA extension for OCSP and no default responder in place, the\n\
cert is considered to have a good status.\n\
\n\
Returns True if an approved OCSP responder knows the cert\n\
and returns a non-revoked status for it. Otherwise a `error.NSPRError`\n\
is raised and it's error_code property may be one of the following:\n\
\n\
    - SEC_ERROR_OCSP_BAD_HTTP_RESPONSE\n\
    - SEC_ERROR_OCSP_FUTURE_RESPONSE\n\
    - SEC_ERROR_OCSP_MALFORMED_REQUEST\n\
    - SEC_ERROR_OCSP_MALFORMED_RESPONSE\n\
    - SEC_ERROR_OCSP_OLD_RESPONSE\n\
    - SEC_ERROR_OCSP_REQUEST_NEEDS_SIG\n\
    - SEC_ERROR_OCSP_SERVER_ERROR\n\
    - SEC_ERROR_OCSP_TRY_SERVER_LATER\n\
    - SEC_ERROR_OCSP_UNAUTHORIZED_REQUEST\n\
    - SEC_ERROR_OCSP_UNAUTHORIZED_RESPONSE\n\
    - SEC_ERROR_OCSP_UNKNOWN_CERT\n\
    - SEC_ERROR_OCSP_UNKNOWN_RESPONSE_STATUS\n\
    - SEC_ERROR_OCSP_UNKNOWN_RESPONSE_TYPE\n\
\n\
    - SEC_ERROR_BAD_SIGNATURE\n\
    - SEC_ERROR_CERT_BAD_ACCESS_LOCATION\n\
    - SEC_ERROR_INVALID_TIME\n\
    - SEC_ERROR_REVOKED_CERTIFICATE\n\
    - SEC_ERROR_UNKNOWN_ISSUER\n\
    - SEC_ERROR_UNKNOWN_SIGNER\n\
\n\
Other errors are possible failures in cert verification\n\
(e.g. SEC_ERROR_REVOKED_CERTIFICATE, SEC_ERROR_UNTRUSTED_ISSUER) when\n\
verifying the signer's cert, or other low-level problems.\n\
");
static PyObject *
Certificate_check_ocsp_status(Certificate *self, PyObject *args)
{
    Py_ssize_t n_base_args = 2;
    CertDB *py_certdb = NULL;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;

    PRTime pr_time = 0;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(args, "O!O&:check_ocsp_status",
                          &CertDBType, &py_certdb,
                          PRTimeConvert, &pr_time)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if (CERT_CheckOCSPStatus(py_certdb->handle, self->cert,
                             pr_time, pin_args) != SECSuccess) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);
    Py_RETURN_TRUE;
}

PyDoc_STRVAR(Certificate_get_extension_doc,
"get_extension(oid) -> `CertificateExtension`\n\
\n\
Given an oid identifying the extension try to locate it in the\n\
certificate and return it as generic `CertificateExtension` object. If\n\
the extension is not present raise a KeyError.\n\
\n\
The generic `CertificateExtension` object is not terribly useful on\n\
it's own, howerver it's value property can be used to intialize\n\
instances of a class representing the extension.  Or it may be passed\n\
to functions that convert the value into some other usable format.\n\
Although one might believe this function should do these conversions\n\
for you automatically there are too many possible variations. Plus one\n\
might simple be interested to know if an extension is present or\n\
not. So why perform conversion work that might not be needed or might\n\
not be in the format needed? Therefore this function is just one\n\
simple element in a larger toolbox. Below are some suggestions on how\n\
to convert the generic `CertificateExtension` object (this list may\n\
not be complete).\n\
\n\
    SEC_OID_PKCS12_KEY_USAGE\n\
        `x509_key_usage()`\n\
    SEC_OID_X509_SUBJECT_KEY_ID\n\
        `SecItem.der_to_hex()`\n\
    SEC_OID_X509_CRL_DIST_POINTS\n\
        `CRLDistributionPts()`\n\
    case SEC_OID_X509_AUTH_KEY_ID\n\
        `AuthKeyID()`\n\
    SEC_OID_X509_EXT_KEY_USAGE\n\
        `x509_ext_key_usage()`\n\
    SEC_OID_X509_BASIC_CONSTRAINTS\n\
        `BasicConstraints()`\n\
    SEC_OID_X509_SUBJECT_ALT_NAME\n\
        `x509_alt_name()`\n\
    SEC_OID_X509_ISSUER_ALT_NAME\n\
        `x509_alt_name()`\n\
\n\
:Parameters:\n\
     oid : may be one of integer, string, SecItem\n\
         The OID of the certification extension to retreive\n\
         May be one of:\n\
\n\
         * integer: A SEC OID enumeration constant (i.e. SEC_OID\\_*)\n\
           for example SEC_OID_X509_BASIC_CONSTRAINTS.\n\
         * string: A string either the OID name, with or without the SEC_OID\\_\n\
           prefix (e.g. \"SEC_OID_X509_BASIC_CONSTRAINTS\" or \"X509_BASIC_CONSTRAINTS\")\n\
           or as the dotted decimal representation, for example\n\
           'OID.2 5 29 19'. Case is not significant for either form.\n\
         * SecItem: A SecItem object encapsulating the OID in \n\
           DER format.\n\
\n\
:returns:\n\
    generic `CertificateExtension` object\n\
\n\
");

static PyObject *
Certificate_get_extension(Certificate *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"oid", NULL};
    PyObject *py_oid;
    SECOidTag oid_tag = SEC_OID_UNKNOWN;
    SECOidTag cur_oid_tag = SEC_OID_UNKNOWN;
    CERTCertExtension **extensions = NULL;
    CERTCertExtension *cur_extension = NULL, *extension = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:get_extension", kwlist,
                                     &py_oid))
        return NULL;

    if ((oid_tag = get_oid_tag_from_object(py_oid)) == -1) {
        return NULL;
    }

    extension = NULL;
    for (extensions = self->cert->extensions; extensions && *extensions; extensions++) {
        cur_extension = *extensions;

        cur_oid_tag = SECOID_FindOIDTag(&cur_extension->id);

        if (cur_oid_tag == SEC_OID_UNKNOWN) {
            continue;
        }

        if (oid_tag == cur_oid_tag) {
            extension = cur_extension;
            break;
        }

    }

    if (extension == NULL) {
        PyObject *py_oid_name = NULL;

        if ((py_oid_name = oid_tag_name_from_tag(oid_tag)) == NULL) {
            py_oid_name = PyObject_Str(py_oid);
        }
        PyErr_Format(PyExc_KeyError, "no extension with OID %s found",
                     PyString_AsString(py_oid_name));
        Py_DECREF(py_oid_name);
        return NULL;
    }

    return CertificateExtension_new_from_CERTCertExtension(extension);

}

PyDoc_STRVAR(Certificate_get_cert_chain_doc,
"get_cert_chain(time=now, usages=certUsageAnyCA) -> (`Certificate`, ...)\n\
\n\
:Parameters:\n\
    time : number or None\n\
        an optional point in time as number of microseconds\n\
        since the NSPR epoch, midnight (00:00:00) 1 January\n\
        1970 UTC, either as an integer or a float. If time \n\
        is None the current time is used.\n\
    usages : integer\n\
        a certUsage* enumerated constant\n\
\n\
Returns a tuple of `Certificate` objects.\n\
");

static PyObject *
Certificate_get_cert_chain(Certificate *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"time", "usages", NULL};
    PRTime pr_time = 0;
    int usages = certUsageAnyCA;
    CERTCertList *cert_list = NULL;
    PyObject *tuple = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O&i:get_cert_chain", kwlist,
                                     PRTimeConvert, &pr_time, &usages))
        return NULL;

    if ((cert_list = CERT_GetCertChainFromCert(self->cert, pr_time, usages)) == NULL) {
        return set_nspr_error(NULL);
    }

    tuple = CERTCertList_to_tuple(cert_list, true);
    CERT_DestroyCertList(cert_list);
    return tuple;
}

static PyObject *
Certificate_summary_format_lines(Certificate *self, int level, PyObject *lines)
{
    PyObject *obj = NULL;
    PyObject *obj1 = NULL;
    PyObject *obj2 = NULL;

    if ((obj = Certificate_get_subject(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Subject"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = Certificate_get_issuer(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Issuer"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj1 = Certificate_get_valid_not_before_str(self, NULL)) == NULL) {
        goto fail;
    }
    if ((obj2 = Certificate_get_valid_not_after_str(self, NULL)) == NULL) {
        goto fail;
    }
    if ((obj = obj_sprintf("[%s] - [%s]", obj1, obj2)) == NULL) {
        goto fail;
    }
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);
    FMT_OBJ_AND_APPEND(lines, _("Validity"), obj, level, fail);
    Py_CLEAR(obj);

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(obj1);
    Py_XDECREF(obj2);
    return NULL;
}

static PyObject *
Certificate_format_lines(Certificate *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    Py_ssize_t len, i;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *obj1 = NULL;
    PyObject *obj2 = NULL;
    PyObject *obj3 = NULL;
    PyObject *obj_line_fmt_tuples = NULL;
    PyObject *obj_lines = NULL;
    PyObject *ssl_trust_lines = NULL, *email_trust_lines = NULL, *signing_trust_lines = NULL;
    PyObject *tmp_args = NULL;
    PyObject *extensions = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        goto fail;
    }

    FMT_LABEL_AND_APPEND(lines, _("Data"), level, fail);

    if ((obj = Certificate_get_version(self, NULL)) == NULL) {
        goto fail;
    }
    if ((obj1 = PyInt_FromLong(1)) == NULL) {
        goto fail;
    }
    if ((obj2 = PyNumber_Add(obj, obj1)) == NULL) {
        goto fail;
    }
    if ((obj3 = obj_sprintf("%d (%#x)", obj2, obj)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Version"), obj3, level+2, fail);
    Py_CLEAR(obj);
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);
    Py_CLEAR(obj3);

    if ((obj = Certificate_get_serial_number(self, NULL)) == NULL) {
        goto fail;
    }
    if ((obj1 = obj_sprintf("%d (%#x)", obj, obj)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Serial Number"), obj1, level+2, fail);
    Py_CLEAR(obj);
    Py_CLEAR(obj1);

    if ((obj = Certificate_get_signature_algorithm(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_LABEL_AND_APPEND(lines, _("Signature Algorithm"), level+2, fail);
    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+3, fail);
    Py_CLEAR(obj);

    if ((obj = Certificate_get_issuer(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Issuer"), obj, level+2, fail);
    Py_CLEAR(obj);

    FMT_LABEL_AND_APPEND(lines, _("Validity"), level+2, fail);

    if ((obj = Certificate_get_valid_not_before_str(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Not Before"), obj, level+3, fail);
    Py_CLEAR(obj);

    if ((obj = Certificate_get_valid_not_after_str(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Not After"), obj, level+3, fail);
    Py_CLEAR(obj);

    if ((obj = Certificate_get_subject(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Subject"), obj, level+2, fail);
    Py_CLEAR(obj);

    FMT_LABEL_AND_APPEND(lines, _("Subject Public Key Info"), level+2, fail);

    if ((obj = Certificate_get_subject_public_key_info(self, NULL)) == NULL) {
        goto fail;
    }

    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+3, fail);
    Py_CLEAR(obj);

    if ((extensions = Certificate_get_extensions(self, NULL)) == NULL) {
        goto fail;
    }

    len = PyTuple_Size(extensions);
    if ((obj = PyString_FromFormat("Signed Extensions: (%zd total)", len)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, NULL, obj, level+1, fail);
    Py_CLEAR(obj);

    for (i = 0; i < len; i++) {
        obj = PyTuple_GetItem(extensions, i);
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+2, fail);
        FMT_LABEL_AND_APPEND(lines, NULL, 0, fail);
    }
    Py_CLEAR(extensions);

    if ((ssl_trust_lines = Certificate_get_ssl_trust_str(self, NULL)) == NULL) {
        goto fail;
    }
    if ((email_trust_lines = Certificate_get_email_trust_str(self, NULL)) == NULL) {
        goto fail;
    }
    if ((signing_trust_lines = Certificate_get_signing_trust_str(self, NULL)) == NULL) {
        goto fail;
    }

    if ((ssl_trust_lines != Py_None) || (email_trust_lines != Py_None) || (signing_trust_lines != Py_None)) {
        FMT_LABEL_AND_APPEND(lines, _("Certificate Trust Flags"), level+2, fail);

        if (PyList_Check(ssl_trust_lines)) {
            FMT_LABEL_AND_APPEND(lines, _("SSL Flags"), level+3, fail);
            APPEND_LINES_AND_CLEAR(lines, ssl_trust_lines, level+4, fail);
        }

        if (PyList_Check(email_trust_lines)) {
            FMT_LABEL_AND_APPEND(lines, _("Email Flags"), level+3, fail);
            APPEND_LINES_AND_CLEAR(lines, email_trust_lines, level+4, fail);
        }

        if (PyList_Check(signing_trust_lines)) {
            FMT_LABEL_AND_APPEND(lines, _("Object Signing Flags"), level+3, fail);
            APPEND_LINES_AND_CLEAR(lines, signing_trust_lines, level+4, fail);
        }

    }
    Py_CLEAR(ssl_trust_lines);
    Py_CLEAR(email_trust_lines);
    Py_CLEAR(signing_trust_lines);

    FMT_LABEL_AND_APPEND(lines, _("Signature"), level+1, fail);

    if ((obj = Certificate_get_signed_data(self, NULL)) == NULL) {
        goto fail;
    }

    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+2, fail);
    Py_CLEAR(obj);

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(obj1);
    Py_XDECREF(obj2);
    Py_XDECREF(obj3);
    Py_XDECREF(lines);
    Py_XDECREF(obj_line_fmt_tuples);
    Py_XDECREF(obj_lines);
    Py_XDECREF(tmp_args);
    Py_XDECREF(ssl_trust_lines);
    Py_XDECREF(email_trust_lines);
    Py_XDECREF(signing_trust_lines);
    Py_XDECREF(extensions);
    return NULL;
}

static PyObject *
Certificate_format(Certificate *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)Certificate_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
Certificate_str(Certificate *self)
{
    PyObject *py_formatted_result = NULL;

    py_formatted_result = Certificate_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef Certificate_methods[] = {
    {"trust_flags",            (PyCFunction)Certificate_trust_flags,            METH_VARARGS | METH_CLASS,  Certificate_trust_flags_doc},
    {"set_trust_attributes",   (PyCFunction)Certificate_set_trust_attributes,   METH_VARARGS,               Certificate_set_trust_attributes_doc},
    {"find_kea_type",          (PyCFunction)Certificate_find_kea_type,          METH_NOARGS,                Certificate_find_kea_type_doc},
    {"make_ca_nickname",       (PyCFunction)Certificate_make_ca_nickname,       METH_NOARGS,                Certificate_make_ca_nickname_doc},
    {"has_signer_in_ca_names", (PyCFunction)Certificate_has_signer_in_ca_names, METH_VARARGS,               Certificate_has_signer_in_ca_names_doc},
    {"verify_hostname",        (PyCFunction)Certificate_verify_hostname,        METH_VARARGS,               Certificate_verify_hostname_doc},
    {"check_valid_times",      (PyCFunction)Certificate_check_valid_times,      METH_VARARGS|METH_KEYWORDS, Certificate_check_valid_times_doc},
    {"is_ca_cert",             (PyCFunction)Certificate_is_ca_cert,             METH_VARARGS|METH_KEYWORDS, Certificate_is_ca_cert_doc},
    {"verify_now",             (PyCFunction)Certificate_verify_now,             METH_VARARGS,               Certificate_verify_now_doc},
    {"verify",                 (PyCFunction)Certificate_verify,                 METH_VARARGS,               Certificate_verify_doc},
    {"verify_with_log",        (PyCFunction)Certificate_verify_with_log,        METH_VARARGS,               Certificate_verify_with_log_doc},
    {"check_ocsp_status",      (PyCFunction)Certificate_check_ocsp_status,      METH_VARARGS,               Certificate_check_ocsp_status_doc},
    {"get_cert_chain",         (PyCFunction)Certificate_get_cert_chain,         METH_VARARGS|METH_KEYWORDS, Certificate_get_cert_chain_doc},
    {"get_extension",          (PyCFunction)Certificate_get_extension,          METH_VARARGS|METH_KEYWORDS, Certificate_get_extension_doc},
    {"format_lines",           (PyCFunction)Certificate_format_lines,           METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",                 (PyCFunction)Certificate_format,                 METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
Certificate_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Certificate *self;

    TraceObjNewEnter(type);

    if ((self = (Certificate *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }
    self->cert = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
Certificate_dealloc(Certificate* self)
{
    TraceMethodEnter(self);

#ifdef DEBUG
    print_cert(self->cert, "%s before CERT_DestroyCertificate" ,__FUNCTION__);
#endif

    if (self->cert) {
        CERT_DestroyCertificate(self->cert);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(Certificate_doc,
"Certificate(data, certdb=get_default_certdb(), perm=False, nickname=None)\n\
\n\
:Parameters:\n\
    data : SecItem or str or any buffer compatible object\n\
        Data to initialize the certificate from, must be in DER format\n\
    certdb : CertDB object or None\n\
        CertDB certificate database object, if None then the default\n\
        certdb will be supplied by calling `nss.get_default_certdb()`.\n\
    perm : bool\n\
        True if certificate should be permantely stored in the certdb.\n\
    nickname : string\n\
        certificate nickname.\n\
\n\
An X509 Certificate object.\n\
\n\
The Certificate is initialized from the supplied DER data. The\n\
Certificate is added to the NSS temporary database. If perm is True\n\
then the Certificate is also permanently written into certdb.\n\
");

static int
Certificate_init(Certificate *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"data", "certdb", "perm", "nickname", NULL};
    PyObject *py_data = NULL;
    CertDB *py_certdb = NULL;
    PyObject *py_perm = NULL;
    PyObject *py_nickname = NULL;

    SECItem der_tmp_item;
    SECItem *der_item = NULL;
    CERTCertDBHandle *certdb_handle = NULL;
    SECItem *der_certs = NULL;
    CERTCertificate **certs = NULL;
    PRBool perm = PR_FALSE;
    unsigned int n_certs = 1;
    int result = 0;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O!O!O&:Certificate", kwlist,
                                     &py_data,
                                     &CertDBType, &py_certdb,
                                     &PyBool_Type, &py_perm,
                                     UTF8OrNoneConvert, &py_nickname))
        return -1;

    SECITEM_PARAM(py_data, der_item, der_tmp_item, false, "data");

    if (py_certdb) {
        certdb_handle = py_certdb->handle;
    } else {
        certdb_handle = CERT_GetDefaultCertDB();
    }

    if (py_perm) {
        perm = PyBoolAsPRBool(py_perm);
    }

    der_certs = der_item;

    Py_BEGIN_ALLOW_THREADS
    if (CERT_ImportCerts(certdb_handle, certUsageUserCertImport,
                         n_certs, &der_certs, &certs,
                         perm, PR_FALSE,
                         py_nickname ? PyString_AsString(py_nickname) : NULL) != SECSuccess) {
        Py_BLOCK_THREADS
        set_nspr_error(NULL);
        result = -1;
        goto exit;
    }
    Py_END_ALLOW_THREADS

#ifdef DEBUG
    print_cert(certs[0], "%s after CERT_ImportCerts certificate perm=%s" ,__FUNCTION__, perm ? "True":"False");
#endif

    if ((self->cert = CERT_DupCertificate(certs[0])) == NULL) {
        set_nspr_error(NULL);
        result = -1;
        goto exit;
    }

 exit:
    Py_XDECREF(py_nickname);
    if (certs != NULL) {
	CERT_DestroyCertArray(certs, n_certs);
    }

    return result;
}


static PyObject *
Certificate_repr(Certificate *self)
{
    return PyString_FromFormat("<%s object at %p Certificate %p>",
                               Py_TYPE(self)->tp_name, self, self->cert);
}

static PyTypeObject CertificateType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.Certificate",			/* tp_name */
    sizeof(Certificate),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)Certificate_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)Certificate_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)Certificate_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    Certificate_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    Certificate_methods,			/* tp_methods */
    Certificate_members,			/* tp_members */
    Certificate_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)Certificate_init,			/* tp_init */
    0,						/* tp_alloc */
    Certificate_new,				/* tp_new */
};

static PyObject *
Certificate_new_from_CERTCertificate(CERTCertificate *cert, bool add_reference)
{
    Certificate *self = NULL;

    TraceObjNewEnter(NULL);

#ifdef DEBUG
    print_cert(cert, "%s certificate" ,__FUNCTION__);
#endif

    if ((self = (Certificate *) CertificateType.tp_new(&CertificateType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (add_reference) {
        if ((self->cert = CERT_DupCertificate(cert)) == NULL) {
            return set_nspr_error(NULL);
        }
    } else {
        self->cert = cert;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

static PyObject *
Certificate_new_from_signed_der_secitem(SECItem *der)
{
#if 0
    PyObject *py_der = NULL;
    PyObject *py_cert = NULL;
    PRArenaPool *arena = NULL;
    CERTSignedData *sd = NULL;

    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        set_nspr_error(NULL);
        goto exit;
    }

    if ((sd = PORT_ArenaZNew(arena, CERTSignedData)) == NULL) {
        set_nspr_error(NULL);
        goto exit;
    }

    if (SEC_ASN1DecodeItem(arena, sd, SEC_ASN1_GET(CERT_SignedDataTemplate), der) != SECSuccess) {
        set_nspr_error("bad signed certificate DER data");
        goto exit;
    }

    if ((py_der = SecItem_new_from_SECItem(&sd->data, SECITEM_certificate)) == NULL) {
        goto exit;
    }

    if ((py_cert = PyObject_CallFunction((PyObject *)&CertificateType, "O", py_der)) == NULL) {
        goto exit;
    }

 exit:
    Py_XDECREF(py_der);
    PORT_FreeArena(arena, PR_FALSE);
    return py_cert;
#else
    PyObject *py_der = NULL;
    PyObject *py_cert = NULL;

    if ((py_der = SecItem_new_from_SECItem(der, SECITEM_certificate)) == NULL) {
        goto exit;
    }

    if ((py_cert = PyObject_CallFunction((PyObject *)&CertificateType, "O", py_der)) == NULL) {
        goto exit;
    }

 exit:
    Py_XDECREF(py_der);
    return py_cert;
#endif
}

/* ========================================================================== */
/* ============================= PrivateKey Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static
PyGetSetDef PrivateKey_getseters[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef PrivateKey_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */


static PyMethodDef PrivateKey_methods[] = {
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
PrivateKey_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PrivateKey *self;

    TraceObjNewEnter(type);

    if ((self = (PrivateKey *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }
    self->private_key = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
PrivateKey_dealloc(PrivateKey* self)
{
    TraceMethodEnter(self);

    if (self->private_key)
        SECKEY_DestroyPrivateKey(self->private_key);

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(PrivateKey_doc,
"An object representing a Private Key");

static int
PrivateKey_init(PrivateKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);
    return 0;
}

static PyTypeObject PrivateKeyType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.PrivateKey",			/* tp_name */
    sizeof(PrivateKey),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)PrivateKey_dealloc,		/* tp_dealloc */
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
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    PrivateKey_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    PrivateKey_methods,				/* tp_methods */
    PrivateKey_members,				/* tp_members */
    PrivateKey_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)PrivateKey_init,			/* tp_init */
    0,						/* tp_alloc */
    PrivateKey_new,				/* tp_new */
};

static PyObject *
PrivateKey_new_from_SECKEYPrivateKey(SECKEYPrivateKey *private_key)
{
    PrivateKey *self = NULL;

    TraceObjNewEnter(NULL);
    if ((self = (PrivateKey *) PrivateKeyType.tp_new(&PrivateKeyType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->private_key = private_key;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}


/* ========================================================================== */
/* ============================== SignedCRL Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static
PyGetSetDef SignedCRL_getseters[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef SignedCRL_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(SignedCRL_delete_permanently_doc,
"delete_permanently()\n\
\n\
Permanently remove the CRL from the database.\n\
");

static PyObject *
SignedCRL_delete_permanently(SignedCRL *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (SEC_DeletePermCRL(self->signed_crl) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

static PyMethodDef SignedCRL_methods[] = {
    {"delete_permanently", (PyCFunction)SignedCRL_delete_permanently, METH_NOARGS,  SignedCRL_delete_permanently_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
SignedCRL_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    SignedCRL *self;

    TraceObjNewEnter(type);

    if ((self = (SignedCRL *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }
    self->signed_crl = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
SignedCRL_dealloc(SignedCRL* self)
{
    TraceMethodEnter(self);

    if (self->signed_crl)
        SEC_DestroyCrl(self->signed_crl);

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(SignedCRL_doc,
"An object representing a signed certificate revocation list");

static int
SignedCRL_init(SignedCRL *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);
    return 0;
}

static PyTypeObject SignedCRLType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.SignedCRL",			/* tp_name */
    sizeof(SignedCRL),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)SignedCRL_dealloc,		/* tp_dealloc */
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
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    SignedCRL_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    SignedCRL_methods,				/* tp_methods */
    SignedCRL_members,				/* tp_members */
    SignedCRL_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)SignedCRL_init,			/* tp_init */
    0,						/* tp_alloc */
    SignedCRL_new,				/* tp_new */
};

static PyObject *
SignedCRL_new_from_CERTSignedCRL(CERTSignedCrl *signed_crl)
{
    SignedCRL *self = NULL;

    TraceObjNewEnter(NULL);
    if ((self = (SignedCRL *) SignedCRLType.tp_new(&SignedCRLType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->signed_crl = signed_crl;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* =============================== AVA Class ================================ */
/* ========================================================================== */

/*
 * Note: CERT_CopyAVA, CERT_GetAVATag, CERT_CompareAVA, CERT_CreateAVA,
 * and CERT_DecodeAVAValue are defined in cert.h
 *
 * But only CERT_GetAVATag, CERT_CreateAVA, CERT_DecodeAVAValue are exported
 * by nss.def
 *
 * That means CERT_CopyAVA and CERT_CompareAVA are defined as public but aren't.
 */

/* ============================ Attribute Access ============================ */

static PyObject *
AVA_get_oid(AVA *self, void *closure)
{
    TraceMethodEnter(self);

    return SecItem_new_from_SECItem(&self->ava->type, SECITEM_oid);
}

static PyObject *
AVA_get_oid_tag(AVA *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(CERT_GetAVATag(self->ava));
}

static PyObject *
AVA_get_value(AVA *self, void *closure)
{
    TraceMethodEnter(self);

    return SecItem_new_from_SECItem(&self->ava->value, SECITEM_utf8_string);
}

static PyObject *
AVA_get_value_str(AVA *self, void *closure)
{
    TraceMethodEnter(self);

    return AVA_repr(self);
}

static
PyGetSetDef AVA_getseters[] = {
    {"oid",       (getter)AVA_get_oid, (setter)NULL,
     "The OID (e.g. type) of the AVA as a SecItem", NULL},
    {"oid_tag",   (getter)AVA_get_oid_tag, (setter)NULL,
     "The OID tag enumerated constant (i.e. SEC_OID_AVA_*) of the AVA's type", NULL},
    {"value",     (getter)AVA_get_value, (setter)NULL,
     "The value of the AVA as a SecItem", NULL},
    {"value_str", (getter)AVA_get_value_str, (setter)NULL,
     "The value of the AVA as a UTF-8 encoded string", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef AVA_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */


/*
 * Compares two CERTAVA's, returns -1 if a < b, 0 if a == b, 1 if a > b
 * If error, returns -2
 */
static int
CERTAVA_compare(CERTAVA *a, CERTAVA *b)
{
    SECComparison sec_cmp_result;
    int int_cmp_result;
    PyObject *a_val_str, *b_val_str;

    if (a == NULL && b == NULL) return 0;
    if (a == NULL && b != NULL) return -1;
    if (a != NULL && b == NULL) return 1;

    if ((sec_cmp_result = SECITEM_CompareItem(&a->type, &b->type)) != SECEqual) {
#if 0 /* FIXME when https://bugzilla.redhat.com/show_bug.cgi?id=804802 is fixed */
        return sec_cmp_result == SECLessThan ? -1 : 1;
#else
        return sec_cmp_result < 0 ? SECLessThan : SECGreaterThan;
#endif
    }

    /* Attribute types matched, are values equal? */
    if ((sec_cmp_result = SECITEM_CompareItem(&a->value,
                                              &b->value)) == SECEqual) {
        return 0;
    }

    /* No values not equal, compare as case insenstive strings */
    a_val_str = CERTAVA_value_to_pystr(a);
    b_val_str = CERTAVA_value_to_pystr(b);
    if (a_val_str == NULL || b_val_str == NULL) {
        Py_XDECREF(a_val_str);
        Py_XDECREF(b_val_str);
        PyErr_SetString(PyExc_ValueError, "Failed to convert AVA value to string");
        return -2;
    }

    int_cmp_result = strcasecmp(PyString_AS_STRING(a_val_str),
                                PyString_AS_STRING(b_val_str));
    Py_DECREF(a_val_str);
    Py_DECREF(b_val_str);
    return (int_cmp_result == 0) ? 0 : ((int_cmp_result < 0) ? -1 : 1);
}

static int
AVA_compare(AVA *self, AVA *other)
{
    int cmp_result;

    if (!PyAVA_Check(other)) {
        PyErr_SetString(PyExc_TypeError, "Bad type, must be AVA");
        return -1;
    }

    cmp_result = CERTAVA_compare(self->ava, other->ava);
    if (cmp_result == -2) {
        return -1;
    }
    return cmp_result;
}

static PyMethodDef AVA_methods[] = {
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
AVA_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    AVA *self;

    TraceObjNewEnter(type);

    if ((self = (AVA *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    self->ava = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
AVA_dealloc(AVA* self)
{
    TraceMethodEnter(self);

    if (self->arena) {
        PORT_FreeArena(self->arena, PR_FALSE);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(AVA_doc,
"An object representing an AVA (attribute value assertion).\n\
\n\
AVA(type, value)\n\
\n\
:Parameters:\n\
     type : may be one of integer, string, SecItem\n\
         What kind of attribute is being created. May be\n\
         one of:\n\
\n\
         * integer: A SEC OID enumeration constant (i.e. SEC_OID_*)\n\
           for example SEC_OID_AVA_COMMON_NAME.\n\
         * string: A string either as the ava name, for example 'cn'\n\
           or as the dotted decimal representation, for example\n\
           'OID.2.5.4.3'. Case is not significant for either form.\n\
         * SecItem: A SecItem object encapsulating the OID in \n\
           DER format.\n\
     value : string\n\
         The value of the AVA, must be a string.\n\
\n\
RDN's (Relative Distinguished Name) are composed from AVA's.\n\
An `RDN` is a sequence of AVA's.\n\
\n\
An example of an AVA is \"CN=www.redhat.com\" where CN is the X500\n\
directory abbrevation for \"Common Name\".\n\
\n\
An AVA is composed of two items:\n\
\n\
type\n\
    Specifies the attribute (e.g. CN). AVA types are specified by\n\
    predefined OID's (Object Identifiers). For example the OID of CN\n\
    is 2.5.4.3 ({joint-iso-itu-t(2) ds(5) attributeType(4) commonName(3)})\n\
    OID's in NSS are encapsulated in a SecItem as a DER encoded OID.\n\
    Because DER encoded OID's are less than ideal mechanisms by which\n\
    to specify an item NSS has mapped each OID to a integral enumerated\n\
    constant called an OID tag (i.e. SEC_OID_*). Many of the NSS API's\n\
    will accept an OID tag number instead of DER encoded OID in a SecItem.\n\
    One can easily convert between DER encoded OID's, tags, and their\n\
    string representation in dotted-decimal format. The enumerated OID\n\
    constants are the most efficient in most cases.\n\
value\n\
    The value of the attribute (e.g. 'www.redhat.com').\n\
\n\
Examples::\n\
\n\
    The AVA cn=www.redhat.com can be created in any of the follow ways:\n\
\n\
    ava = nss.AVA('cn', 'www.redhat.com')\n\
    ava = nss.AVA(nss.SEC_OID_AVA_COMMON_NAME, 'www.redhat.com')\n\
    ava = nss.AVA('2.5.4.3', 'www.redhat.com')\n\
    ava = nss.AVA('OID.2.5.4.3', 'www.redhat.com')\n\
");

static int
AVA_init(AVA *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"type", "value", NULL};
    PyObject *py_type = NULL;
    PyObject *py_value = NULL;
    PyObject *py_value_utf8 = NULL;
    int oid_tag = SEC_OID_UNKNOWN;
    int value_type;
    char *value_string;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO:AVA", kwlist,
                                     &py_type, &py_value))
        return -1;

    if ((oid_tag = get_oid_tag_from_object(py_type)) == -1) {
        return -1;
    }

    if (oid_tag == SEC_OID_UNKNOWN) {
        PyObject *type_str = PyObject_Str(py_type);
        PyErr_Format(PyExc_ValueError, "unable to convert \"%s\" to known OID",
                     PyString_AsString(type_str));
        Py_DECREF(type_str);
        return -1;
    }

    if (PyString_Check(py_value) || PyUnicode_Check(py_value)) {
        if (PyString_Check(py_value)) {
            py_value_utf8 = py_value;
            Py_INCREF(py_value_utf8);
        } else {
            py_value_utf8 =  PyUnicode_AsUTF8String(py_value);
        }

        if ((value_string = PyString_AsString(py_value_utf8)) == NULL) {
            Py_DECREF(py_value_utf8);
            return -1;
        }
    } else {
        PyErr_Format(PyExc_TypeError, "AVA value must be a string, not %.200s",
                     Py_TYPE(py_type)->tp_name);
        return -1;
    }

    value_type = ava_oid_tag_to_value_type(oid_tag);
    if ((self->ava = CERT_CreateAVA(self->arena, oid_tag, value_type, value_string)) == NULL) {
        set_nspr_error("could not create AVA, oid tag = %d, value = \"%s\"",
                       oid_tag, value_string);
	Py_XDECREF(py_value_utf8);
        return -1;
    }

    Py_XDECREF(py_value_utf8);
    return 0;
}

static PyObject *
AVA_repr(AVA *self)
{
    PyObject *py_value_str;

    if ((py_value_str = CERTAVA_value_to_pystr(self->ava)) == NULL) {
        return PyString_FromFormat("<%s object at %p>",
                                   Py_TYPE(self)->tp_name, self);
    }
    return py_value_str;
}

static PyTypeObject AVAType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.AVA",				/* tp_name */
    sizeof(AVA),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)AVA_dealloc,			/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    (cmpfunc)AVA_compare,			/* tp_compare */
    (reprfunc)AVA_repr,				/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    0,						/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    AVA_doc,					/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    AVA_methods,				/* tp_methods */
    AVA_members,				/* tp_members */
    AVA_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)AVA_init,				/* tp_init */
    0,						/* tp_alloc */
    AVA_new,					/* tp_new */
};

PyObject *
AVA_new_from_CERTAVA(CERTAVA *ava)
{
    AVA *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (AVA *) AVAType.tp_new(&AVAType, NULL, NULL)) == NULL)
        return NULL;

    if ((self->ava = (CERTAVA*) PORT_ArenaZNew(self->arena, CERTAVA)) == NULL) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    if (SECITEM_CopyItem(NULL, &self->ava->type, &ava->type) != SECSuccess) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }
    self->ava->type.type = siDEROID; /* NSS often fails to set this so force it */

    if (SECITEM_CopyItem(NULL, &self->ava->value, &ava->value) != SECSuccess) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* =============================== RDN Class ================================ */
/* ========================================================================== */

/*
 * Note: CERT_AddAVA, CERT_AddRDN, CERT_CompareRDN, CERT_CopyRDN, CERT_CreateName
 * CERT_CreateRDN, CERT_DestroyRDN are defined in cert.h
 *
 * But only CERT_AddRDN, CERT_CopyRDN, CERT_CreateName, CERT_CreateRDN
 * are exported by nss.def
 *
 * That means CERT_AddAVA, CERT_CompareRDN, CERT_DestroyRDN
 * are defined as public but aren't. Note CERT_DestroyRDN has no implementation.
 */

/* ============================ Attribute Access ============================ */

static
PyGetSetDef RDN_getseters[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef RDN_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

/*
 * Compares two CERTRDN's, returns -1 if a < b, 0 if a == b, 1 if a > b
 * If error, returns -2
 */
static int
CERTRDN_compare(CERTRDN *a, CERTRDN *b)
{
    SECComparison cmp_result;
    int a_len, b_len;
    CERTAVA **a_avas, *a_ava;
    CERTAVA **b_avas, *b_ava;

    if (a == NULL && b == NULL) return 0;
    if (a == NULL && b != NULL) return -1;
    if (a != NULL && b == NULL) return 1;

    a_len = CERTRDN_ava_count(a);
    b_len = CERTRDN_ava_count(b);

    if (a_len < b_len) return -1;
    if (a_len > b_len) return  1;

    for (a_avas = a->avas, b_avas = b->avas;
         a_avas && (a_ava = *a_avas) && b_avas && (b_ava = *b_avas);
         a_avas++, b_avas++) {
        if ((cmp_result = CERTAVA_compare(a_ava, b_ava)) != 0) {
            return cmp_result;
        }
    }
    return 0;
}

static int
RDN_compare(RDN *self, RDN *other)
{
    int cmp_result;

    if (!PyRDN_Check(other)) {
        PyErr_SetString(PyExc_TypeError, "Bad type, must be RDN");
        return -1;
    }

    cmp_result = CERTRDN_compare(self->rdn, other->rdn);
    if (cmp_result == -2) {
        return -1;
    }
    return cmp_result;
}

PyDoc_STRVAR(RDN_has_key_doc,
"has_key(arg) -> bool\n\
\n\
:Parameters:\n\
    arg : string or integer\n\
        canonical name (e.g. 'cn') or oid dotted-decimal or\n\
        SEC_OID_* enumeration constant\n\
\n\
return True if RDN has an AVA whose oid can be identified by arg.\n\
");

static PyObject *
RDN_has_key(RDN *self, PyObject *args)
{
    PyObject *arg;
    int oid_tag;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:has_key",
                          &arg))
        return NULL;

    oid_tag = get_oid_tag_from_object(arg);
    if (oid_tag == SEC_OID_UNKNOWN || oid_tag == -1) {
        Py_RETURN_FALSE;
    }

    if (CERTRDN_has_tag(self->rdn, oid_tag)) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

/* =========================== Sequence Protocol ============================ */

static Py_ssize_t
CERTRDN_ava_count(CERTRDN *rdn)
{
    Py_ssize_t count;
    CERTAVA **avas;

    if (!rdn) return 0;
    for (avas = rdn->avas, count = 0; *avas; avas++, count++);

    return count;
}

static Py_ssize_t
RDN_length(RDN *self)
{
    return CERTRDN_ava_count(self->rdn);
}

static PyObject *
RDN_item(RDN *self, register Py_ssize_t i)
{
    Py_ssize_t count = 0;
    CERTAVA **avas;

    if (i < 0 || !self->rdn || self->rdn->avas == NULL) {
        PyErr_SetString(PyExc_IndexError, "RDN index out of range");
        return NULL;
    }

    for (avas = self->rdn->avas, count = 0; *avas && count < i; avas++, count++);

    if (!*avas) {
        PyErr_SetString(PyExc_IndexError, "RDN index out of range");
        return NULL;
    }

    return AVA_new_from_CERTAVA(*avas);
}


static bool
CERTRDN_has_tag(CERTRDN *rdn, int tag)
{
    CERTAVA **avas;
    CERTAVA *ava = NULL;

    if (!rdn) return false;
    for (avas = rdn->avas; avas && (ava = *avas); avas++) {
        int ava_tag = CERT_GetAVATag(ava);
        if (tag == ava_tag) {
            return true;
        }
    }
    return false;
}

static PyObject *
CERTRDN_get_matching_tag_list(CERTRDN *rdn, int tag)
{
    PyObject *list = NULL;
    PyObject *py_ava = NULL;
    CERTAVA **avas, *ava;

    if ((list = PyList_New(0)) == NULL) {
        return NULL;
    }

    if (!rdn) {
        return list;
    }

    for (avas = rdn->avas; avas && (ava = *avas); avas++) {
        int ava_tag = CERT_GetAVATag(ava);
        if (tag == ava_tag) {
            if ((py_ava = AVA_new_from_CERTAVA(ava)) == NULL) {
                Py_DECREF(list);
                return NULL;
            }
            PyList_Append(list, py_ava);
        }
    }

    return list;
}
static PyObject*
RDN_subscript(RDN *self, PyObject* item)
{
    PyObject* result;

    if (PyIndex_Check(item)) {
        Py_ssize_t i = PyNumber_AsSsize_t(item, PyExc_IndexError);

        if (i == -1 && PyErr_Occurred())
            return NULL;
        if (i < 0)
            i += RDN_length(self);
        return RDN_item(self, i);
    } else if (PySlice_Check(item)) {
        Py_ssize_t start, stop, step, slicelength, cur, i;
        PyObject* py_ava;

        if (PySlice_GetIndicesEx((PySliceObject*)item, RDN_length(self),
				 &start, &stop, &step, &slicelength) < 0) {
            return NULL;
        }

        if (slicelength <= 0) {
            return PyList_New(0);
        } else {
            result = PyList_New(slicelength);
            if (!result) return NULL;

            for (cur = start, i = 0; i < slicelength; cur += step, i++) {
                /* We don't need to bump the ref count because RDN_item
                 * returns a new object */
                py_ava = RDN_item(self, cur);
                if (PyList_SetItem(result, i, py_ava) == -1) {
                    Py_DECREF(result);
                    return NULL;
                }
            }
            return result;
	}
    } else if (PyString_Check(item) || PyUnicode_Check(item) || PySecItem_Check(item)) {
        int oid_tag;

        if ((oid_tag = get_oid_tag_from_object(item)) == -1) {
            return NULL;
        }

        if (oid_tag == SEC_OID_UNKNOWN) {
            if (PyString_Check(item) || PyUnicode_Check(item)) {
                char *name = PyString_AsString(item);
                PyErr_Format(PyExc_KeyError, "oid name unknown: \"%s\"", name);
                return NULL;
            } else {
                PyErr_SetString(PyExc_KeyError, "oid unknown");
                return NULL;
            }
        }

        if ((result = CERTRDN_get_matching_tag_list(self->rdn, oid_tag)) == NULL) {
            return NULL;
        }

        if (PyList_Size(result) == 0) {
            Py_DECREF(result);
            if (PyString_Check(item) || PyUnicode_Check(item)) {
                char *name = PyString_AsString(item);
                PyErr_Format(PyExc_KeyError, "oid name not found: \"%s\"", name);
                return NULL;
            } else {
                PyErr_SetString(PyExc_KeyError, "oid not found");
                return NULL;
            }
        } else {
            return result;
        }
    } else {
        PyErr_Format(PyExc_TypeError,
                     "indices must be integers or strings, not %.200s",
                     item->ob_type->tp_name);
        return NULL;
    }
    return NULL;
}

static PyObject *
RDN_repr(RDN *self)
{
    return CERTRDN_to_pystr(self->rdn);
}

static PyMethodDef RDN_methods[] = {
    {"has_key", (PyCFunction)RDN_has_key, METH_VARARGS, RDN_has_key_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
RDN_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    RDN *self;

    TraceObjNewEnter(type);

    if ((self = (RDN *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    self->rdn = NULL;

    TraceObjNewLeave(self);

    return (PyObject *)self;
}

static void
RDN_dealloc(RDN* self)
{
    TraceMethodEnter(self);

    if (self->arena) {
        PORT_FreeArena(self->arena, PR_FALSE);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(RDN_doc,
"An object representing an X501 Relative Distinguished Name (e.g. RDN).\n\
\n\
RDN objects contain an ordered list of `AVA` objects. \n\
\n\
Examples::\n\
\n\
    RDN()\n\
    RDN(nss.AVA('cn', 'www.redhat.com'))\n\
    RDN([ava0, ava1])\n\
\n\
The RDN object constructor may be invoked with zero or more\n\
`AVA` objects, or you may optionally pass a list or tuple of `AVA`\n\
objects.\n\
\n\
RDN objects contain an ordered list of `AVA` objects. The\n\
RDN object has both sequence and mapping behaviors with respect to\n\
the AVA's they contain. Thus you can index an AVA by position, by\n\
name, or by SecItem (if it's an OID). You can iterate over the list,\n\
get it's length or take a slice.\n\
\n\
If you index by string the string may be either a canonical name for\n\
the AVA type (e.g. 'cn') or the dotted-decimal notation for the OID\n\
(e.g. 2.5.4.3). There may be multiple AVA's in a RDN whose type matches\n\
(e.g. OU=engineering+OU=boston). It is not common to have more than\n\
one AVA in a RDN with the same type. However because of the possiblity\n\
of being multi-valued when indexing by type a list is always returned\n\
containing the matching AVA's. Thus::\n\
\n\
    rdn = nss.RDN(nss.AVA('OU', 'engineering'))\n\
    rdn['ou']\n\
        returns [AVA('OU=engineering')\n\
\n\
    rdn = nss.RDN(nss.AVA('OU', 'engineering'), nss.AVA('OU', 'boston'))\n\
    rdn['ou']\n\
        returns [AVA('OU=boston'), AVA('OU=engineering')]\n\
\n\
Examples::\n\
\n\
    rdn = nss.RDN(nss.AVA('cn', 'www.redhat.com'))\n\
    str(rdn)\n\
       returns 'CN=www.redhat.com'\n\
    rdn[0]\n\
       returns an `AVA` object with the value C=US\n\
    rdn['cn']\n\
        returns a list comprised of an `AVA` object with the value CN=www.redhat.com\n\
    rdn['2.5.4.3']\n\
        returns a list comprised of an `AVA` object with the value CN=www.redhat.com\n\
        because 2.5.4.3 is the dotted-decimal OID for common name (i.e. cn)\n\
    rdn.has_key('cn')\n\
        returns True because the RDN has a common name RDN\n\
    rdn.has_key('2.5.4.3')\n\
        returns True because the RDN has a common name AVA\n\
        because 2.5.4.3 is the dotted-decimal OID for common name (i.e. cn)\n\
    len(rdn)\n\
       returns 1 because there is one `AVA` object in it\n\
    list(rdn)\n\
       returns a list of each `AVA` object in it\n\
\n\
");

static int
RDN_init(RDN *self, PyObject *args, PyObject *kwds)
{
    PyObject *sequence, *item;
    Py_ssize_t sequence_len, i;
    AVA *py_ava;
    CERTAVA *ava_arg[MAX_AVAS+1];  /* +1 for NULL terminator */

    TraceMethodEnter(self);

    if (PyTuple_GET_SIZE(args) > 0) {
        sequence = PyTuple_GetItem(args, 0);
        if (!(PyTuple_Check(sequence) || PyList_Check(sequence))) {
            sequence = args;
        }
        sequence_len = PySequence_Length(sequence);
        if (sequence_len > MAX_AVAS) {
            PyErr_Format(PyExc_ValueError, "to many AVA items, maximum is %d, received %zd",
                         MAX_AVAS-1, sequence_len);
            return -1;
        }
        for (i = 0; i < sequence_len && i < MAX_AVAS; i++) {
            item = PySequence_ITEM(sequence, i);
            if (PyAVA_Check(item)) {
                py_ava = (AVA *)item;
                if ((ava_arg[i] = CERT_CopyAVA(self->arena, py_ava->ava)) == NULL) {
                    set_nspr_error(NULL);
                    Py_DECREF(item);
                    return -1;
                }
                Py_DECREF(item);
            } else {
                PyErr_Format(PyExc_TypeError, "item %zd must be an AVA object, not %.200s",
                             i, Py_TYPE(item)->tp_name);
                Py_DECREF(item);
                return -1;
                }
            }

        for (; i < MAX_AVAS+1; i++) ava_arg[i] = NULL;

        if ((self->rdn = CERT_CreateRDN(self->arena,
                                        ava_arg[0], ava_arg[1], ava_arg[2], ava_arg[3],
                                        ava_arg[4], ava_arg[5], ava_arg[6], ava_arg[7],
                                        ava_arg[8], ava_arg[9], ava_arg[10])) == NULL) {
            set_nspr_error(NULL);
            return -1;
        }
    }

    return 0;
}

static PySequenceMethods RDN_as_sequence = {
    (lenfunc)RDN_length,			/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)RDN_item,			/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyMappingMethods RDN_as_mapping = {
    (lenfunc)RDN_length,			/* mp_length */
    (binaryfunc)RDN_subscript,			/* mp_subscript */
    0,						/* mp_ass_subscript */
};

static PyTypeObject RDNType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.RDN",				/* tp_name */
    sizeof(RDN),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)RDN_dealloc,			/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    (cmpfunc)RDN_compare,			/* tp_compare */
    (reprfunc)RDN_repr,				/* tp_repr */
    0,						/* tp_as_number */
    &RDN_as_sequence,				/* tp_as_sequence */
    &RDN_as_mapping,				/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    0,						/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    RDN_doc,					/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    RDN_methods,				/* tp_methods */
    RDN_members,				/* tp_members */
    RDN_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)RDN_init,				/* tp_init */
    0,						/* tp_alloc */
    RDN_new,					/* tp_new */
};

PyObject *
RDN_new_from_CERTRDN(CERTRDN *rdn)
{
    RDN *self = NULL;
    int i;
    CERTAVA *ava_arg[MAX_AVAS+1];  /* +1 for NULL terminator */
    CERTAVA **avas, *ava;

    TraceObjNewEnter(NULL);

    if ((self = (RDN *) RDNType.tp_new(&RDNType, NULL, NULL)) == NULL) {
        return NULL;
    }

    i = 0;
    if (rdn) {
        for (avas = rdn->avas; i < MAX_AVAS && avas && (ava = *avas); avas++, i++) {
            if ((ava_arg[i] = CERT_CopyAVA(self->arena, ava)) == NULL) {
                set_nspr_error(NULL);
                Py_CLEAR(self);
                return NULL;
            }
        }
    }

    for (; i < MAX_AVAS+1; i++) ava_arg[i] = NULL;

    if ((self->rdn = CERT_CreateRDN(self->arena,
                                    ava_arg[0], ava_arg[1], ava_arg[2], ava_arg[3],
                                    ava_arg[4], ava_arg[5], ava_arg[6], ava_arg[7],
                                    ava_arg[8], ava_arg[9], ava_arg[10])) == NULL) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* =============================== DN Class ================================= */
/* ========================================================================== */

/*
 * NSS WART
 *
 * CERT_CopyRDN() does not return a new CERTRDN, requires calling CERT_CreateRDN()
 *
 * CERT_CreateName() does not copy it's rdn arguments, must call CERT_CopyRDN()
 *
 * CERT_CreateName() does not allow you to pass in an arena, it creates one
 * and stores it internally. But to call CERT_CreateName() you have to call
 * CERT_CopyRDN() which requires an arena. This means a CERTName object has to
 * have 2 arenas when one would have sufficed, it also means more bookkeeping
 * to manage the second unnecessary arena.
 *
 * CERT_CopyAVA() doesn't return SECStatus unlike other copy routines.
 */

/*
 * All these are defined in cert.h and all are exported in nss.def
 *
 * CERT_AsciiToName
 * CERT_NameToAscii
 * CERT_NameToAsciiInvertible
 * CERT_CreateName
 * CERT_CopyName
 * CERT_DestroyName
 * CERT_AddRDN
 * CERT_CompareName
 * CERT_FormatName
 * CERT_GetCertEmailAddress
 * CERT_GetCommonName
 * CERT_GetCountryName
 * CERT_GetLocalityName
 * CERT_GetStateName
 * CERT_GetOrgName
 * CERT_GetOrgUnitName
 * CERT_GetDomainComponentName
 * CERT_GetCertUid
 */

static bool
CERTName_has_tag(CERTName *name, int tag)
{
    CERTRDN **rdns, *rdn;
    CERTAVA **avas, *ava;

    if (!name) return false;
    for (rdns = name->rdns; rdns && (rdn = *rdns); rdns++) {
	for (avas = rdn->avas; avas && (ava = *avas); avas++) {
	    int ava_tag = CERT_GetAVATag(ava);
	    if (tag == ava_tag) {
                return true;
	    }
	}
    }

    return false;
}

static PyObject *
CERTName_get_matching_tag_list(CERTName *name, int tag)
{
    PyObject *list = NULL;
    PyObject *py_rdn = NULL;
    CERTRDN **rdns, *rdn;
    CERTAVA **avas, *ava;

    if ((list = PyList_New(0)) == NULL) {
        return NULL;
    }

    if (!name) {
        return list;
    }

    for (rdns = name->rdns; rdns && (rdn = *rdns); rdns++) {
	for (avas = rdn->avas; avas && (ava = *avas); avas++) {
	    int ava_tag = CERT_GetAVATag(ava);
	    if (tag == ava_tag) {
                if ((py_rdn = RDN_new_from_CERTRDN(rdn)) == NULL) {
                    Py_DECREF(list);
                    return NULL;
                }
                PyList_Append(list, py_rdn);
                break;
	    }
	}
    }

    return list;
}

static PyObject*
DN_subscript(DN *self, PyObject* item)
{
    PyObject* result = NULL;

    if (PyIndex_Check(item)) {
        Py_ssize_t i = PyNumber_AsSsize_t(item, PyExc_IndexError);

        if (i == -1 && PyErr_Occurred())
            return NULL;
        if (i < 0)
            i += DN_length(self);
        return DN_item(self, i);
    } else if (PySlice_Check(item)) {
        Py_ssize_t start, stop, step, slicelength, cur, i;
        PyObject* py_ava;

        if (PySlice_GetIndicesEx((PySliceObject*)item, DN_length(self),
				 &start, &stop, &step, &slicelength) < 0) {
            return NULL;
        }

        if (slicelength <= 0) {
            return PyList_New(0);
        } else {
            result = PyList_New(slicelength);
            if (!result) return NULL;

            for (cur = start, i = 0; i < slicelength; cur += step, i++) {
                /* We don't need to bump the ref count because RDN_item
                 * returns a new object */
                py_ava = DN_item(self, cur);
                if (PyList_SetItem(result, i, py_ava) == -1) {
                    Py_DECREF(result);
                    return NULL;
                }
            }
            return result;
	}
    } else if (PyString_Check(item) || PyUnicode_Check(item) || PySecItem_Check(item)) {
        int oid_tag;

        if ((oid_tag = get_oid_tag_from_object(item)) == -1) {
            return NULL;
        }

        if (oid_tag == SEC_OID_UNKNOWN) {
            if (PyString_Check(item) || PyUnicode_Check(item)) {
                char *name = PyString_AsString(item);
                PyErr_Format(PyExc_KeyError, "oid name unknown: \"%s\"", name);
                return NULL;
            } else {
                PyErr_SetString(PyExc_KeyError, "oid unknown");
                return NULL;
            }
        }

        if ((result = CERTName_get_matching_tag_list(&self->name, oid_tag)) == NULL) {
            return NULL;
        }

        if (PyList_Size(result) == 0) {
            Py_DECREF(result);
            if (PyString_Check(item) || PyUnicode_Check(item)) {
                char *name = PyString_AsString(item);
                PyErr_Format(PyExc_KeyError, "oid name not found: \"%s\"", name);
                return NULL;
            } else {
                PyErr_SetString(PyExc_KeyError, "oid not found");
                return NULL;
            }
        } else {
            return result;
        }
    } else {
        PyErr_Format(PyExc_TypeError,
                     "indices must be integers or strings, not %.200s",
                     item->ob_type->tp_name);
        return NULL;
    }
    return NULL;
}

PyDoc_STRVAR(DN_has_key_doc,
"has_key(arg) -> bool\n\
\n\
:Parameters:\n\
    arg : string or integer\n\
        canonical name (e.g. 'cn') or oid dotted-decimal or\n\
        SEC_OID_* enumeration constant\n\
\n\
return True if Name has an AVA whose oid can be identified by arg.\n\
");

static PyObject *
DN_has_key(DN *self, PyObject *args)
{
    PyObject *arg;
    int oid_tag;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:has_key",
                          &arg))
        return NULL;

    oid_tag = get_oid_tag_from_object(arg);
    if (oid_tag == SEC_OID_UNKNOWN || oid_tag == -1) {
        Py_RETURN_FALSE;
    }

    if (CERTName_has_tag(&self->name, oid_tag)) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

/* =========================== Sequence Protocol ============================ */

static Py_ssize_t
CERTName_rdn_count(CERTName *name)
{
    Py_ssize_t count = 0;
    CERTRDN **rdns;

    for (rdns = name->rdns, count = 0; *rdns; rdns++, count++);

    return count;
}

static Py_ssize_t
DN_length(DN *self)
{
    return CERTName_rdn_count(&self->name);
}

static PyObject *
DN_item(DN *self, register Py_ssize_t i)
{
    Py_ssize_t count = 0;
    CERTRDN **rdns;

    if (i < 0 || self->name.rdns == NULL) {
        PyErr_SetString(PyExc_IndexError, "DN index out of range");
        return NULL;
    }

    for (rdns = self->name.rdns, count = 0; *rdns && count < i; rdns++, count++);

    if (!*rdns) {
        PyErr_SetString(PyExc_IndexError, "DN index out of range");
        return NULL;
    }

    return RDN_new_from_CERTRDN(*rdns);
}

/* ============================ Attribute Access ============================ */

static PyObject *
DN_get_email_address(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetCertEmailAddress(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static PyObject *
DN_get_common_name(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetCommonName(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static PyObject *
DN_get_country_name(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetCountryName(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static PyObject *
DN_get_locality_name(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetLocalityName(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static PyObject *
DN_get_state_name(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetStateName(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static PyObject *
DN_get_org_name(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetOrgName(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static PyObject *
DN_get_org_unit_name(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetOrgUnitName(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static PyObject *
DN_get_domain_component_name(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetDomainComponentName(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static PyObject *
DN_get_cert_uid(DN *self, void *closure)
{
    char *value;

    TraceMethodEnter(self);

    if ((value = CERT_GetCertUid(&self->name)) == NULL) {
        Py_RETURN_NONE;
    }
    return PyString_FromString(value);
}

static
PyGetSetDef DN_getseters[] = {
    {"email_address", (getter)DN_get_email_address, (setter)NULL,
     "Returns the email address member as a string. Returns None if not found.", NULL},
    {"common_name", (getter)DN_get_common_name, (setter)NULL,
     "Returns the common name member (i.e. CN) as a string. Returns None if not found.", NULL},
    {"country_name", (getter)DN_get_country_name, (setter)NULL,
     "Returns the country name member (i.e. C) as a string. Returns None if not found.", NULL},
    {"locality_name", (getter)DN_get_locality_name, (setter)NULL,
     "Returns the locality name member (i.e. L) as a string. Returns None if not found.", NULL},
    {"state_name", (getter)DN_get_state_name, (setter)NULL,
     "Returns the state name member (i.e. ST) as a string. Returns None if not found.", NULL},
    {"org_name", (getter)DN_get_org_name, (setter)NULL,
     "Returns the organization name member (i.e. O) as a string. Returns None if not found.", NULL},
    {"org_unit_name", (getter)DN_get_org_unit_name, (setter)NULL,
     "Returns the organizational unit name member (i.e. OU) as a string. Returns None if not found.", NULL},
    {"dc_name", (getter)DN_get_domain_component_name, (setter)NULL,
     "Returns the domain component name member (i.e. DC) as a string. Returns None if not found.", NULL},
    {"cert_uid", (getter)DN_get_cert_uid, (setter)NULL,
     "Returns the certificate uid member (i.e. UID) as a string. Returns None if not found.", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef DN_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static int
DN_compare(DN *self, DN *other)
{
    if (!PyDN_Check(other)) {
        PyErr_SetString(PyExc_TypeError, "Bad type, must be DN");
        return -1;
    }

    return CERT_CompareName(&self->name, &other->name);
}

PyDoc_STRVAR(DN_add_rdn_doc,
"add_rdn(rdn) \n\
\n\
:Parameters:\n\
    rdn : RDN object\n\
        The rnd to add to the name\n\
\n\
Adds a RDN to the name.\n\
");

static PyObject *
DN_add_rdn(DN *self, PyObject *args)
{
    RDN *py_rdn;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O!:add_rdn",
                          &RDNType, &py_rdn))
        return NULL;

    if (CERT_AddRDN(&self->name, py_rdn->rdn) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

static PyMethodDef DN_methods[] = {
    {"has_key", (PyCFunction)DN_has_key, METH_VARARGS, DN_has_key_doc},
    {"add_rdn", (PyCFunction)DN_add_rdn, METH_VARARGS, DN_add_rdn_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
DN_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    DN *self;

    TraceObjNewEnter(type);

    if ((self = (DN *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    memset(&self->name, 0, sizeof(self->name));

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
DN_dealloc(DN* self)
{
    TraceMethodEnter(self);

    CERT_DestroyName(&self->name);

    if (self->arena) {
        PORT_FreeArena(self->arena, PR_FALSE);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(DN_doc,
"An object representing an X501 Distinguished Name (e.g DN).\n\
\n\
DN objects contain an ordered list of `RDN` objects.\n\
\n\
The DN object constructor may be invoked with a string\n\
representing an X500 name. Zero or more `RDN` objects, or you may\n\
optionally pass a list or tuple of `RDN` objects.\n\
\n\
Examples::\n\
\n\
    DN()\n\
    DN('CN=www.redhat.com,OU=Web Operations,O=Red Hat Inc,L=Raleigh,ST=North Carolina,C=US')\n\
    DN(rdn0, ...)\n\
    DN([rdn0, rdn1])\n\
\n\
**The string representation of a Distinguished Name (DN) has reverse\n\
ordering from it's sequential components.**\n\
\n\
The ordering is a requirement of the relevant RFC's. When a\n\
Distinguished Name is rendered as a string it is ordered from most\n\
specific to least specific. However it's components (RDN's) as a\n\
sequence are ordered from least specific to most specific.\n\
\n\
DN objects contain an ordered list of `RDN` objects. The\n\
DN object has both sequence and mapping behaviors with respect to\n\
the RDN's they contain. Thus you can index an RDN by position, by\n\
name, or by SecItem (if it's an OID). You can iterate over the list,\n\
get it's length or take a slice.\n\
\n\
If you index by string the string may be either a canonical name for\n\
the RDN type (e.g. 'cn') or the dotted-decimal notation for the OID\n\
(e.g. 2.5.4.3). There may be multiple RDN's in a DN whose type matches\n\
(e.g. OU=engineering, OU=boston). It is not common to have more than\n\
one RDN in a DN with the same type. However because of the possiblity\n\
of being multi-valued when indexing by type a list is always returned\n\
containing the matching RDN's. Thus::\n\
\n\
    dn = nss.DN('OU=engineering')\n\
    dn['ou']\n\
        returns [RDN('OU=engineering')\n\
\n\
    dn = nss.DN('OU=engineering, OU=boston')\n\
    dn['ou']\n\
        returns [RDN('OU=boston'), RDN('OU=engineering')]\n\
        Note the reverse ordering between string representation and RDN sequencing\n\
\n\
Note, if you use properties to access the RDN values (e.g. name.common_name,\n\
name.org_unit_name) the string value is returned or None if not found.\n\
If the item was multi-valued then the most appropriate item will be selected\n\
and returned as a string value.\n\
\n\
Note it is not possible to index by oid tag\n\
(e.g. nss.SEC_OID_AVA_COMMON_NAME) because oid tags are integers and\n\
it's impossible to distinguish between an integer representing the\n\
n'th member of the sequence and the integer representing the oid\n\
tag. In this case positional indexing wins (e.g. rdn[0] means the\n\
first element).\n\
\n\
Examples::\n\
\n\
    subject_name = 'CN=www.redhat.com,OU=Web Operations,O=Red Hat Inc,L=Raleigh,ST=North Carolina,C=US'\n\
    name = nss.DN(subject_name)\n\
    str(name)\n\
       returns 'CN=www.redhat.com,OU=Web Operations,O=Red Hat Inc,L=Raleigh,ST=North Carolina,C=US'\n\
    name[0]\n\
       returns an `RDN` object with the value C=US\n\
    name['cn']\n\
        returns a list comprised of an `RDN` object with the value CN=www.redhat.com\n\
    name['2.5.4.3']\n\
        returns a list comprised of an `RDN` object with the value CN=www.redhat.com\n\
        because 2.5.4.3 is the dotted-decimal OID for common name (i.e. cn)\n\
    name.common_name\n\
        returns the string www.redhat.com\n\
        common_name is easy shorthand property, it only retuns a single string\n\
        value or None, if it was multi-valued the most appropriate item is selected.\n\
    name.has_key('cn')\n\
        returns True because the DN has a common name RDN\n\
    name.has_key('2.5.4.3')\n\
        returns True because the DN has a common name RDN\n\
        because 2.5.4.3 is the dotted-decimal OID for common name (i.e. cn)\n\
\n\
    cn_rdn = nss.RDN(nss.AVA('cn', 'www.redhat.com'))\n\
    ou_rdn = nss.RDN(nss.AVA('ou', 'Web Operations'))\n\
    name = nss.DN(cn_rdn)\n\
    name\n\
       is a DN with one RDN (e.g. CN=www.redhat.com)\n\
    len(name)\n\
       returns 1 because there is one RDN in it\n\
    name.add_rdn(ou_rdn)\n\
    name\n\
       name is now a DN with two RDN's (e.g. OU=Web Operations,CN=www.redhat.com)\n\
    len(name)\n\
       returns 2 because there are now two RDN's in it\n\
    list(name)\n\
       returns a list with the two RDN's in it\n\
    name[:]\n\
       same as list(name)\n\
    for rdn in name:\n\
       iterate over each RDN in name\n\
    name = nss.DN(cn_rdn, ou_rdn)\n\
        This is an alternate way to build the above DN\n\
");

static int
DN_init(DN *self, PyObject *args, PyObject *kwds)
{
    PyObject *sequence, *item;
    Py_ssize_t sequence_len, i;
    RDN *py_rdn;
    CERTRDN *new_rdn;
    CERTName *cert_name;
    CERTRDN *rdn_arg[MAX_RDNS+1];  /* +1 for NULL terminator */

    TraceMethodEnter(self);

    CERT_DestroyName(&self->name);

    if (PyTuple_GET_SIZE(args) > 0) {
        item = PyTuple_GetItem(args, 0);
        if (PyString_Check(item) || PyUnicode_Check(item)) {
            char *ascii_name;

            if ((ascii_name = PyString_AsString(item)) == NULL) {
                return -1;
            }

            if (strlen(ascii_name) == 0) goto empty_name;

            if ((cert_name = CERT_AsciiToName(ascii_name)) == NULL) {
                set_nspr_error("cannot parse X500 name \"%s\"", ascii_name);
                return -1;
            }

            self->name = *cert_name;
            return 0;
        }

        if (PyRDN_Check(item)) {
            sequence = args;
        } else if (PyList_Check(item) || PyTuple_Check(item)) {
            sequence = item;
        } else {
            PyErr_Format(PyExc_TypeError, "must be an RDN object or list or tuple of RDN objects, not %.200s",
                         Py_TYPE(item)->tp_name);
            return -1;
        }

        sequence_len = PySequence_Length(sequence);

        if (sequence_len > MAX_RDNS) {
            PyErr_Format(PyExc_ValueError, "to many RDN items, maximum is %d, received %zd",
                         MAX_RDNS-1, sequence_len);
            return -1;
        }

        for (i = 0; i < sequence_len && i < MAX_RDNS; i++) {
            item = PySequence_ITEM(sequence, i);
            if (PyRDN_Check(item)) {
                py_rdn = (RDN *)item;

                if ((new_rdn = CERT_CreateRDN(self->arena, NULL)) == NULL) {
                    set_nspr_error(NULL);
                    Py_DECREF(item);
                    return -1;
                }

                if (CERT_CopyRDN(self->arena, new_rdn, py_rdn->rdn) != SECSuccess) {
                    set_nspr_error(NULL);
                    Py_DECREF(item);
                    return -1;
                }
                rdn_arg[i] = new_rdn;
            } else {
                PyErr_Format(PyExc_TypeError, "item %zd must be an RDN object, not %.200s",
                             i, Py_TYPE(item)->tp_name);
                Py_DECREF(item);
                return -1;
            }
            Py_DECREF(item);
        }

        for (; i < MAX_RDNS+1; i++) rdn_arg[i] = NULL;

        if ((cert_name = CERT_CreateName(rdn_arg[0], rdn_arg[1], rdn_arg[2], rdn_arg[3],
                                         rdn_arg[4], rdn_arg[5], rdn_arg[6], rdn_arg[7],
                                         rdn_arg[8], rdn_arg[9], rdn_arg[10])) == NULL) {
            set_nspr_error(NULL);
            return -1;
        }
        self->name = *cert_name;
    } else {
    empty_name:
        if ((cert_name = CERT_CreateName(NULL)) == NULL) {
            set_nspr_error(NULL);
            return -1;
        }
        self->name = *cert_name;
    }
    return 0;
}

static PyObject *
DN_repr(DN *self)
{
    return CERTName_to_pystr(&self->name);
}

static PySequenceMethods DN_as_sequence = {
    (lenfunc)DN_length,				/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)DN_item,			/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyMappingMethods DN_as_mapping = {
    (lenfunc)DN_length,				/* mp_length */
    (binaryfunc)DN_subscript,			/* mp_subscript */
    0,						/* mp_ass_subscript */
};

static PyTypeObject DNType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.DN",				/* tp_name */
    sizeof(DN),					/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)DN_dealloc,			/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    (cmpfunc)DN_compare,			/* tp_compare */
    (reprfunc)DN_repr,				/* tp_repr */
    0,						/* tp_as_number */
    &DN_as_sequence,				/* tp_as_sequence */
    &DN_as_mapping,				/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)DN_repr,				/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    DN_doc,					/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    DN_methods,					/* tp_methods */
    DN_members,					/* tp_members */
    DN_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)DN_init,				/* tp_init */
    0,						/* tp_alloc */
    DN_new,					/* tp_new */
};

PyObject *
DN_new_from_CERTName(CERTName *name)
{
    DN *self = NULL;
    PRArenaPool *arena;

    TraceObjNewEnter(NULL);

    if ((self = (DN *) DNType.tp_new(&DNType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    if (CERT_CopyName(arena, &self->name, name) != SECSuccess) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* =========================== GeneralName Class ============================ */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
GeneralName_get_name_string(GeneralName *self, void *closure)
{
    TraceMethodEnter(self);

    if (!self->name) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }
    return CERTGeneralName_to_pystr(self->name);
}

static PyObject *
GeneralName_get_type_enum(GeneralName *self, void *closure)
{
    TraceMethodEnter(self);

    if (!self->name) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }
    return PyInt_FromLong(self->name->type);
}

static PyObject *
GeneralName_get_type_name(GeneralName *self, void *closure)
{
    TraceMethodEnter(self);

    if (!self->name) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }
    return general_name_type_to_pystr(self->name->type);
}

static PyObject *
GeneralName_get_type_string(GeneralName *self, void *closure)
{
    TraceMethodEnter(self);

    if (!self->name) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }
    return CERTGeneralName_type_string_to_pystr(self->name);
}

static
PyGetSetDef GeneralName_getseters[] = {
    {"name",      (getter)GeneralName_get_name_string, (setter)NULL,
     "Returns the general name as a string", NULL},
    {"type_enum", (getter)GeneralName_get_type_enum, (setter)NULL,
     "Returns the general name type enumerated constant", NULL},
    {"type_name", (getter)GeneralName_get_type_name, (setter)NULL,
     "Returns the general name type enumerated constant as a string", NULL},
    {"type_string", (getter)GeneralName_get_type_string, (setter)NULL,
     "Returns the type of the general name as a string (e.g. \"URI\")", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef GeneralName_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(GeneralName_get_name_doc,
"get_name(repr_kind=AsString) -> \n\
\n\
:Parameters:\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsObject\n\
            The general name as a nss.GeneralName object\n\
        AsString\n\
            The general name as a string.\n\
            (e.g. \"http://crl.geotrust.com/crls/secureca.crl\")\n\
        AsTypeString\n\
            The general name type as a string.\n\
             (e.g. \"URI\")\n\
        AsTypeEnum\n\
            The general name type as a general name type enumerated constant.\n\
             (e.g. nss.certURI )\n\
        AsLabeledString\n\
            The general name as a string with it's type prepended.\n\
            (e.g. \"URI: http://crl.geotrust.com/crls/secureca.crl\"\n\
\n\
Returns the value of the GeneralName according to the representation type parameter.\n\
");

static PyObject *
GeneralName_get_name(GeneralName *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"repr_kind", NULL};
    PyObject *name;
    int repr_kind = AsString;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:get_name", kwlist,
                                     &repr_kind))
        return NULL;


    if (!self->name) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }

    switch(repr_kind) {
    case AsObject:
        Py_INCREF(self);
        name = (PyObject *)self;
        break;
    case AsString:
        name = CERTGeneralName_to_pystr(self->name);
        break;
    case AsTypeString:
        name = CERTGeneralName_type_string_to_pystr(self->name);
        break;
    case AsTypeEnum:
        name = PyInt_FromLong(self->name->type);
        break;
    case AsLabeledString:
        name = CERTGeneralName_to_pystr_with_label(self->name);
        break;
    default:
        PyErr_Format(PyExc_ValueError, "Unsupported representation kind (%d)", repr_kind);
        return NULL;
    }

    return name;
}

static PyMethodDef GeneralName_methods[] = {
    {"get_name", (PyCFunction)GeneralName_get_name, METH_VARARGS|METH_KEYWORDS, GeneralName_get_name_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
GeneralName_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    GeneralName *self;

    TraceObjNewEnter(type);

    if ((self = (GeneralName *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    self->name = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
GeneralName_dealloc(GeneralName* self)
{
    TraceMethodEnter(self);

    if (self->arena) {
        PORT_FreeArena(self->arena, PR_FALSE);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(GeneralName_doc,
"An object representing a GeneralName or list of GeneralNames.\n\
\n\
");

static int
GeneralName_init(GeneralName *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"sec_item", NULL};
    SecItem *py_sec_item;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:GeneralName", kwlist,
                                     &SecItemType, &py_sec_item))
        return -1;

    if ((self->name = CERT_DecodeGeneralName(self->arena, &py_sec_item->item, NULL)) == NULL) {
        set_nspr_error(NULL);
        return -1;
    }

    return 0;
}

static PyObject *
GeneralName_repr(GeneralName *self)
{
    PyObject *result = NULL;

    if (!self->name) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }

    if ((result = CERTGeneralName_to_pystr_with_label(self->name)) == NULL) {
        result = PyString_FromFormat("<%s object at %p>",
                                     Py_TYPE(self)->tp_name, self);
    }

    return result;
}

static Py_ssize_t
GeneralName_length(GeneralName *self)
{
    if (!self->name) {
        PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
        return -1;
    }

    return CERTGeneralName_list_count(self->name);
}

static PyObject *
GeneralName_item(GeneralName *self, register Py_ssize_t i)
{
    CERTGeneralName *head, *cur;
    Py_ssize_t index;

    if (!self->name) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }

    index = 0;
    cur = head = self->name;
    do {
        cur = CERT_GetNextGeneralName(cur);
        if (i == index) {
            return GeneralName_new_from_CERTGeneralName(cur);
        }
        index++;
    } while (cur != head);

    PyErr_SetString(PyExc_IndexError, "GeneralName index out of range");
    return NULL;
}

static PySequenceMethods GeneralName_as_sequence = {
    (lenfunc)GeneralName_length,		/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)GeneralName_item,		/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyTypeObject GeneralNameType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.GeneralName",			/* tp_name */
    sizeof(GeneralName),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)GeneralName_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)GeneralName_repr,			/* tp_repr */
    0,						/* tp_as_number */
    &GeneralName_as_sequence,			/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    0,						/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    GeneralName_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    GeneralName_methods,			/* tp_methods */
    GeneralName_members,			/* tp_members */
    GeneralName_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)GeneralName_init,			/* tp_init */
    0,						/* tp_alloc */
    0,						/* tp_new */
};

PyObject *
GeneralName_new_from_CERTGeneralName(CERTGeneralName *name)
{
    GeneralName *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (GeneralName *) GeneralName_new(&GeneralNameType, NULL, NULL)) == NULL) {
        return NULL;
    }

    /*
     * NSS WART
     * There is no public API to create a CERTGeneralName, copy it, or free it.
     * You don't know what arena was used to create the general name.
     * GeneralNames are linked in a list, this makes it difficult for a
     * general name to exist independently, it would have been better if there
     * was a list container independent general names could be placed in,
     * then you wouldn't have to worry about the link fields in each independent name.
     */

    if (CERT_CopyGeneralName(self->arena, &self->name, name) != SECSuccess) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

PyDoc_STRVAR(cert_get_default_certdb_doc,
"get_default_certdb()\n\
\n\
Returns the default certificate database as a CertDB object\n\
");
static PyObject *
cert_get_default_certdb(PyObject *self, PyObject *args)
{
    CERTCertDBHandle *certdb_handle;

    TraceMethodEnter(self);

    if ((certdb_handle = CERT_GetDefaultCertDB()) == NULL) {
        Py_RETURN_NONE;
    }

    return CertDB_new_from_CERTCertDBHandle(certdb_handle);
}

PyDoc_STRVAR(cert_get_cert_nicknames_doc,
"get_cert_nicknames(certdb, what, [user_data1, ...]) -> name0, ...\n\
\n\
:Parameters:\n\
    certdb : CertDB object\n\
        CertDB certificate database object\n\
    what : integer\n\
        one of:\n\
            - SEC_CERT_NICKNAMES_ALL\n\
            - SEC_CERT_NICKNAMES_USER\n\
            - SEC_CERT_NICKNAMES_SERVER\n\
            - SEC_CERT_NICKNAMES_CA\n\
    user_dataN : object\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Returns a tuple of the nicknames of the certificates in a specified\n\
certificate database.\n\
");

static PyObject *
cert_get_cert_nicknames(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 2;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    CertDB *py_certdb = NULL;
    int what;
    CERTCertNicknames *cert_nicknames = NULL;
    PyObject *py_nicknames = NULL;
    PyObject *py_nickname = NULL;
    int i, len;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "O!i:get_cert_nicknames",
                          &CertDBType, &py_certdb, &what)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((cert_nicknames = CERT_GetCertNicknames(py_certdb->handle, what, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    len = cert_nicknames->numnicknames;
    if ((py_nicknames = PyTuple_New(len)) == NULL) {
        CERT_FreeNicknames(cert_nicknames);
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if ((py_nickname = PyString_FromString(cert_nicknames->nicknames[i])) == NULL) {
            CERT_FreeNicknames(cert_nicknames);
            return NULL;
        }
        PyTuple_SetItem(py_nicknames, i, py_nickname);
    }

    CERT_FreeNicknames(cert_nicknames);

    return py_nicknames;
}

PyDoc_STRVAR(pk11_hash_buf_doc,
"hash_buf(hash_alg, data) --> digest\n\
\n\
:Parameters:\n\
    hash_alg : int\n\
        hash algorithm enumeration (SEC_OID_*)\n\
        e.g.: SEC_OID_MD5, SEC_OID_SHA1, SEC_OID_SHA256, SEC_OID_SHA512, etc.\n\
    data : buffer or string\n\
        buffer the digest will be computed for\n\
\n\
Computes a digest according to the hash_alg type.\n\
Return the digest data as buffer object.\n\
\n\
Note, if a hexidecimal string representation is desired then pass\n\
result to data_to_hex()\n\
");
static PyObject *
pk11_hash_buf(PyObject *self, PyObject *args)
{
    unsigned long hash_alg;
    unsigned char *in_data = NULL;
    Py_ssize_t in_data_len = 0;
    unsigned int hash_len;
    PyObject *py_out_buf = NULL;
    void *out_buf = NULL;
    Py_ssize_t out_buf_len;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "kt#:hash_buf",
                          &hash_alg, &in_data, &in_data_len)) {
        return NULL;
    }

    if ((hash_len = HASH_ResultLenByOidTag(hash_alg)) == 0) {
        return set_nspr_error("unable to determine resulting hash length for hash_alg = %s",
                              oid_tag_str(hash_alg));
    }

    out_buf_len = hash_len;

    if ((py_out_buf = PyString_FromStringAndSize(NULL, out_buf_len)) == NULL) {
        return NULL;
    }

    if ((out_buf = PyString_AsString(py_out_buf)) == NULL) {
        return NULL;
    }

    if (PK11_HashBuf(hash_alg, out_buf, in_data, in_data_len) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return py_out_buf;
}

PyDoc_STRVAR(pk11_md5_digest_doc,
"md5_digest(data) --> digest\n\
\n\
:Parameters:\n\
    data : buffer or string\n\
        buffer the digest will be computed for\n\
\n\
Returns 16 octet MD5 digest data as buffer object.\n\
\n\
Note, if a hexidecimal string representation is desired then pass\n\
result to data_to_hex()\n\
");
static PyObject *
pk11_md5_digest(PyObject *self, PyObject *args)
{
    unsigned char *in_data = NULL;
    Py_ssize_t in_data_len = 0;
    PyObject *py_out_buf = NULL;
    void *out_buf;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "t#:md5_digest", &in_data, &in_data_len)) {
        return NULL;
    }

    if ((py_out_buf = PyString_FromStringAndSize(NULL, MD5_LENGTH)) == NULL) {
        return NULL;
    }

    if ((out_buf = PyString_AsString(py_out_buf)) == NULL) {
        return NULL;
    }

    if (PK11_HashBuf(SEC_OID_MD5, out_buf, in_data, in_data_len) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return py_out_buf;
}

PyDoc_STRVAR(pk11_sha1_digest_doc,
"sha1_digest(data) --> digest\n\
\n\
:Parameters:\n\
    data : buffer or string\n\
        buffer the digest will be computed for\n\
\n\
Returns 20 octet SHA1 digest data as buffer object.\n\
\n\
Note, if a hexidecimal string representation is desired then pass\n\
result to data_to_hex()\n\
");
static PyObject *
pk11_sha1_digest(PyObject *self, PyObject *args)
{
    unsigned char *in_data = NULL;
    Py_ssize_t in_data_len = 0;
    PyObject *py_out_buf = NULL;
    void *out_buf;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "t#:sha1_digest", &in_data, &in_data_len)) {
        return NULL;
    }

    if ((py_out_buf = PyString_FromStringAndSize(NULL, SHA1_LENGTH)) == NULL) {
        return NULL;
    }

    if ((out_buf = PyString_AsString(py_out_buf)) == NULL) {
        return NULL;
    }

    if (PK11_HashBuf(SEC_OID_SHA1, out_buf, in_data, in_data_len) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return py_out_buf;
}

PyDoc_STRVAR(pk11_sha256_digest_doc,
"sha256_digest(data) --> digest\n\
\n\
:Parameters:\n\
    data : buffer or string\n\
        buffer the digest will be computed for\n\
\n\
Returns 32 octet SHA256 digest data as buffer object.\n\
\n\
Note, if a hexidecimal string representation is desired then pass\n\
result to data_to_hex()\n\
");

static PyObject *
pk11_sha256_digest(PyObject *self, PyObject *args)
{
    unsigned char *in_data = NULL;
    Py_ssize_t in_data_len = 0;
    PyObject *py_out_buf = NULL;
    void *out_buf;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "t#:sha256_digest", &in_data, &in_data_len)) {
        return NULL;
    }

    if ((py_out_buf = PyString_FromStringAndSize(NULL, SHA256_LENGTH)) == NULL) {
        return NULL;
    }

    if ((out_buf = PyString_AsString(py_out_buf)) == NULL) {
        return NULL;
    }

    if (PK11_HashBuf(SEC_OID_SHA256, out_buf, in_data, in_data_len) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return py_out_buf;
}

PyDoc_STRVAR(pk11_sha512_digest_doc,
"sha512_digest(data) --> digest\n\
\n\
:Parameters:\n\
    data : buffer or string\n\
        buffer the digest will be computed for\n\
\n\
Returns 64 octet SHA512 digest data as buffer object.\n\
\n\
Note, if a hexidecimal string representation is desired then pass\n\
result to data_to_hex()\n\
");
static PyObject *
pk11_sha512_digest(PyObject *self, PyObject *args)
{
    unsigned char *in_data = NULL;
    Py_ssize_t in_data_len = 0;
    PyObject *py_out_buf = NULL;
    void *out_buf;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "t#:sha512_digest", &in_data, &in_data_len)) {
        return NULL;
    }

    if ((py_out_buf = PyString_FromStringAndSize(NULL, SHA512_LENGTH)) == NULL) {
        return NULL;
    }

    if ((out_buf = PyString_AsString(py_out_buf)) == NULL) {
        return NULL;
    }

    if (PK11_HashBuf(SEC_OID_SHA512, out_buf, in_data, in_data_len) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return py_out_buf;
}

/* ========================================================================== */
/* ============================== PK11Slot Class ============================ */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
PK11_get_slot_name(PK11Slot *self, void *closure)
{
    char *slot_name = NULL;

    TraceMethodEnter(self);

    if ((slot_name = PK11_GetSlotName(self->slot)) == NULL) {
        Py_RETURN_NONE;
    }

    return PyString_FromString(slot_name);
}

static PyObject *
PK11_get_token_name(PK11Slot *self, void *closure)
{
    char *token_name = NULL;

    TraceMethodEnter(self);

    if ((token_name = PK11_GetTokenName(self->slot)) == NULL) {
        Py_RETURN_NONE;
    }

    return PyString_FromString(token_name);
}

static
PyGetSetDef PK11Slot_getseters[] = {
    {"slot_name",  (getter)PK11_get_slot_name,  (setter)NULL, "slot name", NULL},
    {"token_name", (getter)PK11_get_token_name, (setter)NULL, "token name", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef PK11Slot_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

/* ========== Slot Info Functions ========== */

// FIXME: should these be properties rather than methods?

PyDoc_STRVAR(PK11Slot_is_hw_doc,
"is_hw() -> bool\n\
\n\
Returns True if the slot is implemented in hardware, False otherwise.\n\
");
static PyObject *
PK11Slot_is_hw(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_IsHW(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_is_present_doc,
"is_present() -> bool\n\
\n\
Returns True if the slot's token present, False otherwise.\n\
");
static PyObject *
PK11Slot_is_present(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_IsPresent(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_is_read_only_doc,
"is_read_only() -> bool\n\
\n\
Returns True if the the slot is read-only, False otherwise.\n\
");
static PyObject *
PK11Slot_is_read_only(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_IsReadOnly(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_is_internal_doc,
"is_internal() -> bool\n\
\n\
Returns True if the the slot is internal, False otherwise.\n\
");
static PyObject *
PK11Slot_is_internal(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_IsInternal(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_need_login_doc,
"need_login() -> bool\n\
\n\
Returns True if there are some cryptographic functions that a\n\
user must be logged in to perform, False otherwise.\n\
");
static PyObject *
PK11Slot_need_login(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_NeedLogin(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_need_user_init_doc,
"need_user_init() -> bool\n\
\n\
Returns True if the slot needs to be logged into by\n\
the user by providing their pin, False otherwise.\n\
");
static PyObject *
PK11Slot_need_user_init(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_NeedUserInit(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_is_friendly_doc,
"is_friendly() -> bool\n\
\n\
Returns True if the slot allows certificates to be read\n\
without logging in to the token, False otherwise.\n\
");
static PyObject *
PK11Slot_is_friendly(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_IsFriendly(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_is_removable_doc,
"is_removable() -> bool\n\
\n\
Returns True if the token is removable, False otherwise.\n\
");
static PyObject *
PK11Slot_is_removable(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_IsRemovable(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_has_protected_authentication_path_doc,
"has_protected_authentication_path() -> bool\n\
\n\
Returns True if token has a \"protected authentication path\", whereby\n\
a user can log into the token without passing a PIN through the\n\
library, False otherwise.  An example might be a token with an\n\
integrated key pad.\n\
");
static PyObject *
PK11Slot_has_protected_authentication_path(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_ProtectedAuthenticationPath(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_is_disabled_doc,
"is_disabled() -> bool\n\
\n\
Returns True if the slot is disabled, False otherwise.\n\
");
static PyObject *
PK11Slot_is_disabled(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_IsDisabled(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_has_root_certs_doc,
"has_root_certs() -> bool\n\
\n\
Returns True if the slot contains the root certificate , False otherwise.\n\
");
static PyObject *
PK11Slot_has_root_certs(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_HasRootCerts(self->slot))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(PK11Slot_get_disabled_reason_doc,
"get_disabled_reason() -> integer\n\
\n\
Returns a diabled reason enumerated constant (i.e. PK11_DIS_*).\n\
\n\
May be one of:\n\
\n\
    * PK11_DIS_NONE\n\
    * PK11_DIS_USER_SELECTED\n\
    * PK11_DIS_COULD_NOT_INIT_TOKEN\n\
    * PK11_DIS_TOKEN_VERIFY_FAILED\n\
    * PK11_DIS_TOKEN_NOT_PRESENT\n\
\n\
");
static PyObject *
PK11Slot_get_disabled_reason(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(PK11_GetDisabledReason(self->slot));
}

PyDoc_STRVAR(PK11Slot_user_disable_doc,
"user_disable() \n\
\n\
Prevents the slot from being used, and sets disable reason to\n\
PK11_DIS_USER_SELECTED.\n\
\n\
Mechanisms that were on continue to stay on. Therefore, when the slot\n\
is enabled again via `PK11Slot.user_enable()`, it will remember what\n\
mechanisms needs to be turned on.\n\
");

static PyObject *
PK11Slot_user_disable(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (!PK11_UserDisableSlot(self->slot)) {
        return set_nspr_error(_("unable to disable slot"));
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(PK11Slot_user_enable_doc,
"user_enable() \n\
\n\
Allow all mechanisms that are ON before `PK11Slot.user_disable()` was\n\
called to be available again. Sets disable reason to PK11_DIS_NONE.\n\
");

static PyObject *
PK11Slot_user_enable(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (!PK11_UserEnableSlot(self->slot)) {
        return set_nspr_error(_("unable to enable slot"));
    }

    Py_RETURN_NONE;
}

/* ========== Slot Password Management Functions ========== */

PyDoc_STRVAR(PK11Slot_is_logged_in_doc,
"is_logged_in([user_data1, ...]) -> bool\n\
\n\
:Parameters:\n\
    user_data1 : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Return True if token is logged in, False otherwise.\n\
");

static PyObject *
PK11Slot_is_logged_in(PK11Slot *self, PyObject *args)
{
    PyObject *pin_args = args;
    PRBool result;

    TraceMethodEnter(self);

    Py_INCREF(pin_args);
    result = PK11_IsLoggedIn(self->slot, pin_args);
    Py_DECREF(pin_args);

    if (result)
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

    return NULL;
}

PyDoc_STRVAR(PK11Slot_authenticate_doc,
"authenticate(load_certs=False, [user_data1, ...]) -> \n\
\n\
:Parameters:\n\
    load_certs : bool\n\
        If True load certificates after authenticating.\n\
\n\
Checks to see if token needs to be logged in.  If so it invokes the\n\
password callback (set via `nss.set_password_callback()`) passing the\n\
optional user_data parameters to the password callback.\n\
");

static PyObject *
PK11Slot_authenticate(PK11Slot *self, PyObject *args)
{
    PyObject *py_load_certs = NULL;
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    PRBool load_certs = PR_FALSE;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "|O!:authenticate",
                          &PyBool_Type, &py_load_certs)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    if (py_load_certs) {
        load_certs = PyBoolAsPRBool(py_load_certs);
    }
    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if (PK11_Authenticate(self->slot, load_certs, pin_args) != SECSuccess) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error("Unable to authenticate");
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    Py_RETURN_NONE;

}

PyDoc_STRVAR(PK11Slot_logout_doc,
"logout()l\n\
\n\
Logs a user out of a session destroying any objects\n\
allocated on their behalf.\n\
");
static PyObject *
PK11Slot_logout(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_Logout(self->slot) != SECSuccess) {
        return set_nspr_error("failed to logout of slot");
    }

    Py_RETURN_NONE;
}

/* ========== Slot Mapping Utility Functions ========== */

PyDoc_STRVAR(PK11Slot_get_best_wrap_mechanism_doc,
"get_best_wrap_mechanism() -> mechanism\n\
\n\
Find the best key wrap mechanism for this slot.\n\
");
static PyObject *
PK11Slot_get_best_wrap_mechanism(PK11Slot *self, PyObject *args)
{
    CK_MECHANISM_TYPE mechanism;

    TraceMethodEnter(self);

    mechanism = PK11_GetBestWrapMechanism(self->slot);
    return PyInt_FromLong(mechanism);
}


PyDoc_STRVAR(PK11Slot_get_best_key_length_doc,
"get_best_key_length(mechanism) -> length\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
\n\
Return the best key length for this slot and mechanism.\n\
A zero result means that token knows how long the key should be,\n\
the result is typically used with key_gen(), token_key_gen(), or\n\
token_key_gen_with_flags()\n\
");
static PyObject *
PK11Slot_get_best_key_length(PK11Slot *self, PyObject *args)
{
    unsigned long mechanism;
    int length;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:get_best_key_length", &mechanism))
        return NULL;

    length = PK11_GetBestKeyLength(self->slot, mechanism);
    return PyInt_FromLong(length);
}

PyDoc_STRVAR(PK11Slot_key_gen_doc,
"key_gen(mechanism, sec_param, key_size, [user_data1, ...]) -> PK11SymKey object\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    sec_param : SecItem object or None\n\
        SecItem key parameters. None is also valid.\n\
    key_size : int\n\
        key length (use get_best_key_length())\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Generate a symmetric key.\n\
");
static PyObject *
PK11Slot_key_gen(PK11Slot *self, PyObject *args)
{
    Py_ssize_t n_base_args = 3;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    unsigned long mechanism;
    int key_size;
    SecItem *py_sec_param;
    PK11SymKey *sym_key;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "kO&i:key_gen",
                          &mechanism, SecItemOrNoneConvert, &py_sec_param,
                          &key_size)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((sym_key = PK11_KeyGen(self->slot, mechanism, py_sec_param ? &py_sec_param->item : NULL,
                               key_size, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    return PyPK11SymKey_new_from_PK11SymKey(sym_key);
}

PyDoc_STRVAR(PK11Slot_generate_key_pair_doc,
"generate_key_pair(mechanism, key_params, token, sensitive, [user_data1, ...]) -> public_key, private_key\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    key_params : SecItem object or None\n\
        SecItem key parameters. None is also valid.\n\
    token : bool\n\
        If true the key is a token object otherwise it's a session object.\n\
    sensitive : bool\n\
        If a key is sensitive, certain attributes of the key cannot be\n\
        revealed in plaintext outside the token. It is also more\n\
        expensive to move between tokens.\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Generate a public and private key pair.\n\
\n\
Example::\n\
\n\
    # Generate a DSA key pair\n\
    key_params = nss.KEYPQGParams()\n\
    mechanism = nss.CKM_DSA_KEY_PAIR_GEN\n\
    slot = nss.get_best_slot(mechanism)\n\
    pub_key, priv_key = slot.generate_key_pair(mechanism, key_params, False, False)\n\
\n\
    # Generate a DSA key pair\n\
    key_params = nss.RSAGenParams()\n\
    mechanism = nss.CKM_RSA_PKCS_KEY_PAIR_GEN\n\
    slot = nss.get_best_slot(mechanism)\n\
    pub_key, priv_key = slot.generate_key_pair(mechanism, key_params, False, False)\n\
\n\
");
static PyObject *
PK11Slot_generate_key_pair(PK11Slot *self, PyObject *args)
{
    Py_ssize_t n_base_args = 4;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    unsigned long mechanism;
    int token;
    int sensitive;
    PyObject *py_key_params;
    void *key_params = NULL;
    SECKEYPublicKey *pub_key = NULL;
    SECKEYPrivateKey *priv_key = NULL;
    PyObject *result_tuple = NULL;
    PyObject *py_pub_key = NULL;
    PyObject *py_priv_key = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "kOii:generate_key_pair",
                          &mechanism, &py_key_params, &token, &sensitive)) {
        goto fail;
    }
    Py_CLEAR(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    switch(mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
    case CKM_RSA_X9_31_KEY_PAIR_GEN:
        if (!PyRSAGenParams_Check(py_key_params)) {
            PyObject *mechanism_name = key_mechanism_type_to_pystr(mechanism);

            PyErr_Format(PyExc_TypeError, "key_params for %s mechanism must be %.50s, not %.50s",
                         mechanism_name ? PyString_AsString(mechanism_name) : "unknown",
                         RSAGenParamsType.tp_name, Py_TYPE(py_key_params)->tp_name);
            Py_XDECREF(mechanism_name);
            goto fail;
        }
        key_params = &((RSAGenParams *)py_key_params)->params;
        break;
    case CKM_DSA_KEY_PAIR_GEN:
        if (!PyKEYPQGParams_Check(py_key_params)) {
            PyObject *mechanism_name = key_mechanism_type_to_pystr(mechanism);

            PyErr_Format(PyExc_TypeError, "key_params for %s mechanism must be %.50s, not %.50s",
                         mechanism_name ? PyString_AsString(mechanism_name) : "unknown",
                         KEYPQGParamsType.tp_name, Py_TYPE(py_key_params)->tp_name);
            Py_XDECREF(mechanism_name);
            goto fail;
        }
        key_params = &((KEYPQGParams *)py_key_params)->params;
        break;
    default:
        break;
    }

    Py_BEGIN_ALLOW_THREADS
    if ((priv_key = PK11_GenerateKeyPair(self->slot, mechanism, key_params,
                                         &pub_key,
                                         token     ? PR_TRUE : PR_FALSE,
                                         sensitive ? PR_TRUE : PR_FALSE,
                                         pin_args)) == NULL) {
	Py_BLOCK_THREADS
        set_nspr_error(NULL);
        goto fail;
    }
    Py_END_ALLOW_THREADS

    Py_CLEAR(pin_args);

    if ((py_pub_key = PublicKey_new_from_SECKEYPublicKey(pub_key)) == NULL) {
        goto fail;
    }

    if ((py_priv_key = PrivateKey_new_from_SECKEYPrivateKey(priv_key)) == NULL) {
        goto fail;
    }

    if ((result_tuple = PyTuple_New(2)) == NULL) {
        goto fail;
    }

    PyTuple_SetItem(result_tuple, 0, py_pub_key);
    PyTuple_SetItem(result_tuple, 1, py_priv_key);

    return result_tuple;

 fail:
    Py_XDECREF(parse_args);
    Py_XDECREF(pin_args);
    Py_XDECREF(result_tuple);
    return NULL;
}

PyDoc_STRVAR(PK11Slot_list_certs_doc,
"list_certs() -> (`Certificate`, ...)\n\
\n\
Returns a tuple of `Certificate` objects found in the slot.\n\
");

static PyObject *
PK11Slot_list_certs(PK11Slot *self, PyObject *args)
{
    CERTCertList *cert_list = NULL;
    PyObject *tuple = NULL;

    TraceMethodEnter(self);

    if ((cert_list = PK11_ListCertsInSlot(self->slot)) == NULL) {
        return set_nspr_error(NULL);
    }

    tuple = CERTCertList_to_tuple(cert_list, true);
    CERT_DestroyCertList(cert_list);
    return tuple;
}

PyDoc_STRVAR(PK11Slot_pbe_key_gen_doc,
"pbe_key_gen(algid, password, [user_data1, ...]) -> PK11SymKey object\n\
\n\
:Parameters:\n\
    algid : AlgorithmID object\n\
        algorithm id\n\
    password : string\n\
        the password used to create the PBE Key\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Generate a PBE symmetric key.\n\
");
static PyObject *
PK11Slot_pbe_key_gen(PK11Slot *self, PyObject *args)
{
    Py_ssize_t n_base_args = 2;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    AlgorithmID *py_algid = NULL;
    char *password = NULL;
    Py_ssize_t password_len = 0;
    SECItem pwitem;
    PK11SymKey *sym_key;
    PyObject *py_pwitem = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "O!s#:pbe_key_gen",
                          &AlgorithmIDType, &py_algid,
                          &password, &password_len)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    pwitem.data = (unsigned char *)password;
    pwitem.len = password_len;

    Py_BEGIN_ALLOW_THREADS
    if ((sym_key = PK11_PBEKeyGen(self->slot, &py_algid->id,
                                  &pwitem, PR_FALSE, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    /*
     * Store the password in the symkey userData so it can be referenced
     * by PK11_GetPBECryptoMechanism
     */
    if ((py_pwitem = SecItem_new_from_SECItem(&pwitem, SECITEM_utf8_string)) == NULL) {
        PK11_FreeSymKey(sym_key);
        return NULL;
    }

    PK11_SetSymKeyUserData(sym_key, py_pwitem,
                           (PK11FreeDataFunc)SecItem_decref);

    return PyPK11SymKey_new_from_PK11SymKey(sym_key);
}

static PyObject *
PK11Slot_format_lines(PK11Slot *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj1 = NULL;
    PyObject *obj2 = NULL;
    PyObject *obj3 = NULL;
    PyObject *obj4 = NULL;
    PyObject *obj5 = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist,
                                     &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    obj1 = PK11_get_slot_name(self, NULL);
    FMT_OBJ_AND_APPEND(lines, _("Slot Name"), obj1, level, fail);
    Py_CLEAR(obj1);

    obj1 = PK11_get_token_name(self, NULL);
    FMT_OBJ_AND_APPEND(lines, _("Token Name"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "is_hw", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Is Hardware"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "is_present", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Is Present"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "is_read_only", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Is Read Only"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "is_internal", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Is Internal"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "need_login", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Needs Login"), obj1, level, fail);
    Py_CLEAR(obj1);


    if ((obj1 = PyObject_CallMethod((PyObject *)self, "need_user_init", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Needs User Init"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "is_friendly", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Is Friendly"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "is_removable", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Is Removable"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "has_protected_authentication_path", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Has Protected Authentication Path"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "is_disabled", NULL)) == NULL) {
        goto fail;
    }
    if ((obj2 = PyObject_CallMethod((PyObject *)self, "get_disabled_reason", NULL)) == NULL) {
        goto fail;
    }
    if ((obj3 = Py_BuildValue("(O)", obj2)) == NULL) {
        goto fail;
    }

    if ((obj4 = pk11_pk11_disabled_reason_str(NULL, obj3)) == NULL) {
        goto fail;
    }

    if ((obj5 = obj_sprintf("%s (%s)", obj1, obj4)) == NULL) {
        goto fail;
    }

    FMT_OBJ_AND_APPEND(lines, _("Is Disabled"), obj5, level, fail);
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);
    Py_CLEAR(obj3);
    Py_CLEAR(obj4);
    Py_CLEAR(obj5);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "has_root_certs", NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Has Root Certs"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PyObject_CallMethod((PyObject *)self, "get_best_wrap_mechanism", NULL)) == NULL) {
        goto fail;
    }
    obj2 = key_mechanism_type_to_pystr(PyInt_AsLong(obj1));
    if ((obj3 = obj_sprintf("%s (%#x)", obj2, obj1)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Best Wrap Mechanism"), obj3, level, fail);
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);
    Py_CLEAR(obj3);

    return lines;

 fail:
    Py_XDECREF(obj1);
    Py_XDECREF(obj2);
    Py_XDECREF(obj3);
    Py_XDECREF(obj4);
    Py_XDECREF(obj5);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
PK11Slot_format(PK11Slot *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)PK11Slot_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
PK11Slot_str(PK11Slot *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  PK11Slot_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef PK11Slot_methods[] = {
    {"format_lines",                      (PyCFunction)PK11Slot_format_lines,                      METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",                            (PyCFunction)PK11Slot_format,                            METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {"is_hw",                             (PyCFunction)PK11Slot_is_hw,                             METH_NOARGS,                PK11Slot_is_hw_doc},
    {"is_present",                        (PyCFunction)PK11Slot_is_present,                        METH_NOARGS,                PK11Slot_is_present_doc},
    {"is_read_only",                      (PyCFunction)PK11Slot_is_read_only,                      METH_NOARGS,                PK11Slot_is_read_only_doc},
    {"is_internal",                       (PyCFunction)PK11Slot_is_internal,                       METH_NOARGS,                PK11Slot_is_internal_doc},
    {"need_login",                        (PyCFunction)PK11Slot_need_login,                        METH_NOARGS,                PK11Slot_need_login_doc},
    {"need_user_init",                    (PyCFunction)PK11Slot_need_user_init,                    METH_NOARGS,                PK11Slot_need_user_init_doc},
    {"is_friendly",                       (PyCFunction)PK11Slot_is_friendly,                       METH_NOARGS,                PK11Slot_is_friendly_doc},
    {"is_removable",                      (PyCFunction)PK11Slot_is_removable,                      METH_NOARGS,                PK11Slot_is_removable_doc},
    {"is_logged_in",                      (PyCFunction)PK11Slot_is_logged_in,                      METH_NOARGS,                PK11Slot_is_logged_in_doc},
    {"has_protected_authentication_path", (PyCFunction)PK11Slot_has_protected_authentication_path, METH_NOARGS,                PK11Slot_has_protected_authentication_path_doc},
    {"is_disabled",                       (PyCFunction)PK11Slot_is_disabled,                       METH_NOARGS,                PK11Slot_is_disabled_doc},
    {"has_root_certs",                    (PyCFunction)PK11Slot_has_root_certs,                    METH_NOARGS,                PK11Slot_has_root_certs_doc},
    {"get_disabled_reason",               (PyCFunction)PK11Slot_get_disabled_reason,               METH_NOARGS,                PK11Slot_get_disabled_reason_doc},
    {"user_disable",                      (PyCFunction)PK11Slot_user_disable,                      METH_NOARGS,                PK11Slot_user_disable_doc},
    {"user_enable",                       (PyCFunction)PK11Slot_user_enable,                       METH_NOARGS,                PK11Slot_user_enable_doc},
    {"authenticate",                      (PyCFunction)PK11Slot_authenticate,                      METH_VARARGS,               PK11Slot_authenticate_doc},
    {"logout",                            (PyCFunction)PK11Slot_logout,                            METH_NOARGS,                PK11Slot_logout_doc},
    {"get_best_wrap_mechanism",           (PyCFunction)PK11Slot_get_best_wrap_mechanism,           METH_NOARGS,                PK11Slot_get_best_wrap_mechanism_doc},
    {"get_best_key_length",               (PyCFunction)PK11Slot_get_best_key_length,               METH_VARARGS,               PK11Slot_get_best_key_length_doc},
    {"key_gen",                           (PyCFunction)PK11Slot_key_gen,                           METH_VARARGS,               PK11Slot_key_gen_doc},
    {"generate_key_pair",                 (PyCFunction)PK11Slot_generate_key_pair,                 METH_VARARGS,               PK11Slot_generate_key_pair_doc},
    {"list_certs",                        (PyCFunction)PK11Slot_list_certs,                        METH_NOARGS,                PK11Slot_list_certs_doc},
    {"pbe_key_gen",                       (PyCFunction)PK11Slot_pbe_key_gen,                       METH_VARARGS,               PK11Slot_pbe_key_gen_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
PK11Slot_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PK11Slot *self;

    TraceObjNewEnter(type);

    if ((self = (PK11Slot *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }
    self->slot = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
PK11Slot_dealloc(PK11Slot* self)
{
    TraceMethodEnter(self);

    /* NSS_Shutdown might have been called before Python deallocates this object */
    if (NSS_IsInitialized()) {
        PK11_FreeSlot(self->slot);
    }
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(PK11Slot_doc,
"An object representing a PKCS #11 Slot");

static int
PK11Slot_init(PK11Slot *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {NULL};

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist))
        return -1;

    return 0;
}

static PyTypeObject PK11SlotType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.PK11Slot",				/* tp_name */
    sizeof(PK11Slot),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)PK11Slot_dealloc,		/* tp_dealloc */
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
    (reprfunc)PK11Slot_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    PK11Slot_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    PK11Slot_methods,				/* tp_methods */
    PK11Slot_members,				/* tp_members */
    PK11Slot_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)PK11Slot_init,			/* tp_init */
    0,						/* tp_alloc */
    PK11Slot_new,				/* tp_new */
};

PyObject *
PK11Slot_new_from_PK11SlotInfo(PK11SlotInfo *slot)
{
    PK11Slot *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (PK11Slot *) PK11SlotType.tp_new(&PK11SlotType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->slot = slot;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* =========================== PK11SymKey Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
PK11SymKey_get_mechanism(PyPK11SymKey *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(PK11_GetMechanism(self->pk11_sym_key));
}

static PyObject *
PK11SymKey_get_key_data(PyPK11SymKey *self, void *closure)
{
    SECItem *sec_item;

    TraceMethodEnter(self);

    if (PK11_ExtractKeyValue(self->pk11_sym_key) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    if ((sec_item = PK11_GetKeyData(self->pk11_sym_key)) == NULL) {
        return PyString_FromStringAndSize("", 0);
    }

    return PyString_FromStringAndSize((const char *)sec_item->data, sec_item->len);
}

static PyObject *
PK11SymKey_get_key_length(PyPK11SymKey *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(PK11_GetKeyLength(self->pk11_sym_key));
}

static PyObject *
PK11SymKey_get_slot(PyPK11SymKey *self, void *closure)
{
    PK11SlotInfo *slot = NULL;
    PyObject *py_slot = NULL;

    TraceMethodEnter(self);

    slot = PK11_GetSlotFromKey(self->pk11_sym_key);
    if ((py_slot = PK11Slot_new_from_PK11SlotInfo(slot)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create PK11Slot object");
        return NULL;
    }
    return py_slot;
}

static
PyGetSetDef PK11SymKey_getseters[] = {
    {"mechanism",  (getter)PK11SymKey_get_mechanism,  (setter)NULL, "CK_MECHANISM_TYPE mechanism", NULL},
    {"key_data",   (getter)PK11SymKey_get_key_data,   (setter)NULL, "key data", NULL},
    {"key_length", (getter)PK11SymKey_get_key_length, (setter)NULL, "key length", NULL},
    {"slot",       (getter)PK11SymKey_get_slot,       (setter)NULL, "slot", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef PK11SymKey_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
PK11SymKey_format_lines(PyPK11SymKey *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj1 = NULL;
    PyObject *obj2 = NULL;
    PyObject *obj3 = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist,
                                     &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    obj1 = PK11SymKey_get_mechanism(self, NULL);
    obj2 = key_mechanism_type_to_pystr(PyInt_AsLong(obj1));
    if ((obj3 = obj_sprintf("%s (%#x)", obj2, obj1)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Mechanism"), obj3, level, fail);
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);
    Py_CLEAR(obj3);

    obj1 = PK11SymKey_get_key_length(self, NULL);
    FMT_OBJ_AND_APPEND(lines, _("Key Length"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj1 = PK11SymKey_get_key_data(self, NULL)) != NULL) {
        FMT_LABEL_AND_APPEND(lines, _("Key Data"), level, fail);
        APPEND_OBJ_TO_HEX_LINES_AND_CLEAR(lines, obj1, level+1, fail);
    } else {
        PyObject *error_type, *error_value, *error_traceback;

        PyErr_Fetch(&error_type, &error_value, &error_traceback);

        obj1 = PyObject_Str(error_value);
        FMT_OBJ_AND_APPEND(lines, _("Key Data"), obj1, level, fail);
        Py_CLEAR(obj1);

        Py_XDECREF(error_type);
        Py_XDECREF(error_value);
        Py_XDECREF(error_traceback);
    }

    obj1 = PK11SymKey_get_slot(self, NULL);
    FMT_LABEL_AND_APPEND(lines, _("PK11 Slot"), level, fail);
    CALL_FORMAT_LINES_AND_APPEND(lines, obj1, level+1, fail);
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
PK11SymKey_format(PyPK11SymKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)PK11SymKey_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
PK11SymKey_str(PyPK11SymKey *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  PK11SymKey_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

PyDoc_STRVAR(PK11SymKey_derive_doc,
"derive(mechanism, sec_param, target, operation, key_size) -> PK11SymKey\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    sec_param : SecItem object or None\n\
        mechanism parameters or None.\n\
    target : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    operation : int\n\
        type of operation. A (CKA_*) constant\n\
        (e.g. CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_DIGEST)\n\
    key_size : int\n\
        key size.\n\
\n\
Derive a new key from this key.\n\
Return a key which can do exactly one operation, it is\n\
ephemeral (session key).\n\
");
static PyObject *
PK11SymKey_derive(PyPK11SymKey *self, PyObject *args)
{
    unsigned long mechanism;
    SecItem *py_sec_param;
    unsigned long target;
    unsigned long operation;
    int key_size;
    PK11SymKey *derived_key = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "kO&kki:derive",
                          &mechanism, SecItemOrNoneConvert, &py_sec_param,
                          &target, &operation, &key_size))
        return NULL;

    if ((derived_key = PK11_Derive(self->pk11_sym_key, mechanism,
                                   py_sec_param ? &py_sec_param->item : NULL,
                                   target, operation, key_size)) == NULL) {
        return set_nspr_error(NULL);
    }

    return PyPK11SymKey_new_from_PK11SymKey(derived_key);
}

PyDoc_STRVAR(PK11SymKey_wrap_sym_key_doc,
"wrap_sym_key(mechanism, sec_param, sym_key) -> SecItem\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    sec_param : SecItem object or None\n\
        mechanism parameters or None.\n\
    sym_key : PK11SymKey object\n\
        the symmetric key to wrap\n\
\n\
Wrap (encrypt) the supplied sym_key using the mechanism\n\
and parameter. Return the wrapped key as a SecItem.\n\
");
static PyObject *
PK11SymKey_wrap_sym_key(PyPK11SymKey *self, PyObject *args)
{
    unsigned long mechanism;
    SecItem *py_sec_param;
    PyPK11SymKey *py_sym_key = NULL;
    SECItem wrapped_key;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "kO&O!:wrap_sym_key",
                          &mechanism, SecItemOrNoneConvert, &py_sec_param,
                          &PK11SymKeyType, &py_sym_key))
        return NULL;

    if (PK11_WrapSymKey(mechanism, py_sec_param ? &py_sec_param->item : NULL,
                        self->pk11_sym_key, py_sym_key->pk11_sym_key,
                        &wrapped_key) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    return SecItem_new_from_SECItem(&wrapped_key, SECITEM_wrapped_key);
}

PyDoc_STRVAR(PK11SymKey_unwrap_sym_key_doc,
"unwrap_sym_key(mechanism, sec_param, wrapped_key, target, operation, key_size) -> PK11SymKey\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    sec_param : SecItem object or None\n\
        mechanism parameters or None.\n\
    wrapped_key : SecItem object\n\
        the symmetric key to unwrap\n\
    target : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    operation : int\n\
        type of operation. A (CKA_*) constant\n\
        (e.g. CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_DIGEST)\n\
    key_size : int\n\
        key size.\n\
\n\
Unwrap (decrypt) the supplied wrapped key.\n\
Return the unwrapped key as a PK11SymKey.\n\
");
static PyObject *
PK11SymKey_unwrap_sym_key(PyPK11SymKey *self, PyObject *args)
{
    unsigned long mechanism;
    SecItem *py_sec_param;
    unsigned long target;
    unsigned long operation;
    int key_size;
    SecItem *py_wrapped_key = NULL;
    PK11SymKey *sym_key = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "kO&O!kki:unwrap_sym_key",
                          &mechanism, SecItemOrNoneConvert, &py_sec_param,
                          &SecItemType, &py_wrapped_key,
                          &target, &operation, &key_size))
        return NULL;

    if ((sym_key = PK11_UnwrapSymKey(self->pk11_sym_key, mechanism,
                                     py_sec_param ? &py_sec_param->item : NULL,
                                     &py_wrapped_key->item,
                                     target, operation, key_size)) == NULL) {
        return set_nspr_error(NULL);
    }

    return PyPK11SymKey_new_from_PK11SymKey(sym_key);
}


static PyObject *
PK11SymKey_repr(PyPK11SymKey *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyMethodDef PK11SymKey_methods[] = {
    {"format_lines",   (PyCFunction)PK11SymKey_format_lines,     METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",         (PyCFunction)PK11SymKey_format,           METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {"derive",         (PyCFunction)PK11SymKey_derive,           METH_VARARGS, PK11SymKey_derive_doc},
    {"wrap_sym_key",   (PyCFunction)PK11SymKey_wrap_sym_key,     METH_VARARGS, PK11SymKey_wrap_sym_key_doc},
    {"unwrap_sym_key", (PyCFunction)PK11SymKey_unwrap_sym_key,   METH_VARARGS, PK11SymKey_unwrap_sym_key_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static void
PK11SymKey_dealloc(PyPK11SymKey* self)
{
    TraceMethodEnter(self);

    if (self->pk11_sym_key) {
        PK11_FreeSymKey(self->pk11_sym_key);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(PK11SymKey_doc,
"Holds a hash, encryption or signing context for multi-part operations.\n\
");
static int
PK11SymKey_init(PyPK11SymKey *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return 0;
}

static PyTypeObject PK11SymKeyType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.PK11SymKey",			/* tp_name */
    sizeof(PyPK11SymKey),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)PK11SymKey_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)PK11SymKey_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)PK11SymKey_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    PK11SymKey_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    PK11SymKey_methods,				/* tp_methods */
    PK11SymKey_members,				/* tp_members */
    PK11SymKey_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)PK11SymKey_init,			/* tp_init */
    0,						/* tp_alloc */
    0,/* NULL cannot be directly created */	/* tp_new */
};

static PyObject *
PyPK11SymKey_new_from_PK11SymKey(PK11SymKey *pk11_sym_key)
{
    PyPK11SymKey *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = PyObject_NEW(PyPK11SymKey, &PK11SymKeyType)) == NULL) {
        return NULL;
    }

    self->pk11_sym_key = pk11_sym_key;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ============================ PK11Context Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static
PyGetSetDef PK11Context_getseters[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef PK11Context_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(PK11Context_digest_key_doc,
"digest_key(sym_key)\n\
\n\
:Parameters:\n\
    sym_key : PK11SymKey object\n\
        symmetric key\n\
\n\
Continues a multiple-part message-digesting operation by digesting the\n\
value of a secret key.\n\
");
static PyObject *
PK11Context_digest_key(PyPK11Context *self, PyObject *args)
{
    PyPK11SymKey *py_sym_key;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O!:digest_key", &PK11SymKeyType, &py_sym_key))
        return NULL;

    if (PK11_DigestKey(self->pk11_context, py_sym_key->pk11_sym_key) != SECSuccess) {
        return set_nspr_error(NULL);
    }
    Py_RETURN_NONE;
}

PyDoc_STRVAR(PK11Context_clone_context_doc,
"clone_context(context) -> PK11Context\n\
\n\
:Parameters:\n\
    context : PK11Context object\n\
        The PK11Context to be cloned\n\
\n\
Create a new PK11Context which is clone of the supplied context.\n\
");
static PyObject *
PK11Context_clone_context(PyPK11Context *self, PyObject *args)
{
    PK11Context *pk11_context;
    PyObject *py_pk11_context;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O!:clone_context", &PK11ContextType, &py_pk11_context))
        return NULL;

    if ((pk11_context = PK11_CloneContext(self->pk11_context)) == NULL) {
        return set_nspr_error(NULL);
    }

    if ((py_pk11_context =
         PyPK11Context_new_from_PK11Context(pk11_context)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create PK11Context object");
        return NULL;
    }

    return py_pk11_context;
}

PyDoc_STRVAR(PK11Context_digest_begin_doc,
"digest_begin()\n\
\n\
Start a new digesting or Mac'ing operation on this context.\n\
");
static PyObject *
PK11Context_digest_begin(PyPK11Context *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_DigestBegin(self->pk11_context) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(PK11Context_digest_op_doc,
"digest_op(data)\n\
:Parameters:\n\
    data : any read buffer compatible object (e.g. buffer or string)\n\
        raw data to compute digest from\n\
\n\
Execute a digest/signature operation.\n\
");
static PyObject *
PK11Context_digest_op(PyPK11Context *self, PyObject *args)
{
    const void *buffer = NULL;
    Py_ssize_t buffer_len;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "t#:digest_op", &buffer, &buffer_len))
        return NULL;

    if (PK11_DigestOp(self->pk11_context, buffer, buffer_len) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(PK11Context_cipher_op_doc,
"cipher_op(data) -> data\n\
:Parameters:\n\
    data : any read buffer compatible object (e.g. buffer or string)\n\
        raw data to compute digest from\n\
\n\
Execute a digest/signature operation.\n\
");
static PyObject *
PK11Context_cipher_op(PyPK11Context *self, PyObject *args)
{
    const void *in_buf = NULL;
    void *out_buf = NULL;
    PyObject *py_out_string;
    Py_ssize_t in_buf_len;
    Py_ssize_t out_buf_alloc_len;
    int suggested_out_len = 0, actual_out_len;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "t#:cipher_op", &in_buf, &in_buf_len))
        return NULL;

    /*
     * Create an output buffer to hold the result.
     */

    /*
     * We call the PK11 function with a NULL output buffer and it returns an
     * upper bound on the size of the output data buffer. We create a string to
     * hold the data using the upper bound as it's size. We then invoke the PK11
     * function again which performs the operation writing into string buffer.
     * It returns the exact number of bytes written. If the allocated size does
     * not equal the actual number of bytes written we resize the string before
     * returning it so the caller sees a string whose length exactly matches
     * the number of bytes written by the PK11 function.
     */
    if (PK11_CipherOp(self->pk11_context, NULL, &suggested_out_len, 0,
                      (unsigned char *)in_buf, in_buf_len) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    out_buf_alloc_len = suggested_out_len;

    if ((py_out_string = PyString_FromStringAndSize(NULL, out_buf_alloc_len)) == NULL) {
        return NULL;
    }
    out_buf = PyString_AsString(py_out_string);

    /*
     * Now that we have both the input and output buffers perform the cipher operation.
     */
    if (PK11_CipherOp(self->pk11_context, out_buf, &actual_out_len, out_buf_alloc_len,
                      (unsigned char *)in_buf, in_buf_len) != SECSuccess) {
        Py_DECREF(py_out_string);
        return set_nspr_error(NULL);
    }

    if (actual_out_len != out_buf_alloc_len) {
        if (_PyString_Resize(&py_out_string, actual_out_len) < 0) {
        return NULL;
        }
    }

    return py_out_string;
}

PyDoc_STRVAR(PK11Context_finalize_doc,
"finalize()\n\
\n\
Clean up cipher operation so that any pending multi-part\n\
operations have been flushed. Any pending output which would\n\
have been available as a result of the flush is discarded.\n\
The context is left in a state available for reuse.\n\
\n\
WARNING: Currently context reuse only works for digest contexts\n\
not encryption/decryption contexts\n\
");
static PyObject *
PK11Context_finalize(PyPK11Context *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (PK11_Finalize(self->pk11_context) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(PK11Context_digest_final_doc,
"digest_final() -> data\n\
\n\
Completes the multi-part cryptographic operation in progress\n\
on this context and returns any final data which may have been\n\
pending in the context (i.e. the output data is flushed from the\n\
context). If there was no final data the returned\n\
data buffer will have a length of zero.\n\
");
static PyObject *
PK11Context_digest_final(PyPK11Context *self, PyObject *args)
{
    void *out_buf = NULL;
    Py_ssize_t out_buf_alloc_len;
    unsigned int suggested_out_len = 0, actual_out_len;
    PyObject *py_out_string;
    SECStatus result;

    TraceMethodEnter(self);

    /*
     * We call the PK11 function with a NULL output buffer and it returns an
     * upper bound on the size of the output data buffer. We create a string to
     * hold the data using the upper bound as it's size. We then invoke the PK11
     * function again which performs the operation writing into string buffer.
     * It returns the exact number of bytes written. If the allocated size does
     * not equal the actual number of bytes written we resize the string before
     * returning it so the caller sees a string whose length exactly matches
     * the number of bytes written by the PK11 function.
     *
     * NSS WART
     *
     * We must be careful to detect the case when the 1st call to
     * DigestFinal returns a zero output length and not call it
     * again. This is because when there is nothing further to do
     * DigestFinal will close the context and release its resources
     * even if all you're doing is performing a buffer size check. I
     * believe this is a violation of the PKCS11 C API spec which says
     * that a call to check buffer size has no side effect. I could
     * find no NSS documentation as to the defined behavior in NSS.
     * This has been filed as Bug 1095725.
     */

    if (PK11_DigestFinal(self->pk11_context, NULL, &suggested_out_len, 0) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    out_buf_alloc_len = suggested_out_len;

    if ((py_out_string = PyString_FromStringAndSize(NULL, out_buf_alloc_len)) == NULL) {
        return NULL;
    }
    out_buf = PyString_AsString(py_out_string);

    result = PK11_DigestFinal(self->pk11_context, out_buf,
                              &actual_out_len, out_buf_alloc_len);

    if (result != SECSuccess) {
        /*
         * Did we hit the above bug? If so ignore it, otherwise report failure.
         */
        if (!(suggested_out_len == 0 &&
              PORT_GetError() == SEC_ERROR_LIBRARY_FAILURE)) {
            Py_DECREF(py_out_string);
            return set_nspr_error(NULL);
        }
    }

    if (actual_out_len != out_buf_alloc_len) {
        if (_PyString_Resize(&py_out_string, actual_out_len) < 0) {
            return NULL;
        }
    }

    return py_out_string;
}

static PyObject *
PK11Context_repr(PyPK11Context *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyObject *
PK11Context_str(PyPK11Context *self)
{
    return PK11Context_repr(self);
}

static PyMethodDef PK11Context_methods[] = {
    {"digest_key",    (PyCFunction)PK11Context_digest_key,    METH_VARARGS, PK11Context_digest_key_doc},
    {"clone_context", (PyCFunction)PK11Context_clone_context, METH_VARARGS, PK11Context_clone_context_doc},
    {"digest_begin",  (PyCFunction)PK11Context_digest_begin,  METH_NOARGS,  PK11Context_digest_begin_doc},
    {"digest_op",     (PyCFunction)PK11Context_digest_op,     METH_VARARGS, PK11Context_digest_op_doc},
    {"cipher_op",     (PyCFunction)PK11Context_cipher_op,     METH_VARARGS, PK11Context_cipher_op_doc},
    {"finalize",      (PyCFunction)PK11Context_finalize,      METH_NOARGS,  PK11Context_finalize_doc},
    {"digest_final",  (PyCFunction)PK11Context_digest_final,  METH_NOARGS,  PK11Context_digest_final_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
PK11Context_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyPK11Context *self;

    TraceObjNewEnter(type);

    if ((self = (PyPK11Context *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->pk11_context = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
PK11Context_dealloc(PyPK11Context* self)
{
    TraceMethodEnter(self);

    if (self->pk11_context) {
        PK11_DestroyContext(self->pk11_context, PR_TRUE);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(PK11Context_doc,
"\n\
");
static int
PK11Context_init(PyPK11Context *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return 0;
}

static PyTypeObject PK11ContextType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.PK11Context",			/* tp_name */
    sizeof(PyPK11Context),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)PK11Context_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)PK11Context_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)PK11Context_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    PK11Context_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    PK11Context_methods,			/* tp_methods */
    PK11Context_members,			/* tp_members */
    PK11Context_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)PK11Context_init,			/* tp_init */
    0,						/* tp_alloc */
    PK11Context_new,				/* tp_new */
};

static PyObject *
PyPK11Context_new_from_PK11Context(PK11Context *pk11_context)

{
    PyPK11Context *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (PyPK11Context *) PK11ContextType.tp_new(&PK11ContextType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->pk11_context = pk11_context;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ======================== CRLDistributionPt Class ========================= */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
CRLDistributionPt_get_crl_issuer(CRLDistributionPt *self, void *closure)
{
    TraceMethodEnter(self);

    if (!self->pt || !self->pt->crlIssuer) {
        Py_RETURN_NONE;
    }
    return GeneralName_new_from_CERTGeneralName(self->pt->crlIssuer);
}

static
PyGetSetDef CRLDistributionPt_getseters[] = {
    {"issuer", (getter)CRLDistributionPt_get_crl_issuer, (setter)NULL,
     "returns the CRL Issuer as a `GeneralName` object if defined, returns None if not defined", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef CRLDistributionPt_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(CRLDistributionPt_get_general_names_doc,
"get_general_names(repr_kind=AsString) -> (general_name, ...)\n\
\n\
:Parameters:\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsObject\n\
            The general name as a nss.GeneralName object\n\
        AsString\n\
            The general name as a string.\n\
            (e.g. \"http://crl.geotrust.com/crls/secureca.crl\")\n\
        AsTypeString\n\
            The general name type as a string.\n\
             (e.g. \"URI\")\n\
        AsTypeEnum\n\
            The general name type as a general name type enumerated constant.\n\
             (e.g. nss.certURI )\n\
        AsLabeledString\n\
            The general name as a string with it's type prepended.\n\
            (e.g. \"URI: http://crl.geotrust.com/crls/secureca.crl\"\n\
\n\
Returns a tuple of general names in the CRL Distribution Point. If the\n\
distribution point type is not nss.generalName or the list was empty then\n\
the returned tuple will be empty.\n\
\n\
You may specify how the each member of the tuple is represented, by default\n\
it will be as a string.\n\
");

static PyObject *
CRLDistributionPt_get_general_names(CRLDistributionPt *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"repr_kind", NULL};
    int repr_kind = AsString;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:get_general_names", kwlist,
                                     &repr_kind))
        return NULL;

    return CRLDistributionPt_general_names_tuple(self, repr_kind);
}

PyDoc_STRVAR(CRLDistributionPt_get_reasons_doc,
"get_reasons(repr_kind=AsEnumDescription) -> (reason, ...)\n\
\n\
:Parameters:\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant.\n\
            (e.g. nss.crlEntryReasonCaCompromise)\n\
        AsEnumDescription\n\
            A friendly human readable description of the enumerated constant as a string.\n\
             (e.g. \"CA Compromise\")\n\
        AsIndex\n\
            The bit position within the bit string.\n\
\n\
Returns a tuple of reasons in the CRL Distribution Point. If no\n\
reasons were defined the returned tuple will be empty.\n\
\n\
You may specify how the each member of the tuple is represented, by default\n\
it will be as a string.\n\
");

static PyObject *
CRLDistributionPt_get_reasons(CRLDistributionPt *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"repr_kind", NULL};
    int repr_kind = AsEnumDescription;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:get_reasons", kwlist,
                                     &repr_kind))
        return NULL;

    return crl_reason_bitstr_to_tuple(&self->pt->bitsmap, repr_kind);
}

PyObject *
CRLDistributionPt_format_lines(CRLDistributionPt *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    Py_ssize_t len;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *obj1 = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if (!self->pt) {
        return lines;
    }

    if (self->pt->distPointType == generalName) {
        if ((obj = CRLDistributionPt_general_names_tuple(self, AsString)) == NULL) {
            goto fail;
        }
        len = PyTuple_GET_SIZE(obj);

        if ((obj1 = PyString_FromFormat("General Names: [%zd total]", len)) == NULL) {
            goto fail;
        }
        FMT_OBJ_AND_APPEND(lines, NULL, obj1, level, fail);
        Py_CLEAR(obj1);

        APPEND_LINES_AND_CLEAR(lines, obj, level+1, fail);

    } else if (self->pt->distPointType == relativeDistinguishedName) {

        if ((obj = RDN_new_from_CERTRDN(&self->pt->distPoint.relativeName)) == NULL) {
            goto fail;
        }

        FMT_OBJ_AND_APPEND(lines, _("Relative Distinguished Name"), obj, level, fail);
        Py_CLEAR(obj);
    } else {
        PyErr_Format(PyExc_ValueError, "unknown distribution point type (%d), "
                     "expected generalName or relativeDistinguishedName",
                     self->pt->distPointType);
        goto fail;
    }

    if ((obj = CRLDistributionPt_get_crl_issuer(self, NULL)) == NULL) {
        goto fail;
    }

    FMT_OBJ_AND_APPEND(lines, _("Issuer"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = crl_reason_bitstr_to_tuple(&self->pt->bitsmap, AsEnumDescription)) == NULL) {
        goto fail;
    }

    FMT_OBJ_AND_APPEND(lines, _("Reasons"), obj, level, fail);
    Py_CLEAR(obj);

    return lines;

 fail:
    Py_XDECREF(lines);
    Py_XDECREF(obj);
    Py_XDECREF(obj1);
    return NULL;
}

static PyObject *
CRLDistributionPt_format(CRLDistributionPt *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)CRLDistributionPt_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
CRLDistributionPt_str(CRLDistributionPt *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  CRLDistributionPt_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyObject *
CRLDistributionPt_repr(CRLDistributionPt *self)
{
    PyObject *result = NULL;
    PyObject *rdn = NULL;
    PyObject *names = NULL;
    PyObject *name_str = NULL;
    PyObject *name_desc = NULL;
    PyObject *crl_issuer = NULL;
    PyObject *crl_issuer_str = NULL;
    PyObject *reasons = NULL;
    PyObject *reasons_str = NULL;
    PyObject *sep = NULL;

    if (!self->pt) {
        return PyString_FromFormat("<%s object at %p>",
                                   Py_TYPE(self)->tp_name, self);
    }

    if ((sep = PyString_FromString(", ")) == NULL) {
        goto exit;
    }

    if (self->pt->distPointType == generalName) {
        if ((names = CRLDistributionPt_general_names_tuple(self, AsString)) == NULL) {
            goto exit;
        }

        /* Paste them all together with ", " between. */
        if ((name_str = _PyString_Join(sep, names)) == NULL) {
            goto exit;
        }

        name_desc = PyString_FromFormat(_("General Name List: [%s]"),
                                        PyString_AsString(name_str));

    } else if (self->pt->distPointType == relativeDistinguishedName) {

        if ((rdn = RDN_new_from_CERTRDN(&self->pt->distPoint.relativeName)) == NULL) {
            goto exit;
        }

        if ((name_str = PyObject_Str(rdn)) == NULL) {
            goto exit;
        }

        name_desc = PyString_FromFormat(_("Relative Distinguished Name: %s"),
                                        PyString_AsString(name_str));

    } else {
        PyErr_Format(PyExc_ValueError, "unknown distribution point type (%d), "
                     "expected generalName or relativeDistinguishedName",
                     self->pt->distPointType);
        goto exit;
    }

    if ((crl_issuer = CRLDistributionPt_get_crl_issuer(self, NULL)) == NULL) {
        goto exit;
    }

    if ((crl_issuer_str = PyObject_Str(crl_issuer)) == NULL) {
        goto exit;
    }

    if ((reasons = crl_reason_bitstr_to_tuple(&self->pt->bitsmap, AsEnumDescription)) == NULL) {
        goto exit;
    }

    if ((reasons_str = _PyString_Join(sep, reasons)) == NULL) {
        goto exit;
    }

    result = PyString_FromFormat("%s, Issuer: %s, Reasons: [%s]",
                                 PyString_AsString(name_desc),
                                 PyString_AsString(crl_issuer_str),
                                 PyString_AsString(reasons_str));

 exit:
    Py_XDECREF(rdn);
    Py_XDECREF(names);
    Py_XDECREF(name_str);
    Py_XDECREF(name_desc);
    Py_XDECREF(crl_issuer);
    Py_XDECREF(crl_issuer_str);
    Py_XDECREF(reasons);
    Py_XDECREF(reasons_str);
    Py_XDECREF(sep);

    return result;
}

static PyMethodDef CRLDistributionPt_methods[] = {
    {"format_lines",      (PyCFunction)CRLDistributionPt_format_lines,      METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",            (PyCFunction)CRLDistributionPt_format,            METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {"get_general_names", (PyCFunction)CRLDistributionPt_get_general_names, METH_VARARGS|METH_KEYWORDS, CRLDistributionPt_get_general_names_doc},
    {"get_reasons",       (PyCFunction)CRLDistributionPt_get_reasons,       METH_VARARGS|METH_KEYWORDS, CRLDistributionPt_get_reasons_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
CRLDistributionPt_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    CRLDistributionPt *self;

    TraceObjNewEnter(type);

    if ((self = (CRLDistributionPt *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    self->pt = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
CRLDistributionPt_dealloc(CRLDistributionPt* self)
{
    TraceMethodEnter(self);

    if (self->arena) {
        PORT_FreeArena(self->arena, PR_FALSE);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(CRLDistributionPt_doc,
"An object representing a CRL Distribution Point");

static int
CRLDistributionPt_init(CRLDistributionPt *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"arg1", NULL};
    PyObject *arg;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:CRLDistributionPt", kwlist,
                                     &arg))
        return -1;

    return 0;
}

static Py_ssize_t
CRLDistributionPt_general_names_count(CRLDistributionPt *self)
{
    if (!self->pt || self->pt->distPointType != generalName) {
        return 0;
    }

    return CERTGeneralName_list_count(self->pt->distPoint.fullName);
}

static PyObject *
CRLDistributionPt_general_names_tuple(CRLDistributionPt *self, RepresentationKind repr_kind)
{
    Py_ssize_t n_names;

    n_names = CRLDistributionPt_general_names_count(self);

    if (n_names == 0) {
        Py_INCREF(empty_tuple);
        return empty_tuple;
    }

    return CERTGeneralName_list_to_tuple(self->pt->distPoint.fullName, repr_kind);
}


static PyTypeObject CRLDistributionPtType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.CRLDistributionPoint",		/* tp_name */
    sizeof(CRLDistributionPt),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CRLDistributionPt_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)CRLDistributionPt_repr,		/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)CRLDistributionPt_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    CRLDistributionPt_doc,			/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    CRLDistributionPt_methods,			/* tp_methods */
    CRLDistributionPt_members,			/* tp_members */
    CRLDistributionPt_getseters,		/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)CRLDistributionPt_init,		/* tp_init */
    0,						/* tp_alloc */
    CRLDistributionPt_new,			/* tp_new */
};

PyObject *
CRLDistributionPt_new_from_CRLDistributionPoint(CRLDistributionPoint *pt)
{
    CRLDistributionPt *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (CRLDistributionPt *) CRLDistributionPtType.tp_new(&CRLDistributionPtType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (CERT_CopyCRLDistributionPoint(self->arena, &self->pt, pt) != SECSuccess) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ======================== CRLDistributionPts Class ======================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static
PyGetSetDef CRLDistributionPts_getseters[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef CRLDistributionPts_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
CRLDistributionPts_format_lines(CRLDistributionPts *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    Py_ssize_t len, i;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    //
    len = PyObject_Size((PyObject *)self);
    if ((obj = PyString_FromFormat("CRL Distribution Points: [%zd total]", len)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, NULL, obj, level, fail);
    Py_CLEAR(obj);

    for (i = 0; i < len; i++) {
        if ((obj = PyString_FromFormat("Point [%zd]:", i+1)) == NULL) {
            goto fail;
        }
        FMT_OBJ_AND_APPEND(lines, NULL, obj, level+1, fail);
        Py_CLEAR(obj);
        if ((obj = PySequence_GetItem((PyObject *)self, i)) == NULL) {
            goto fail;
        }
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+2, fail);
        Py_CLEAR(obj);
    }

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
CRLDistributionPts_format(CRLDistributionPts *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)CRLDistributionPts_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
CRLDistributionPts_str(CRLDistributionPts *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  CRLDistributionPts_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

/* =========================== Sequence Protocol ============================ */

static Py_ssize_t
CERTCrlDistributionPoints_count(CERTCrlDistributionPoints *dist_pts)
{
    Py_ssize_t count;
    CRLDistributionPoint **pts;

    if (!dist_pts) return 0;
    for (pts = dist_pts->distPoints, count = 0; *pts; pts++, count++);

    return count;
}

static Py_ssize_t
CRLDistributionPts_length(CRLDistributionPts *self)
{
    if (!self->py_pts) return 0;
    return PyTuple_Size(self->py_pts);
}

static PyObject *
CRLDistributionPts_item(CRLDistributionPts *self, register Py_ssize_t i)
{
    PyObject *py_pt = NULL;

    if (!self->py_pts) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }
    py_pt = PyTuple_GetItem(self->py_pts, i);
    Py_XINCREF(py_pt);
    return py_pt;
}

static PyMethodDef CRLDistributionPts_methods[] = {
    {"format_lines", (PyCFunction)CRLDistributionPts_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)CRLDistributionPts_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static int
CRLDistributionPts_init_from_SECItem(CRLDistributionPts *self, SECItem *item)
{
    CERTCrlDistributionPoints *dist_pts;
    CRLDistributionPoint **pts, *pt;
    PLArenaPool *arena;
    Py_ssize_t count, i;
    PyObject *py_pts = NULL;

    Py_CLEAR(self->py_pts);

    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        return -1;
    }

    if ((dist_pts = CERT_DecodeCRLDistributionPoints(arena, item)) == NULL) {
        PyErr_SetString(PyExc_ValueError, "Failed to parse CRL Distribution Point Extension");
        PORT_FreeArena(arena, PR_FALSE);
        return -1;
    }

    count = CERTCrlDistributionPoints_count(dist_pts);

    if ((py_pts = PyTuple_New(count)) == NULL) {
        PORT_FreeArena(arena, PR_FALSE);
	return -1;
    }

    for (pts = dist_pts->distPoints, i = 0; (pt = *pts); pts++, i++) {
        PyObject *py_crl_dist_pt;

        if ((py_crl_dist_pt = CRLDistributionPt_new_from_CRLDistributionPoint(pt)) == NULL) {
            PORT_FreeArena(arena, PR_FALSE);
            Py_CLEAR(py_pts);
            return -1;
        }

        PyTuple_SetItem(py_pts, i, py_crl_dist_pt);
    }

    ASSIGN_NEW_REF(self->py_pts, py_pts);

    PORT_FreeArena(arena, PR_FALSE);

    return 0;
}

static PyObject *
CRLDistributionPts_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    CRLDistributionPts *self;

    TraceObjNewEnter(type);

    if ((self = (CRLDistributionPts *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->py_pts = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
CRLDistributionPts_traverse(CRLDistributionPts *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_pts);
    return 0;
}

static int
CRLDistributionPts_clear(CRLDistributionPts* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_pts);
    return 0;
}

static void
CRLDistributionPts_dealloc(CRLDistributionPts* self)
{
    TraceMethodEnter(self);

    CRLDistributionPts_clear(self);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(CRLDistributionPts_doc,
"An object representing CRL Distribution Points list");

static int
CRLDistributionPts_init(CRLDistributionPts *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"crl_dist_pt_extension", NULL};
    SecItem *py_sec_item;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:CRLDistributionPts", kwlist,
                                     &SecItemType, &py_sec_item))
        return -1;

    return CRLDistributionPts_init_from_SECItem(self, &py_sec_item->item);
}

static PyObject *
CRLDistributionPts_repr(CRLDistributionPts *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PySequenceMethods CRLDistributionPts_as_sequence = {
    (lenfunc)CRLDistributionPts_length,		/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)CRLDistributionPts_item,	/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyTypeObject CRLDistributionPtsType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.CRLDistributionPts",		/* tp_name */
    sizeof(CRLDistributionPts),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CRLDistributionPts_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)CRLDistributionPts_repr,		/* tp_repr */
    0,						/* tp_as_number */
    &CRLDistributionPts_as_sequence,		/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)CRLDistributionPts_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    CRLDistributionPts_doc,			/* tp_doc */
    (traverseproc)CRLDistributionPts_traverse,	/* tp_traverse */
    (inquiry)CRLDistributionPts_clear,		/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    CRLDistributionPts_methods,			/* tp_methods */
    CRLDistributionPts_members,			/* tp_members */
    CRLDistributionPts_getseters,		/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)CRLDistributionPts_init,		/* tp_init */
    0,						/* tp_alloc */
    CRLDistributionPts_new,			/* tp_new */
};

PyObject *
CRLDistributionPts_new_from_SECItem(SECItem *item)
{
    CRLDistributionPts *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (CRLDistributionPts *) CRLDistributionPtsType.tp_new(&CRLDistributionPtsType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (CRLDistributionPts_init_from_SECItem(self, item) < 0) {
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ======================= AuthorityInfoAccess Class ======================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
AuthorityInfoAccess_get_method_oid(AuthorityInfoAccess *self, void *closure)
{
    TraceMethodEnter(self);

    return SecItem_new_from_SECItem(&self->aia->method, SECITEM_oid);
}

static PyObject *
AuthorityInfoAccess_get_method_tag(AuthorityInfoAccess *self, void *closure)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pyint_tag(&self->aia->method);
}

static PyObject *
AuthorityInfoAccess_get_method_str(AuthorityInfoAccess *self, void *closure)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pystr_desc(&self->aia->method);
}

static PyObject *
AuthorityInfoAccess_get_location(AuthorityInfoAccess *self, void *closure)
{
    TraceMethodEnter(self);

    return GeneralName_new_from_CERTGeneralName(self->aia->location);
}

static
PyGetSetDef AuthorityInfoAccess_getseters[] = {
    {"method_oid", (getter)AuthorityInfoAccess_get_method_oid, (setter)NULL, "method OID as SecItem", NULL},
    {"method_tag", (getter)AuthorityInfoAccess_get_method_tag, (setter)NULL, "method TAG as a enumerated constant (e.g. tag) ", NULL},
    {"method_str", (getter)AuthorityInfoAccess_get_method_str, (setter)NULL, "method as string description", NULL},
    {"location", (getter)AuthorityInfoAccess_get_location,     (setter)NULL, "location as a `nss.GeneralName` object", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef AuthorityInfoAccess_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
AuthorityInfoAccess_format_lines(AuthorityInfoAccess *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if (!self->aia) {
        return lines;
    }

    if ((obj = oid_secitem_to_pystr_desc(&self->aia->method)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Method"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = CERTGeneralName_to_pystr_with_label(self->aia->location)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Location"), obj, level, fail);
    Py_CLEAR(obj);

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
AuthorityInfoAccess_format(AuthorityInfoAccess *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)AuthorityInfoAccess_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
AuthorityInfoAccess_str(AuthorityInfoAccess *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  AuthorityInfoAccess_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef AuthorityInfoAccess_methods[] = {
    {"format_lines", (PyCFunction)AuthorityInfoAccess_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)AuthorityInfoAccess_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
AuthorityInfoAccess_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    AuthorityInfoAccess *self;

    TraceObjNewEnter(type);

    if ((self = (AuthorityInfoAccess *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    self->aia = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}


static void
AuthorityInfoAccess_dealloc(AuthorityInfoAccess* self)
{
    TraceMethodEnter(self);

    PORT_FreeArena(self->arena, PR_FALSE);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(AuthorityInfoAccess_doc,
"AuthorityInfoAccess()\n\
\n\
An object representing AuthorityInfoAccess.\n\
");

static int
AuthorityInfoAccess_init(AuthorityInfoAccess *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {NULL};

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, ":AuthorityInfoAccess", kwlist
                                     ))
        return -1;

    return 0;
}

static PyTypeObject AuthorityInfoAccessType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.AuthorityInfoAccess",				/* tp_name */
    sizeof(AuthorityInfoAccess),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)AuthorityInfoAccess_dealloc,		/* tp_dealloc */
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
    (reprfunc)AuthorityInfoAccess_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    AuthorityInfoAccess_doc,				/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    AuthorityInfoAccess_methods,				/* tp_methods */
    AuthorityInfoAccess_members,				/* tp_members */
    AuthorityInfoAccess_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)AuthorityInfoAccess_init,			/* tp_init */
    0,						/* tp_alloc */
    AuthorityInfoAccess_new,				/* tp_new */
};

static PyObject *
AuthorityInfoAccess_new_from_CERTAuthInfoAccess(CERTAuthInfoAccess *aia)
{
    AuthorityInfoAccess *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (AuthorityInfoAccess *) AuthorityInfoAccessType.tp_new(&AuthorityInfoAccessType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (CERT_CopyAuthInfoAccess(self->arena, &self->aia, aia) != SECSuccess) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}
/* ========================================================================== */
/* ======================= AuthorityInfoAccesses Class ====================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

/* ============================== Class Methods ============================= */

static PyObject *
AuthorityInfoAccesses_format_lines(AuthorityInfoAccesses *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    Py_ssize_t len, i;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    len = PyObject_Size((PyObject *)self);
    if ((obj = PyString_FromFormat("Authority Information Access: [%zd total]", len)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, NULL, obj, level, fail);
    Py_CLEAR(obj);


    for (i = 0; i < len; i++) {
        if ((obj = PyString_FromFormat("Info [%zd]:", i+1)) == NULL) {
            goto fail;
        }
        FMT_OBJ_AND_APPEND(lines, NULL, obj, level+1, fail);
        Py_CLEAR(obj);
        if ((obj = PySequence_GetItem((PyObject *)self, i)) == NULL) {
            goto fail;
        }
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+2, fail);
        Py_CLEAR(obj);
    }

    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
AuthorityInfoAccesses_format(AuthorityInfoAccesses *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)AuthorityInfoAccesses_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
AuthorityInfoAccesses_str(AuthorityInfoAccesses *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  AuthorityInfoAccesses_format(self, empty_tuple, NULL);
    return py_formatted_result;

}


static PyMethodDef AuthorityInfoAccesses_methods[] = {
    {"format_lines", (PyCFunction)AuthorityInfoAccesses_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)AuthorityInfoAccesses_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Sequence Protocol ============================ */
static Py_ssize_t
CERTAuthInfoAccess_count(CERTAuthInfoAccess **aias)
{
    CERTAuthInfoAccess **cur;
    Py_ssize_t count;

    if (aias == NULL) {
        return 0;
    }

    for (count = 0, cur = aias; *cur; cur++, count++);

    return count;
}

static Py_ssize_t
AuthorityInfoAccesses_length(AuthorityInfoAccesses *self)
{
    if (!self->py_aias) return 0;
    return PyTuple_Size(self->py_aias);
}

static PyObject *
AuthorityInfoAccesses_item(AuthorityInfoAccesses *self, register Py_ssize_t i)
{
    PyObject *py_aia = NULL;

    if (!self->py_aias) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }

    py_aia = PyTuple_GetItem(self->py_aias, i);
    Py_XINCREF(py_aia);
    return py_aia;
}


/* =========================== Class Construction =========================== */

static int
AuthorityInfoAccesses_init_from_SECItem(AuthorityInfoAccesses *self, SECItem *item)
{
    CERTAuthInfoAccess **aias;
    PLArenaPool *arena;
    Py_ssize_t count, i;
    PyObject *py_aias = NULL;

    Py_CLEAR(self->py_aias);

    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        return -1;
    }

    if ((aias = CERT_DecodeAuthInfoAccessExtension(arena, item)) == NULL) {
        set_nspr_error("cannot decode Authority Access Info extension");
        PORT_FreeArena(arena, PR_FALSE);
        return -1;
    }

    count = CERTAuthInfoAccess_count(aias);

    if ((py_aias = PyTuple_New(count)) == NULL) {
        PORT_FreeArena(arena, PR_FALSE);
	return -1;
    }

    for (i = 0; i < count; i++) {
        PyObject *py_aia;

        if ((py_aia = AuthorityInfoAccess_new_from_CERTAuthInfoAccess(aias[i])) == NULL) {
            PORT_FreeArena(arena, PR_FALSE);
            Py_CLEAR(py_aias);
            return -1;
        }

        PyTuple_SetItem(py_aias, i, py_aia);
    }

    ASSIGN_NEW_REF(self->py_aias, py_aias);

    PORT_FreeArena(arena, PR_FALSE);

    return 0;
}

static PyObject *
AuthorityInfoAccesses_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    AuthorityInfoAccesses *self;

    TraceObjNewEnter(type);

    if ((self = (AuthorityInfoAccesses *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->py_aias = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
AuthorityInfoAccesses_traverse(AuthorityInfoAccesses *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_aias);
    return 0;
}

static int
AuthorityInfoAccesses_clear(AuthorityInfoAccesses* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_aias);
    return 0;
}

static void
AuthorityInfoAccesses_dealloc(AuthorityInfoAccesses* self)
{
    TraceMethodEnter(self);

    AuthorityInfoAccesses_clear(self);

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(AuthorityInfoAccesses_doc,
"AuthorityInfoAccesses(data)\n\
\n\
:Parameters:\n\
    data : SecItem or str or any buffer compatible object\n\
        Data to initialize the Authority Information Access\n\
        from, must be in DER format\n\
\n\
An object representing AuthorityInfoAccess Extension.\n\
");

static int
AuthorityInfoAccesses_init(AuthorityInfoAccesses *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"auth_info_accesses", NULL};
    PyObject *py_data = NULL;
    SECItem der_tmp_item;
    SECItem *der_item = NULL;


    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:AuthorityInfoAccesses", kwlist,
                                     &py_data))
        return -1;

    SECITEM_PARAM(py_data, der_item, der_tmp_item, false, "data");

    return AuthorityInfoAccesses_init_from_SECItem(self, der_item);
}

static PySequenceMethods AuthorityInfoAccesses_as_sequence = {
    (lenfunc)AuthorityInfoAccesses_length,	/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)AuthorityInfoAccesses_item,	/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyTypeObject AuthorityInfoAccessesType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.AuthorityInfoAccesses",		/* tp_name */
    sizeof(AuthorityInfoAccesses),		/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)AuthorityInfoAccesses_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
    0,						/* tp_as_number */
    &AuthorityInfoAccesses_as_sequence,		/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)AuthorityInfoAccesses_str,	/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    AuthorityInfoAccesses_doc,				/* tp_doc */
    (traverseproc)AuthorityInfoAccesses_traverse,	/* tp_traverse */
    (inquiry)AuthorityInfoAccesses_clear,	/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    AuthorityInfoAccesses_methods,		/* tp_methods */
    0,						/* tp_members */
    0,						/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)AuthorityInfoAccesses_init,	/* tp_init */
    0,						/* tp_alloc */
    AuthorityInfoAccesses_new,			/* tp_new */
};

PyObject *
AuthorityInfoAccesses_new_from_SECItem(SECItem *item)
{
    AuthorityInfoAccesses *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (AuthorityInfoAccesses *) AuthorityInfoAccessesType.tp_new(&AuthorityInfoAccessesType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (AuthorityInfoAccesses_init_from_SECItem(self, item) < 0) {
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ============================ AuthKeyID Class ============================= */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
AuthKeyID_get_key_id(AuthKeyID *self, void *closure)
{
    TraceMethodEnter(self);

    if (!self->auth_key_id) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }

    if (!self->auth_key_id->keyID.len || !self->auth_key_id->keyID.data) {
        Py_RETURN_NONE;
    }

    return SecItem_new_from_SECItem(&self->auth_key_id->keyID, SECITEM_unknown);
}

static PyObject *
AuthKeyID_get_serial_number(AuthKeyID *self, void *closure)
{
    TraceMethodEnter(self);

    if (!self->auth_key_id) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }

    if (!self->auth_key_id->authCertSerialNumber.len || !self->auth_key_id->authCertSerialNumber.data) {
        Py_RETURN_NONE;
    }

    return integer_secitem_to_pylong(&self->auth_key_id->authCertSerialNumber);
}

static
PyGetSetDef AuthKeyID_getseters[] = {
    {"key_id", (getter)AuthKeyID_get_key_id,    (setter)NULL,
     "Returns the key id as a SecItem", NULL},
    {"serial_number", (getter)AuthKeyID_get_serial_number,    (setter)NULL,
     "Returns the key id as a SecItem", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef AuthKeyID_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(AuthKeyID_get_general_names_doc,
"get_general_names(repr_kind=AsString) -> (general_name, ...)\n\
\n\
:Parameters:\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsObject\n\
            The general name as a nss.GeneralName object\n\
        AsString\n\
            The general name as a string.\n\
            (e.g. \"http://crl.geotrust.com/crls/secureca.crl\")\n\
        AsTypeString\n\
            The general name type as a string.\n\
             (e.g. \"URI\")\n\
        AsTypeEnum\n\
            The general name type as a general name type enumerated constant.\n\
             (e.g. nss.certURI )\n\
        AsLabeledString\n\
            The general name as a string with it's type prepended.\n\
            (e.g. \"URI: http://crl.geotrust.com/crls/secureca.crl\"\n\
\n\
Returns a tuple of general names in the authentication key id extension\n\
for the issuer. If the issuer was not defined then the returned tuple\n\
will be empty.\n\
\n\
You may specify how the each member of the tuple is represented, by default\n\
it will be as a string.\n\
");

static PyObject *
AuthKeyID_get_general_names(AuthKeyID *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"repr_kind", NULL};
    int repr_kind = AsString;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:get_general_names", kwlist,
                                     &repr_kind))
        return NULL;

    if (!self->auth_key_id) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }

    return AuthKeyID_general_names_tuple(self, repr_kind);
}

static PyObject *
AuthKeyID_format_lines(AuthKeyID *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    Py_ssize_t len;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *obj1 = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if (!self->auth_key_id) {
        return lines;
    }

    FMT_LABEL_AND_APPEND(lines, _("Key ID"), level, fail);

    if ((obj = AuthKeyID_get_key_id(self, NULL)) == NULL) {
        goto fail;
    }
    APPEND_OBJ_TO_HEX_LINES_AND_CLEAR(lines, obj, level+1, fail);

    if ((obj = AuthKeyID_get_serial_number(self, NULL)) == NULL) {
        goto fail;
    }

    if ((obj1 = PyObject_Str(obj)) == NULL) {
        goto fail;
    }
    Py_CLEAR(obj);

    FMT_OBJ_AND_APPEND(lines, _("Serial Number"), obj1, level, fail);
    Py_CLEAR(obj1);

    if ((obj = AuthKeyID_general_names_tuple(self, AsString)) == NULL) {
        goto fail;
    }
    len = PyObject_Size(obj);
    if ((obj1 = PyString_FromFormat("General Names: [%zd total]", len)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, NULL, obj1, level, fail);
    Py_CLEAR(obj1);

    APPEND_LINES_AND_CLEAR(lines, obj, level+1, fail);

    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(obj1);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
AuthKeyID_format(AuthKeyID *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)AuthKeyID_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
AuthKeyID_str(AuthKeyID *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  AuthKeyID_format(self, empty_tuple, NULL);
    return py_formatted_result;

}


static PyMethodDef AuthKeyID_methods[] = {
    {"format_lines",      (PyCFunction)AuthKeyID_format_lines,      METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",            (PyCFunction)AuthKeyID_format,            METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {"get_general_names", (PyCFunction)AuthKeyID_get_general_names, METH_VARARGS|METH_KEYWORDS, AuthKeyID_get_general_names_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
AuthKeyID_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    AuthKeyID *self;

    TraceObjNewEnter(type);

    if ((self = (AuthKeyID *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    self->auth_key_id = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
AuthKeyID_dealloc(AuthKeyID* self)
{
    TraceMethodEnter(self);

    if (self->arena) {
        PORT_FreeArena(self->arena, PR_FALSE);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(AuthKeyID_doc,
"An object representing Authentication Key ID extension");

static int
AuthKeyID_init(AuthKeyID *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"auth_key_id", NULL};
    SecItem *py_sec_item;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:AuthKeyID", kwlist,
                                     &SecItemType, &py_sec_item))
        return -1;

    if ((self->auth_key_id = CERT_DecodeAuthKeyID(self->arena, &py_sec_item->item)) == NULL) {
        set_nspr_error("cannot decode AuthKeyID");
        return -1;
    }

    return 0;
}

static Py_ssize_t
AuthKeyID_general_names_count(AuthKeyID *self)
{
    if (!self->auth_key_id || !self->auth_key_id->authCertIssuer) {
        return 0;
    }

    return CERTGeneralName_list_count(self->auth_key_id->authCertIssuer);
}

static PyObject *
AuthKeyID_general_names_tuple(AuthKeyID *self, RepresentationKind repr_kind)
{
    Py_ssize_t n_names;

    n_names = AuthKeyID_general_names_count(self);

    if (n_names == 0) {
        Py_INCREF(empty_tuple);
        return empty_tuple;
    }

    return CERTGeneralName_list_to_tuple(self->auth_key_id->authCertIssuer, repr_kind);
}

static PyObject *
AuthKeyID_repr(AuthKeyID *self)
{
    PyObject *result = NULL;
    PyObject *sep = NULL;
    PyObject *names = NULL;
    PyObject *name_str = NULL;
    PyObject *key_id = NULL;
    PyObject *key_id_str = NULL;
    PyObject *serial_number = NULL;
    PyObject *serial_number_str = NULL;

    if (!self->auth_key_id) {
        return PyString_FromFormat("<%s object at %p>",
                                   Py_TYPE(self)->tp_name, self);
    }

    if ((sep = PyString_FromString(", ")) == NULL) {
        goto exit;
    }

    if ((names = AuthKeyID_general_names_tuple(self, AsString)) == NULL) {
        goto exit;
    }

    /* Paste them all together with ", " between. */
    if ((name_str = _PyString_Join(sep, names)) == NULL) {
        goto exit;
    }

    if ((key_id = AuthKeyID_get_key_id(self, NULL)) == NULL) {
        goto exit;
    }

    if ((key_id_str = PyObject_Str(key_id)) == NULL) {
        goto exit;
    }

    if ((serial_number = AuthKeyID_get_serial_number(self, NULL)) == NULL) {
        goto exit;
    }

    if ((serial_number_str = PyObject_Str(serial_number)) == NULL) {
        goto exit;
    }

    result = PyString_FromFormat("ID: %s, Serial Number: %s, Issuer: [%s]",
                                 PyString_AsString(key_id_str),
                                 PyString_AsString(serial_number_str),
                                 PyString_AsString(name_str));


    exit:
    Py_XDECREF(sep);
    Py_XDECREF(names);
    Py_XDECREF(name_str);
    Py_XDECREF(key_id);
    Py_XDECREF(key_id_str);
    Py_XDECREF(serial_number);
    Py_XDECREF(serial_number_str);
    return result;
}

static PyTypeObject AuthKeyIDType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.AuthKeyID",			/* tp_name */
    sizeof(AuthKeyID),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)AuthKeyID_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)AuthKeyID_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)AuthKeyID_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    AuthKeyID_doc,				/* tp_doc */
    0,						/* tp_traverse */
    0,						/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    AuthKeyID_methods,				/* tp_methods */
    AuthKeyID_members,				/* tp_members */
    AuthKeyID_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)AuthKeyID_init,			/* tp_init */
    0,						/* tp_alloc */
    AuthKeyID_new,				/* tp_new */
};

PyObject *
AuthKeyID_new_from_CERTAuthKeyID(CERTAuthKeyID *auth_key_id)
{
    AuthKeyID *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (AuthKeyID *) AuthKeyIDType.tp_new(&AuthKeyIDType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (CERT_CopyAuthKeyID(self->arena, &self->auth_key_id, auth_key_id) != SECSuccess) {
        set_nspr_error(NULL);
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

PyObject *
AuthKeyID_new_from_SECItem(SECItem *item)
{
    AuthKeyID *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (AuthKeyID *) AuthKeyIDType.tp_new(&AuthKeyIDType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if ((self->auth_key_id = CERT_DecodeAuthKeyID(self->arena, item)) == NULL) {
        set_nspr_error("cannot decode AuthKeyID");
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}



/* ========================================================================== */
/* ======================== BasicConstraints Class ========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
BasicConstraints_get_is_ca(BasicConstraints *self, void *closure)
{
    TraceMethodEnter(self);

    return PyBool_FromLong(self->bc.isCA);

    return NULL;
}

static PyObject *
BasicConstraints_get_path_len(BasicConstraints *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->bc.pathLenConstraint);

    return NULL;
}

static
PyGetSetDef BasicConstraints_getseters[] = {
    {"is_ca", (getter)BasicConstraints_get_is_ca,    (setter)NULL,
     "returns boolean, True if certificate is a certificate authority (i.e. CA)", NULL},
    {"path_len", (getter)BasicConstraints_get_path_len,    (setter)NULL,
     "returns max path length constraint as an integer", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef BasicConstraints_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
BasicConstraints_format_lines(BasicConstraints *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    obj = self->bc.isCA ? Py_True : Py_False;
    Py_INCREF(obj);
    FMT_OBJ_AND_APPEND(lines, _("Is CA"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = PyString_FromFormat("%d", self->bc.pathLenConstraint)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Path Length"), obj, level, fail);
    Py_CLEAR(obj);

    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
BasicConstraints_format(BasicConstraints *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)BasicConstraints_format_lines, (PyObject *)self, args, kwds);
}

static PyMethodDef BasicConstraints_methods[] = {
    {"format_lines", (PyCFunction)BasicConstraints_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)BasicConstraints_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
BasicConstraints_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    BasicConstraints *self;

    TraceObjNewEnter(type);

    if ((self = (BasicConstraints *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    memset(&self->bc, 0, sizeof(self->bc));


    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
BasicConstraints_dealloc(BasicConstraints* self)
{
    TraceMethodEnter(self);

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(BasicConstraints_doc,
"An object representing X509 Basic Constraints Extension");

static int
BasicConstraints_init(BasicConstraints *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"basic_constraints", NULL};
    SecItem *py_sec_item;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:BasicConstraints", kwlist,
                                     &SecItemType, &py_sec_item))

        return -1;

    if (CERT_DecodeBasicConstraintValue(&self->bc, &py_sec_item->item) != SECSuccess) {
        set_nspr_error("cannot decode Basic Constraints");
        return -1;
    }

    return 0;
}

static PyObject *
BasicConstraints_repr(BasicConstraints *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyObject *
BasicConstraints_str(BasicConstraints *self)
{
    return PyString_FromFormat("is_ca=%s path_len=%d",
                               self->bc.isCA ? "True" : "False", self->bc.pathLenConstraint);
}

static PyTypeObject BasicConstraintsType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.BasicConstraints",			/* tp_name */
    sizeof(BasicConstraints),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)BasicConstraints_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)BasicConstraints_repr,		/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)BasicConstraints_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    BasicConstraints_doc,			/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    BasicConstraints_methods,			/* tp_methods */
    BasicConstraints_members,			/* tp_members */
    BasicConstraints_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)BasicConstraints_init,		/* tp_init */
    0,						/* tp_alloc */
    BasicConstraints_new,			/* tp_new */
};

PyObject *
BasicConstraints_new_from_SECItem(SECItem *item)
{
    BasicConstraints *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (BasicConstraints *) BasicConstraintsType.tp_new(&BasicConstraintsType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (CERT_DecodeBasicConstraintValue(&self->bc, item) != SECSuccess) {
        set_nspr_error("cannot decode Basic Constraints");
        Py_CLEAR(self);
        return NULL;
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ========================== CertAttribute Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
CertAttribute_get_type_oid(CertAttribute *self, void *closure)
{
    TraceMethodEnter(self);

    return SecItem_new_from_SECItem(&self->attr.attrType, SECITEM_oid);
}

static PyObject *
CertAttribute_get_type_tag(CertAttribute *self, void *closure)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pyint_tag(&self->attr.attrType);
}

static PyObject *
CertAttribute_get_type_str(CertAttribute *self, void *closure)
{
    TraceMethodEnter(self);

    return oid_secitem_to_pystr_desc(&self->attr.attrType);
}

static PyObject *
CertAttribute_get_values(CertAttribute *self, void *closure)
{
    Py_ssize_t i;
    PyObject *tuple = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(self);

    if ((tuple = PyTuple_New(self->n_values)) == NULL) {
        goto fail;
    }

    for (i = 0; i < self->n_values; i++) {
        /* NSS WART - extensions are not an array of SECItems like all other attributes */
        if (self->oid_tag == SEC_OID_PKCS9_EXTENSION_REQUEST) {
            if ((obj = CertificateExtension_new_from_CERTCertExtension(self->extensions[i])) == NULL) {
                goto fail;
            }
        } else {
            if ((obj = SecItem_new_from_SECItem(self->attr.attrValue[i], SECITEM_unknown)) == NULL) {
                goto fail;
            }
        }
        PyTuple_SetItem(tuple, i, obj);
    }

    return tuple;
 fail:
    Py_XDECREF(tuple);
    Py_XDECREF(obj);
    return NULL;
}

static
PyGetSetDef CertAttribute_getseters[] = {
    {"type_oid", (getter)CertAttribute_get_type_oid, (setter)NULL, "type OID as SecItem", NULL},
    {"type_tag", (getter)CertAttribute_get_type_tag, (setter)NULL, "type TAG as a enumerated constant (e.g. tag) ", NULL},
    {"type_str", (getter)CertAttribute_get_type_str, (setter)NULL, "type as string description", NULL},
    {"values",   (getter)CertAttribute_get_values, (setter)NULL, "tuple of CertificateExtension objects if "
                                                                 "type_tag == SEC_OID_PKCS9_EXTENSION_REQUEST "
                                                                 "else tuple of SecItem objects", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef CertAttribute_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
CertAttribute_format_lines(CertAttribute *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    Py_ssize_t i;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if ((obj = oid_secitem_to_pystr_desc(&self->attr.attrType)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Type"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = PyString_FromFormat("Values (%zd total)", self->n_values)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, NULL, obj, level, fail);
    Py_CLEAR(obj);

    for (i = 0; i < self->n_values; i++) {
        if ((obj = PyString_FromFormat("Value [%zd]", i)) == NULL) {
            goto fail;
        }
        FMT_OBJ_AND_APPEND(lines, NULL, obj, level+1, fail);
        Py_CLEAR(obj);

        /* NSS WART - extensions are not an array of SECItems like all other attributes */
        if (self->oid_tag == SEC_OID_PKCS9_EXTENSION_REQUEST) {
            if ((obj = CertificateExtension_new_from_CERTCertExtension(self->extensions[i])) == NULL) {
                goto fail;
            }
            CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+2, fail);
        } else {
            if ((obj = der_any_secitem_to_pystr(self->attr.attrValue[i])) == NULL) {
                goto fail;
            }
            FMT_OBJ_AND_APPEND(lines, NULL, obj, level+2, fail);
        }
        Py_CLEAR(obj);
    }

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
CertAttribute_format(CertAttribute *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)CertAttribute_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
CertAttribute_str(CertAttribute *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  CertAttribute_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef CertAttribute_methods[] = {
    {"format_lines", (PyCFunction)CertAttribute_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)CertAttribute_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Sequence Protocol ============================ */
static Py_ssize_t
CertAttribute_length(CertAttribute *self)
{
    return self->n_values;
}

static PyObject *
CertAttribute_item(CertAttribute *self, register Py_ssize_t i)
{
    if (i < 0 || i >= self->n_values) {
        PyErr_SetString(PyExc_IndexError, "CertAttribute index out of range");
        return NULL;
    }

    /* NSS WART - extensions are not an array of SECItems like all other attributes */
    if (self->oid_tag == SEC_OID_PKCS9_EXTENSION_REQUEST) {
        return CertificateExtension_new_from_CERTCertExtension(self->extensions[i]);
    } else {
        return SecItem_new_from_SECItem(self->attr.attrValue[i], SECITEM_unknown);
    }
}


/* =========================== Class Construction =========================== */

static PyObject *
CertAttribute_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    CertAttribute *self;

    TraceObjNewEnter(type);

    if ((self = (CertAttribute *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    memset(&self->attr, 0, sizeof(self->attr));
    self->oid_tag = SEC_OID_UNKNOWN;
    self->n_values = 0;
    self->extensions = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}
static void
CertAttribute_dealloc(CertAttribute* self)
{
    TraceMethodEnter(self);

    PORT_FreeArena(self->arena, PR_FALSE);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(CertAttribute_doc,
"CertAttribute()\n\
\n\
An object representing CertAttribute.\n\
");

static int
CertAttribute_init(CertAttribute *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"arg", NULL};
    PyObject *arg;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:CertAttribute", kwlist,
                                     &arg))
        return -1;

    return 0;
}

static PySequenceMethods CertAttribute_as_sequence = {
    (lenfunc)CertAttribute_length,		/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)CertAttribute_item,		/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyTypeObject CertAttributeType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.CertAttribute",				/* tp_name */
    sizeof(CertAttribute),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CertAttribute_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
    0,						/* tp_as_number */
    &CertAttribute_as_sequence,			/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)CertAttribute_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    CertAttribute_doc,				/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    CertAttribute_methods,				/* tp_methods */
    CertAttribute_members,				/* tp_members */
    CertAttribute_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)CertAttribute_init,			/* tp_init */
    0,						/* tp_alloc */
    CertAttribute_new,				/* tp_new */
};

static PyObject *
CertAttribute_new_from_CERTAttribute(CERTAttribute *attr)
{
    Py_ssize_t i;
    CertAttribute *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (CertAttribute *) CertAttributeType.tp_new(&CertAttributeType, NULL, NULL)) == NULL) {
        return NULL;
    }

    if (SECITEM_CopyItem(self->arena, &self->attr.attrType, &attr->attrType) != SECSuccess) {
        return NULL;
    }

    self->oid_tag = SECOID_FindOIDTag(&self->attr.attrType);

    /* NSS WART - extensions are not an array of SECItems like all other attributes */
    if (self->oid_tag == SEC_OID_PKCS9_EXTENSION_REQUEST) {
        if (CERTCertExtensions_from_CERTAttribute(self->arena, attr, &self->extensions) != SECSuccess) {
            return NULL;
        }
        self->n_values = CERTCertExtension_count(self->extensions);
        self->attr.attrValue = NULL;
    } else {
        Py_ssize_t count;
        SECItem **values;

        count = 0;
        if (attr->attrValue) {
            for (values = attr->attrValue; values[count]; count++);
        }
        self->n_values = count;

        if ((self->attr.attrValue = PORT_ArenaZNewArray(self->arena, SECItem *, self->n_values+1)) == NULL) {
            return NULL;
        }

        for (i = 0; i < self->n_values; i++) {
            if ((self->attr.attrValue[i] = SECITEM_ArenaDupItem(self->arena, attr->attrValue[i])) == NULL) {
                return NULL;
            }
        }
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ======================= CertificateRequest Class ========================= */
/* ========================================================================== */

static SECStatus
CERTCertExtensions_from_CERTAttribute(PRArenaPool *arena,
                                      CERTAttribute *attr, CERTCertExtension ***exts)
{
    if (attr == NULL) {
        /* None of the attributes was an extension, return success with empty extension list */
        *exts = NULL;
        return SECSuccess;
    }

    if (attr->attrValue == NULL) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    return(SEC_ASN1DecodeItem(arena, exts,
            SEC_ASN1_GET(CERT_SequenceOfCertExtensionTemplate),
            *attr->attrValue));
}

/* NSS WART, CERT_GetCertificateRequestExtensions is broken, assumes extensions
 * will be first cert request attribute, but that's an invalid assumption
 *
 * We also break the logic into two parts, CERTCertExtensions_from_CERTAttribute()
 * which is needed elsewhere.
 */

static SECStatus
My_CERT_GetCertificateRequestExtensions(CERTCertificateRequest *req, CERTCertExtension ***exts)
{
    CERTAttribute **attrs, *attr;

    if (req == NULL || exts == NULL) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (req->attributes == NULL) {
        /* No attributes, return success with empty extension list */
        *exts = NULL;
        return SECSuccess;
    }

    /* Search for an extension attribute in set of attributes */
    attrs = req->attributes;
    for (attr = *attrs; attr; attr = *(++attrs)) {
        if (SECOID_FindOIDTag(&attr->attrType) == SEC_OID_PKCS9_EXTENSION_REQUEST) {
            break;
        }
    }

    return CERTCertExtensions_from_CERTAttribute(req->arena, attr, exts);
}

static int
CertificateRequest_init_from_SECItem(CertificateRequest *self, SECItem *der_cert_req)
{
    if ((self->cert_req = PORT_ArenaZAlloc(self->arena, sizeof(CERTCertificateRequest))) == NULL) {
        set_nspr_error(NULL);
        return -1;
    }
    self->cert_req->arena = self->arena;

    /* Since cert request is a signed data, must decode to get the inner data */
    if (SEC_ASN1DecodeItem(self->arena, &self->signed_data,
                           SEC_ASN1_GET(CERT_SignedDataTemplate),
                           der_cert_req) != SECSuccess) {
        set_nspr_error(NULL);
        return -1;
    }

    if (SEC_ASN1DecodeItem(self->arena, self->cert_req,
                           SEC_ASN1_GET(CERT_CertificateRequestTemplate),
                           &self->signed_data.data) != SECSuccess) {
        set_nspr_error(NULL);
        return -1;
    }

    if (CERT_VerifySignedDataWithPublicKeyInfo(&self->signed_data,
                                               &self->cert_req->subjectPublicKeyInfo,
                                               NULL) != SECSuccess) {
        set_nspr_error(NULL);
        return -1;
    }

    if (My_CERT_GetCertificateRequestExtensions(self->cert_req, &self->extensions) != SECSuccess) {
        set_nspr_error("CERT_GetCertificateRequestExtensions failed");
        return -1;
    }

   return 0;
}
/* ============================ Attribute Access ============================ */

static PyObject *
CertificateRequest_get_subject(CertificateRequest *self, void *closure)
{
    TraceMethodEnter(self);

    return DN_new_from_CERTName(&self->cert_req->subject);
}

static PyObject *
CertificateRequest_get_version(CertificateRequest *self, void *closure)
{
    TraceMethodEnter(self);

    return integer_secitem_to_pylong(&self->cert_req->version);
}

static PyObject *
CertificateRequest_get_subject_public_key_info(CertificateRequest *self, void *closure)
{
    TraceMethodEnter(self);

    return SubjectPublicKeyInfo_new_from_CERTSubjectPublicKeyInfo(
               &self->cert_req->subjectPublicKeyInfo);
}



static PyObject *
CertificateRequest_get_extensions(CertificateRequest *self, void *closure)
{
    TraceMethodEnter(self);

    return CERTCertExtension_tuple(self->extensions, AsObject);
}

static PyObject *
CertificateRequest_get_attributes(CertificateRequest *self, void *closure)
{
    CERTAttribute **attributes_list = NULL, **attributes = NULL;
    Py_ssize_t num_attributes, i;
    PyObject *attributes_tuple;

    TraceMethodEnter(self);

    num_attributes = 0;

    attributes_list = self->cert_req->attributes;
    if (attributes_list == NULL) {
        Py_INCREF(empty_tuple);
        return empty_tuple;
    }

    /* First count how many attributes the cert request has */
    for (attributes = attributes_list, num_attributes = 0;
         attributes && *attributes;
         attributes++, num_attributes++);

    /* Allocate a tuple */
    if ((attributes_tuple = PyTuple_New(num_attributes)) == NULL) {
        return NULL;
    }

    /* Copy the attributes into the tuple */
    for (attributes = attributes_list, i = 0; attributes && *attributes; attributes++, i++) {
        CERTAttribute *attribute = *attributes;
        PyObject *py_cert_attribute;

        if ((py_cert_attribute = CertAttribute_new_from_CERTAttribute(attribute)) == NULL) {
            Py_DECREF(attributes_tuple);
            return NULL;
        }

        PyTuple_SetItem(attributes_tuple, i, py_cert_attribute);
    }

    return attributes_tuple;
}

static
PyGetSetDef CertificateRequest_getseters[] = {
    {"subject", (getter)CertificateRequest_get_subject, (setter)NULL,
     "subject as an `DN` object", NULL},
    {"version", (getter)CertificateRequest_get_version, (setter)NULL,
     "version as integer", NULL},
    {"subject_public_key_info", (getter)CertificateRequest_get_subject_public_key_info, NULL,
     "certificate public info as SubjectPublicKeyInfo object",  NULL},
    {"extensions", (getter)CertificateRequest_get_extensions, NULL,
     "certificate extensions as a tuple of CertificateExtension objects",  NULL},
    {"attributes", (getter)CertificateRequest_get_attributes, NULL,
     "certificate request attributes as a tuple of CertAttribute objects",  NULL},

    {NULL}  /* Sentinel */
};

static PyMemberDef CertificateRequest_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
CertificateRequest_format_lines(CertificateRequest *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    Py_ssize_t len, i;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    PyObject *obj1 = NULL;
    PyObject *obj2 = NULL;
    PyObject *attributes = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        goto fail;
    }

    FMT_LABEL_AND_APPEND(lines, _("Data"), level+1, fail);

    if ((obj = CertificateRequest_get_version(self, NULL)) == NULL) {
        goto fail;
    }
    if ((obj2 = obj_sprintf("%d (%#x)", obj, obj)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Version"), obj2, level+2, fail);
    Py_CLEAR(obj);
    Py_CLEAR(obj1);
    Py_CLEAR(obj2);

    if ((obj = CertificateRequest_get_subject(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Subject"), obj, level+2, fail);
    Py_CLEAR(obj);

    FMT_LABEL_AND_APPEND(lines, _("Subject Public Key Info"), level+2, fail);

    if ((obj = CertificateRequest_get_subject_public_key_info(self, NULL)) == NULL) {
        goto fail;
    }

    CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+3, fail);
    Py_CLEAR(obj);

    if ((attributes = CertificateRequest_get_attributes(self, NULL)) == NULL) {
        goto fail;
    }

    len = PyTuple_Size(attributes);
    if ((obj = PyString_FromFormat("Attributes: (%zd total)", len)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, NULL, obj, level+1, fail);
    Py_CLEAR(obj);

    for (i = 0; i < len; i++) {
        if ((obj = PyString_FromFormat("Attribute [%zd]", i)) == NULL) {
            goto fail;
        }
        FMT_OBJ_AND_APPEND(lines, NULL, obj, level+2, fail);
        Py_CLEAR(obj);

        obj = PyTuple_GetItem(attributes, i);
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+3, fail);
        FMT_LABEL_AND_APPEND(lines, NULL, 0, fail);
    }
    Py_CLEAR(attributes);

    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(obj1);
    Py_XDECREF(obj2);
    Py_XDECREF(lines);
    Py_XDECREF(attributes);
    return NULL;
}

static PyObject *
CertificateRequest_format(CertificateRequest *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)CertificateRequest_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
CertificateRequest_str(CertificateRequest *self)
{
    PyObject *py_formatted_result = NULL;

    py_formatted_result = CertificateRequest_format(self, empty_tuple, NULL);
    return py_formatted_result;

}


static PyMethodDef CertificateRequest_methods[] = {
    {"format_lines",           (PyCFunction)CertificateRequest_format_lines,           METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",                 (PyCFunction)CertificateRequest_format,                 METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
CertificateRequest_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    CertificateRequest *self;

    TraceObjNewEnter(type);

    if ((self = (CertificateRequest *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    self->cert_req = NULL;
    memset(&self->signed_data, 0, sizeof(self->signed_data));
    self->extensions = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
CertificateRequest_dealloc(CertificateRequest* self)
{
    TraceMethodEnter(self);

    /*
     * We could call CERT_DestroyCertificateRequest() but all
     * CERT_DestroyCertificateRequest() does is call PORT_FreeArena() on
     * the arena stored in the CERTCertificateRequest. All the other
     * dealloc routines for objects with arenas call PORT_FreeArena()
     * explicitly, so for consistency and to make sure the freeing of
     * the arena is explicit rather than hidden we do the same here.
     *
     * Also, self->signed_data does not need to be explicitly freed
     * because it's allocated out of the arena.
     */

    if (self->arena) {
        PORT_FreeArena(self->arena, PR_FALSE);
    }
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(CertificateRequest_doc,
"CertificateRequest(data=None)\n\
\n\
:Parameters:\n\
    data : SecItem or str or any buffer compatible object\n\
        Data to initialize the certificate request from, must be in DER format\n\
\n\
An object representing a certificate request");

static int
CertificateRequest_init(CertificateRequest *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"data", NULL};
    PyObject *py_data = NULL;
    SECItem der_tmp_item;
    SECItem *der_item = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O:CertificateRequest", kwlist,
                                     &py_data))
        return -1;

    SECITEM_PARAM(py_data, der_item, der_tmp_item, true, "data");
    if (der_item) {
        return CertificateRequest_init_from_SECItem(self, der_item);
    } else {
        return 0;
    }
}

static PyObject *
CertificateRequest_repr(CertificateRequest *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject CertificateRequestType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.CertificateRequest",		/* tp_name */
    sizeof(CertificateRequest),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CertificateRequest_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)CertificateRequest_repr,		/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)CertificateRequest_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    CertificateRequest_doc,			/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    CertificateRequest_methods,			/* tp_methods */
    CertificateRequest_members,			/* tp_members */
    CertificateRequest_getseters,		/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)CertificateRequest_init,		/* tp_init */
    0,						/* tp_alloc */
    CertificateRequest_new,			/* tp_new */
};

/* ========================================================================== */
/* ========================== InitParameters Class ========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
InitParameters_get_password_required(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    return PyBool_FromLong(self->params.passwordRequired);
}

static int
InitParameters_set_password_required(InitParameters *self, PyObject *value, void *closure)
{
    TraceMethodEnter(self);

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the password_required attribute");
        return -1;
    }

    switch(PyObject_IsTrue(value)) {
    case 0:
        self->params.passwordRequired = PR_FALSE;
        return 0;
    case 1:
        self->params.passwordRequired = PR_TRUE;
        return 0;
    default:
        PyErr_SetString(PyExc_TypeError, "The password_required attribute value must be a boolean");
        return -1;
    }
}

static PyObject *
InitParameters_get_min_password_len(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->params.minPWLen);
}

static int
InitParameters_set_min_password_len(InitParameters *self, PyObject *value, void *closure)
{
    TraceMethodEnter(self);

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the min_password_len attribute");
        return -1;
    }

    if (!PyInt_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "The min_password_len attribute value must be an integer");
        return -1;
    }

    self->params.minPWLen = PyInt_AsLong(value);

    return 0;
}

static PyObject *
InitParameters_get_manufacturer_id(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->params.manufactureID == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeUTF8(self->params.manufactureID, strlen(self->params.manufactureID), NULL);
}

static int
InitParameters_set_manufacturer_id(InitParameters *self, PyObject *value, void *closure)
{
    PyObject *args = NULL;
    char *new_value = NULL;

    TraceMethodEnter(self);

    if (value == NULL) {
        if (self->params.manufactureID) {
            PyMem_Free(self->params.manufactureID);
        }
        self->params.manufactureID = NULL;
        return 0;
    }

    if ((args = Py_BuildValue("(O)", value)) == NULL) {
        return -1;
    }

    if (PyArg_ParseTuple(args, "es", "utf-8", &new_value) == -1) {
        Py_DECREF(args);
        PyErr_SetString(PyExc_TypeError, "The manufacturer_id attribute value must be a string or unicode");
        return -1;
    }

    if (self->params.manufactureID) {
        PyMem_Free(self->params.manufactureID);
        self->params.manufactureID = NULL;
    }

    self->params.manufactureID = new_value;
    Py_DECREF(args);
    return 0;
}

static PyObject *
InitParameters_get_library_description(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->params.libraryDescription == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeUTF8(self->params.libraryDescription, strlen(self->params.libraryDescription), NULL);
}

static int
InitParameters_set_library_description(InitParameters *self, PyObject *value, void *closure)
{
    PyObject *args = NULL;
    char *new_value = NULL;

    TraceMethodEnter(self);

    if (value == NULL) {
        if (self->params.libraryDescription) {
            PyMem_Free(self->params.libraryDescription);
        }
        self->params.libraryDescription = NULL;
        return 0;
    }

    if ((args = Py_BuildValue("(O)", value)) == NULL) {
        return -1;
    }

    if (PyArg_ParseTuple(args, "es", "utf-8", &new_value) == -1) {
        Py_DECREF(args);
        PyErr_SetString(PyExc_TypeError, "The library_description attribute value must be a string or unicode");
        return -1;
    }

    if (self->params.libraryDescription) {
        PyMem_Free(self->params.libraryDescription);
        self->params.libraryDescription = NULL;
    }

    self->params.libraryDescription = new_value;
    Py_DECREF(args);
    return 0;
}



static PyObject *
InitParameters_get_crypto_token_description(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->params.cryptoTokenDescription == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeUTF8(self->params.cryptoTokenDescription, strlen(self->params.cryptoTokenDescription), NULL);
}

static int
InitParameters_set_crypto_token_description(InitParameters *self, PyObject *value, void *closure)
{
    PyObject *args = NULL;
    char *new_value = NULL;

    TraceMethodEnter(self);

    if (value == NULL) {
        if (self->params.cryptoTokenDescription) {
            PyMem_Free(self->params.cryptoTokenDescription);
        }
        self->params.cryptoTokenDescription = NULL;
        return 0;
    }

    if ((args = Py_BuildValue("(O)", value)) == NULL) {
        return -1;
    }

    if (PyArg_ParseTuple(args, "es", "utf-8", &new_value) == -1) {
        Py_DECREF(args);
        PyErr_SetString(PyExc_TypeError, "The crypto_token_description attribute value must be a string or unicode");
        return -1;
    }

    if (self->params.cryptoTokenDescription) {
        PyMem_Free(self->params.cryptoTokenDescription);
        self->params.cryptoTokenDescription = NULL;
    }

    self->params.cryptoTokenDescription = new_value;
    Py_DECREF(args);
    return 0;
}



static PyObject *
InitParameters_get_db_token_description(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->params.dbTokenDescription == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeUTF8(self->params.dbTokenDescription, strlen(self->params.dbTokenDescription), NULL);
}

static int
InitParameters_set_db_token_description(InitParameters *self, PyObject *value, void *closure)
{
    PyObject *args = NULL;
    char *new_value = NULL;

    TraceMethodEnter(self);

    if (value == NULL) {
        if (self->params.dbTokenDescription) {
            PyMem_Free(self->params.dbTokenDescription);
        }
        self->params.dbTokenDescription = NULL;
        return 0;
    }

    if ((args = Py_BuildValue("(O)", value)) == NULL) {
        return -1;
    }

    if (PyArg_ParseTuple(args, "es", "utf-8", &new_value) == -1) {
        Py_DECREF(args);
        PyErr_SetString(PyExc_TypeError, "The db_token_description attribute value must be a string or unicode");
        return -1;
    }

    if (self->params.dbTokenDescription) {
        PyMem_Free(self->params.dbTokenDescription);
        self->params.dbTokenDescription = NULL;
    }

    self->params.dbTokenDescription = new_value;
    Py_DECREF(args);
    return 0;
}

static PyObject *
InitParameters_get_fips_token_description(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->params.FIPSTokenDescription == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeUTF8(self->params.FIPSTokenDescription, strlen(self->params.FIPSTokenDescription), NULL);
}

static int
InitParameters_set_fips_token_description(InitParameters *self, PyObject *value, void *closure)
{
    PyObject *args = NULL;
    char *new_value = NULL;

    TraceMethodEnter(self);

    if (value == NULL) {
        if (self->params.FIPSTokenDescription) {
            PyMem_Free(self->params.FIPSTokenDescription);
        }
        self->params.FIPSTokenDescription = NULL;
        return 0;
    }

    if ((args = Py_BuildValue("(O)", value)) == NULL) {
        return -1;
    }

    if (PyArg_ParseTuple(args, "es", "utf-8", &new_value) == -1) {
        Py_DECREF(args);
        PyErr_SetString(PyExc_TypeError, "The fips_token_description attribute value must be a string or unicode");
        return -1;
    }

    if (self->params.FIPSTokenDescription) {
        PyMem_Free(self->params.FIPSTokenDescription);
        self->params.FIPSTokenDescription = NULL;
    }

    self->params.FIPSTokenDescription = new_value;
    Py_DECREF(args);
    return 0;
}

static PyObject *
InitParameters_get_crypto_slot_description(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->params.cryptoSlotDescription == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeUTF8(self->params.cryptoSlotDescription, strlen(self->params.cryptoSlotDescription), NULL);
}

static int
InitParameters_set_crypto_slot_description(InitParameters *self, PyObject *value, void *closure)
{
    PyObject *args = NULL;
    char *new_value = NULL;

    TraceMethodEnter(self);

    if (value == NULL) {
        if (self->params.cryptoSlotDescription) {
            PyMem_Free(self->params.cryptoSlotDescription);
        }
        self->params.cryptoSlotDescription = NULL;
        return 0;
    }

    if ((args = Py_BuildValue("(O)", value)) == NULL) {
        return -1;
    }

    if (PyArg_ParseTuple(args, "es", "utf-8", &new_value) == -1) {
        Py_DECREF(args);
        PyErr_SetString(PyExc_TypeError, "The crypto_slot_description attribute value must be a string or unicode");
        return -1;
    }

    if (self->params.cryptoSlotDescription) {
        PyMem_Free(self->params.cryptoSlotDescription);
        self->params.cryptoSlotDescription = NULL;
    }

    self->params.cryptoSlotDescription = new_value;
    Py_DECREF(args);
    return 0;
}

static PyObject *
InitParameters_get_db_slot_description(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->params.dbSlotDescription == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeUTF8(self->params.dbSlotDescription, strlen(self->params.dbSlotDescription), NULL);
}

static int
InitParameters_set_db_slot_description(InitParameters *self, PyObject *value, void *closure)
{
    PyObject *args = NULL;
    char *new_value = NULL;

    TraceMethodEnter(self);

    if (value == NULL) {
        if (self->params.dbSlotDescription) {
            PyMem_Free(self->params.dbSlotDescription);
        }
        self->params.dbSlotDescription = NULL;
        return 0;
    }

    if ((args = Py_BuildValue("(O)", value)) == NULL) {
        return -1;
    }

    if (PyArg_ParseTuple(args, "es", "utf-8", &new_value) == -1) {
        Py_DECREF(args);
        PyErr_SetString(PyExc_TypeError, "The db_slot_description attribute value must be a string or unicode");
        return -1;
    }

    if (self->params.dbSlotDescription) {
        PyMem_Free(self->params.dbSlotDescription);
        self->params.dbSlotDescription = NULL;
    }

    self->params.dbSlotDescription = new_value;
    Py_DECREF(args);
    return 0;
}

static PyObject *
InitParameters_get_fips_slot_description(InitParameters *self, void *closure)
{
    TraceMethodEnter(self);

    if (self->params.FIPSSlotDescription == NULL) {
        Py_RETURN_NONE;
    }

    return PyUnicode_DecodeUTF8(self->params.FIPSSlotDescription, strlen(self->params.FIPSSlotDescription), NULL);
}

static int
InitParameters_set_fips_slot_description(InitParameters *self, PyObject *value, void *closure)
{
    PyObject *args = NULL;
    char *new_value = NULL;

    TraceMethodEnter(self);

    if (value == NULL) {
        if (self->params.FIPSSlotDescription) {
            PyMem_Free(self->params.FIPSSlotDescription);
        }
        self->params.FIPSSlotDescription = NULL;
        return 0;
    }

    if ((args = Py_BuildValue("(O)", value)) == NULL) {
        return -1;
    }

    if (PyArg_ParseTuple(args, "es", "utf-8", &new_value) == -1) {
        Py_DECREF(args);
        PyErr_SetString(PyExc_TypeError, "The fips_slot_description attribute value must be a string or unicode");
        return -1;
    }

    if (self->params.FIPSSlotDescription) {
        PyMem_Free(self->params.FIPSSlotDescription);
        self->params.FIPSSlotDescription = NULL;
    }

    self->params.FIPSSlotDescription = new_value;
    Py_DECREF(args);
    return 0;
}

static
PyGetSetDef InitParameters_getseters[] = {
    {"password_required",
     (getter)InitParameters_get_password_required,
     (setter)InitParameters_set_password_required,
     "boolean indicating if a password is required", NULL},

    {"min_password_len",
     (getter)InitParameters_get_min_password_len,
     (setter)InitParameters_set_min_password_len,
     "minimum password length", NULL},

    {"manufacturer_id",
     (getter)InitParameters_get_manufacturer_id,
     (setter)InitParameters_set_manufacturer_id,
     "manufacturer id (max 32 chars)", NULL},

    {"library_description",
     (getter)InitParameters_get_library_description,
     (setter)InitParameters_set_library_description,
     "", NULL},

    {"crypto_token_description",
     (getter)InitParameters_get_crypto_token_description,
     (setter)InitParameters_set_crypto_token_description,
     "", NULL},

    {"db_token_description",
     (getter)InitParameters_get_db_token_description,
     (setter)InitParameters_set_db_token_description,
     "", NULL},

    {"fips_token_description",
     (getter)InitParameters_get_fips_token_description,
     (setter)InitParameters_set_fips_token_description,
     "", NULL},

    {"crypto_slot_description",
     (getter)InitParameters_get_crypto_slot_description,
     (setter)InitParameters_set_crypto_slot_description,
     "", NULL},

    {"db_slot_description",
     (getter)InitParameters_get_db_slot_description,
     (setter)InitParameters_set_db_slot_description,
     "", NULL},

    {"fips_slot_description",
     (getter)InitParameters_get_fips_slot_description,
     (setter)InitParameters_set_fips_slot_description,
     "", NULL},

    {NULL}  /* Sentinel */
};

static PyObject *
InitParameters_format_lines(InitParameters *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if ((obj = InitParameters_get_password_required(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Password Required"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_min_password_len(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Minimum Password Length"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_manufacturer_id(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Manufacturer ID"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_library_description(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Library Description"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_crypto_token_description(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Crypto Token Description"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_db_token_description(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Database Token Description"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_fips_token_description(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("FIPS Token Description"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_crypto_slot_description(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Crypto Slot Description"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_db_slot_description(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Database Slot Description"), obj, level, fail);
    Py_CLEAR(obj);

    if ((obj = InitParameters_get_fips_slot_description(self, NULL)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("FIPS Slot Description"), obj, level, fail);
    Py_CLEAR(obj);

    return lines;

 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
InitParameters_format(InitParameters *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)InitParameters_format_lines, (PyObject *)self, args, kwds);
}

static PyMemberDef InitParameters_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */


static PyMethodDef InitParameters_methods[] = {
    {"format_lines", (PyCFunction)InitParameters_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)InitParameters_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
InitParameters_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    InitParameters *self;

    TraceObjNewEnter(type);

    if ((self = (InitParameters *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    memset(&self->params, 0, sizeof(self->params));
    self->params.length = sizeof(self->params);

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
InitParameters_dealloc(InitParameters* self)
{
    TraceMethodEnter(self);

    if (self->params.manufactureID) {
        PyMem_Free(self->params.manufactureID);
    }
    if (self->params.libraryDescription) {
        PyMem_Free(self->params.libraryDescription);
    }
    if (self->params.cryptoTokenDescription) {
        PyMem_Free(self->params.cryptoTokenDescription);
    }
    if (self->params.dbTokenDescription) {
        PyMem_Free(self->params.dbTokenDescription);
    }
    if (self->params.FIPSTokenDescription) {
        PyMem_Free(self->params.FIPSTokenDescription);
    }
    if (self->params.cryptoSlotDescription) {
        PyMem_Free(self->params.cryptoSlotDescription);
    }
    if (self->params.dbSlotDescription) {
        PyMem_Free(self->params.dbSlotDescription);
    }
    if (self->params.FIPSSlotDescription) {
        PyMem_Free(self->params.FIPSSlotDescription);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(InitParameters_doc,
"An object representing NSS Initialization Parameters");

static int
InitParameters_init(InitParameters *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"password_required",
                             "min_password_len",
                             "manufacturer_id",
                             "library_description",
                             "crypto_token_description",
                             "db_token_description",
                             "fips_token_description",
                             "crypto_slot_description",
                             "db_slot_description",
                             "fips_slot_description",
                             NULL};

    PyObject *py_password_required = NULL;
    PyObject *py_min_password_len = NULL;
    PyObject *py_manufacturer_id = NULL;
    PyObject *py_library_description = NULL;
    PyObject *py_crypto_token_description = NULL;
    PyObject *py_db_token_description = NULL;
    PyObject *py_fips_token_description = NULL;
    PyObject *py_crypto_slot_description = NULL;
    PyObject *py_db_slot_description = NULL;
    PyObject *py_fips_slot_description = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOOOOOOOOO:InitParameters", kwlist,
                                     &py_password_required,
                                     &py_min_password_len,
                                     &py_manufacturer_id,
                                     &py_library_description,
                                     &py_crypto_token_description,
                                     &py_db_token_description,
                                     &py_fips_token_description,
                                     &py_crypto_slot_description,
                                     &py_db_slot_description,
                                     &py_fips_slot_description))
        return -1;

    if (py_password_required) {
        if (InitParameters_set_password_required(self, py_password_required, NULL) == -1) {
            return -1;
        }
    }

    if (py_min_password_len) {
        if (InitParameters_set_min_password_len(self, py_min_password_len, NULL) == -1) {
            return -1;
        }
    }

    if (py_manufacturer_id) {
        if (InitParameters_set_manufacturer_id(self, py_manufacturer_id, NULL) == -1) {
            return -1;
        }
    }

    if (py_library_description) {
        if (InitParameters_set_library_description(self, py_library_description, NULL) == -1) {
            return -1;
        }
    }

    if (py_crypto_token_description) {
        if (InitParameters_set_crypto_token_description(self, py_crypto_token_description, NULL) == -1) {
            return -1;
        }
    }

    if (py_db_token_description) {
        if (InitParameters_set_db_token_description(self, py_db_token_description, NULL) == -1) {
            return -1;
        }
    }

    if (py_fips_token_description) {
        if (InitParameters_set_fips_token_description(self, py_fips_token_description, NULL) == -1) {
            return -1;
        }
    }

    if (py_crypto_slot_description) {
        if (InitParameters_set_crypto_slot_description(self, py_crypto_slot_description, NULL) == -1) {
            return -1;
        }
    }

    if (py_db_slot_description) {
        if (InitParameters_set_db_slot_description(self, py_db_slot_description, NULL) == -1) {
            return -1;
        }
    }

    if (py_fips_slot_description) {
        if (InitParameters_set_fips_slot_description(self, py_fips_slot_description, NULL) == -1) {
            return -1;
        }
    }


    return 0;
}

static PyObject *
InitParameters_str(InitParameters *self)
{
    const char *fmt_str = "password_required=%s, min_password_len=%s, manufacturer_id=%s, library_description=%s, crypto_token_description=%s, db_token_description=%s, fips_token_description=%s, crypto_slot_description=%s, db_slot_description=%s, fips_slot_description=%s";

    PyObject *result = NULL;
    PyObject *fmt = NULL;
    PyObject *args = NULL;
    PyObject *py_password_required = NULL;
    PyObject *py_min_password_len = NULL;
    PyObject *py_manufacturer_id = NULL;
    PyObject *py_library_description = NULL;
    PyObject *py_crypto_token_description = NULL;
    PyObject *py_db_token_description = NULL;
    PyObject *py_fips_token_description = NULL;
    PyObject *py_crypto_slot_description = NULL;
    PyObject *py_db_slot_description = NULL;
    PyObject *py_fips_slot_description = NULL;

    if ((py_password_required = InitParameters_get_password_required(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_min_password_len = InitParameters_get_min_password_len(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_manufacturer_id = InitParameters_get_manufacturer_id(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_library_description = InitParameters_get_library_description(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_crypto_token_description = InitParameters_get_crypto_token_description(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_db_token_description = InitParameters_get_db_token_description(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_fips_token_description = InitParameters_get_fips_token_description(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_crypto_slot_description = InitParameters_get_crypto_slot_description(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_db_slot_description = InitParameters_get_db_slot_description(self, NULL)) == NULL) {
        goto fail;
    }

    if ((py_fips_slot_description = InitParameters_get_fips_slot_description(self, NULL)) == NULL) {
        goto fail;
    }


    if ((fmt = PyString_FromString(fmt_str)) == NULL) {
        goto fail;
    }

    if ((args = PyTuple_New(10)) == NULL) {
        goto fail;
    }

    /*
     * We bump the ref count when inserting into the tuple to simpify clean
     * up. We always DECREF the variable on exit and also DECREF the
     * tuple. When the tuple is deallocated it will DECREF it's members,
     * then subsequently we'll individually DECREF the variable, thus
     * requiring the INCREF when it's inserted into the tuple.
     */
    PyTuple_SetItem(args, 0, py_password_required);        Py_INCREF(py_password_required);
    PyTuple_SetItem(args, 1, py_min_password_len);         Py_INCREF(py_min_password_len);
    PyTuple_SetItem(args, 2, py_manufacturer_id);          Py_INCREF(py_manufacturer_id);
    PyTuple_SetItem(args, 3, py_library_description);      Py_INCREF(py_library_description);
    PyTuple_SetItem(args, 4, py_crypto_token_description); Py_INCREF(py_crypto_token_description);
    PyTuple_SetItem(args, 5, py_db_token_description);     Py_INCREF(py_db_token_description);
    PyTuple_SetItem(args, 6, py_fips_token_description);   Py_INCREF(py_fips_token_description);
    PyTuple_SetItem(args, 7, py_crypto_slot_description);  Py_INCREF(py_crypto_slot_description);
    PyTuple_SetItem(args, 8, py_db_slot_description);      Py_INCREF(py_db_slot_description);
    PyTuple_SetItem(args, 9, py_fips_slot_description);    Py_INCREF(py_fips_slot_description);

    if ((result = PyString_Format(fmt, args)) == NULL) {
        goto fail;
    }

    goto exit;

 fail:
    Py_CLEAR(result);
 exit:
    Py_XDECREF(fmt);
    Py_XDECREF(args);
    Py_XDECREF(py_password_required);
    Py_XDECREF(py_min_password_len);
    Py_XDECREF(py_manufacturer_id);
    Py_XDECREF(py_library_description);
    Py_XDECREF(py_crypto_token_description);
    Py_XDECREF(py_db_token_description);
    Py_XDECREF(py_fips_token_description);
    Py_XDECREF(py_crypto_slot_description);
    Py_XDECREF(py_db_slot_description);
    Py_XDECREF(py_fips_slot_description);

    return result;
}

static PyTypeObject InitParametersType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.InitParameters",			/* tp_name */
    sizeof(InitParameters),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)InitParameters_dealloc,		/* tp_dealloc */
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
    (reprfunc)InitParameters_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    InitParameters_doc,				/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    InitParameters_methods,			/* tp_methods */
    InitParameters_members,			/* tp_members */
    InitParameters_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)InitParameters_init,		/* tp_init */
    0,						/* tp_alloc */
    InitParameters_new,				/* tp_new */
};

/* ========================================================================== */
/* =========================== InitContext Class ============================ */
/* ========================================================================== */

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(InitContext_shutdown_doc,
"shutdown()\n\
\n\
Shutdown NSS for this context.\n\
");

static PyObject *
InitContext_shutdown(InitContext* self)
{
    TraceMethodEnter(self);

    if (NSS_ShutdownContext(self->context) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}


static PyMethodDef InitContext_methods[] = {
    {"shutdown", (PyCFunction)InitContext_shutdown,   METH_NOARGS, InitContext_shutdown_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
InitContext_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    InitContext *self;

    TraceObjNewEnter(type);

    if ((self = (InitContext *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->context = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
InitContext_dealloc(InitContext* self)
{
    TraceMethodEnter(self);

    /*
     * Just in case shutdown_context was not called before the context
     * is destroyed we call it here. If the context was already
     * shutdown NSS_ShutdownContext will fail with
     * SEC_ERROR_NOT_INITIALIZED but we don't bother to check for it.
     */
    NSS_ShutdownContext(self->context);

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(InitContext_doc,
"An object representing NSSInitContext");


static PyObject *
InitContext_repr(InitContext *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject InitContextType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.InitContext",				/* tp_name */
    sizeof(InitContext),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)InitContext_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)InitContext_repr,			/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    0,						/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    InitContext_doc,				/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    InitContext_methods,			/* tp_methods */
    0,						/* tp_members */
    0,						/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    0,						/* tp_init */
    0,						/* tp_alloc */
    0,						/* tp_new */
};

static PyObject *
InitContext_new_from_NSSInitContext(NSSInitContext *context)
{
    InitContext *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (InitContext *) InitContext_new(&InitContextType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->context = context;

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ========================= PKCS12DecodeItem Class ========================= */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
PKCS12DecodeItem_get_type(PKCS12DecodeItem *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->type);
}

static PyObject *
PKCS12DecodeItem_get_has_key(PKCS12DecodeItem *self, void *closure)
{
    TraceMethodEnter(self);

    return PyBool_FromLong(self->has_key);
}

static PyObject *
PKCS12DecodeItem_get_signed_cert_der(PKCS12DecodeItem *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_signed_cert_der);
    return self->py_signed_cert_der;
}

static PyObject *
PKCS12DecodeItem_get_certificate(PKCS12DecodeItem *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_cert);
    return self->py_cert;
}

static PyObject *
PKCS12DecodeItem_get_friendly_name(PKCS12DecodeItem *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_friendly_name);
    return self->py_friendly_name;
}

static PyObject *
PKCS12DecodeItem_get_shroud_algorithm_id(PKCS12DecodeItem *self, void *closure)
{
    TraceMethodEnter(self);

    Py_INCREF(self->py_shroud_algorithm_id);
    return self->py_shroud_algorithm_id;
}

static
PyGetSetDef PKCS12DecodeItem_getseters[] = {
    {"type",                (getter)PKCS12DecodeItem_get_type,                (setter)NULL, "SEC OID tag indicating what type of PKCS12 item this is", NULL},
    {"has_key",             (getter)PKCS12DecodeItem_get_has_key,             (setter)NULL, "boolean indicating if this is a cert with a private key", NULL},
    {"signed_cert_der",     (getter)PKCS12DecodeItem_get_signed_cert_der,     (setter)NULL, "signed certificate DER data as SecItem object, or None if does not exist", NULL},
    {"certificate",         (getter)PKCS12DecodeItem_get_certificate,         (setter)NULL, "certificate as Certificate object, or None if does not exist", NULL},
    {"friendly_name",       (getter)PKCS12DecodeItem_get_friendly_name,       (setter)NULL, "friendly_name as unicode object, or None if does not exist", NULL},
    {"shroud_algorithm_id", (getter)PKCS12DecodeItem_get_shroud_algorithm_id, (setter)NULL, "shroud algorithm id certificate as AlgorithmID object, or None if does not exist", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef PKCS12DecodeItem_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
PKCS12DecodeItem_format_lines(PKCS12DecodeItem *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    obj = oid_tag_name_from_tag(self->type);
    FMT_OBJ_AND_APPEND(lines, _("Type"), obj, level, fail);
    Py_CLEAR(obj);

    switch (self->type) {
    case SEC_OID_PKCS12_V1_CERT_BAG_ID:
        if (self->has_key) {
            FMT_LABEL_AND_APPEND(lines, _("Certificate (has private key)"), level, fail);
        } else {
            FMT_LABEL_AND_APPEND(lines, _("Certificate"), level, fail);
        }
        FMT_OBJ_AND_APPEND(lines, NULL, self->py_cert, level+1, fail);
        obj = SignedData_new_from_SECItem(&((SecItem *)self->py_signed_cert_der)->item);
        FMT_OBJ_AND_APPEND(lines, _("Signature"), obj, level, fail);
        Py_CLEAR(obj);

        FMT_OBJ_AND_APPEND(lines, _("Friendly Name"), self->py_friendly_name, level, fail);
        FMT_OBJ_AND_APPEND(lines, _("Encryption algorithm"), self->py_shroud_algorithm_id, level, fail);
        break;
    case SEC_OID_PKCS12_V1_KEY_BAG_ID:
    case SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID:
        if (self->type == SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID) {
            FMT_LABEL_AND_APPEND(lines, _("Key (shrouded)"), level, fail);
        } else {
            FMT_LABEL_AND_APPEND(lines, _("Key"), level, fail);
        }
        FMT_OBJ_AND_APPEND(lines, _("Friendly Name"), self->py_friendly_name, level, fail);
        FMT_OBJ_AND_APPEND(lines, _("Encryption algorithm"), self->py_shroud_algorithm_id, level, fail);
        break;
    default:
        FMT_LABEL_AND_APPEND(lines, _("unknown bag type"), level, fail);
        break;
    }

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
PKCS12DecodeItem_format(PKCS12DecodeItem *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)PKCS12DecodeItem_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
PKCS12DecodeItem_str(PKCS12DecodeItem *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  PKCS12DecodeItem_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef PKCS12DecodeItem_methods[] = {
    {"format_lines", (PyCFunction)PKCS12DecodeItem_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)PKCS12DecodeItem_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
PKCS12DecodeItem_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PKCS12DecodeItem *self;

    TraceObjNewEnter(type);

    if ((self = (PKCS12DecodeItem *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->type                   = SEC_OID_UNKNOWN;
    self->has_key                = PR_FALSE;
    self->py_signed_cert_der     = NULL;
    self->py_cert                = NULL;
    self->py_friendly_name       = NULL;
    self->py_shroud_algorithm_id = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
PKCS12DecodeItem_traverse(PKCS12DecodeItem *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_signed_cert_der);
    Py_VISIT(self->py_cert);
    Py_VISIT(self->py_friendly_name);
    Py_VISIT(self->py_shroud_algorithm_id);
    return 0;
}

static int
PKCS12DecodeItem_clear(PKCS12DecodeItem* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_signed_cert_der);
    Py_CLEAR(self->py_cert);
    Py_CLEAR(self->py_friendly_name);
    Py_CLEAR(self->py_shroud_algorithm_id);
    return 0;
}

static void
PKCS12DecodeItem_dealloc(PKCS12DecodeItem* self)
{
    TraceMethodEnter(self);

    PKCS12DecodeItem_clear(self);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(PKCS12DecodeItem_doc,
"An object representing an item in a PKCS12 collection.\n\
Also known as a \"bag\"");

static int
PKCS12DecodeItem_init(PKCS12DecodeItem *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"arg", NULL};
    PyObject *arg;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:PKCS12DecodeItem", kwlist,
                                     &arg))
        return -1;

    return 0;
}

static PyObject *
PKCS12DecodeItem_repr(PKCS12DecodeItem *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PyTypeObject PKCS12DecodeItemType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.PKCS12DecodeItem",			/* tp_name */
    sizeof(PKCS12DecodeItem),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)PKCS12DecodeItem_dealloc,	/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)PKCS12DecodeItem_repr,		/* tp_repr */
    0,						/* tp_as_number */
    0,						/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)PKCS12DecodeItem_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    PKCS12DecodeItem_doc,			/* tp_doc */
    (traverseproc)PKCS12DecodeItem_traverse,	/* tp_traverse */
    (inquiry)PKCS12DecodeItem_clear,		/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    PKCS12DecodeItem_methods,			/* tp_methods */
    PKCS12DecodeItem_members,			/* tp_members */
    PKCS12DecodeItem_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)PKCS12DecodeItem_init,		/* tp_init */
    0,						/* tp_alloc */
    PKCS12DecodeItem_new,			/* tp_new */
};

static PyObject *
PKCS12DecodeItem_new_from_SEC_PKCS12DecoderItem(const SEC_PKCS12DecoderItem *item)
{
    PKCS12DecodeItem *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (PKCS12DecodeItem *) PKCS12DecodeItemType.tp_new(&PKCS12DecodeItemType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->type = item->type;
    self->has_key = item->hasKey;

    if (item->der) {
        if ((self->py_signed_cert_der = SecItem_new_from_SECItem(item->der, SECITEM_signed_data)) == NULL) {
            Py_CLEAR(self);
            return NULL;
        }
    } else {
        self->py_signed_cert_der = Py_None;
        Py_INCREF(self->py_signed_cert_der);
    }

    if (item->friendlyName) {
        if ((self->py_friendly_name = PyUnicode_DecodeUTF8((const char *)item->friendlyName->data,
                                                           item->friendlyName->len, NULL)) == NULL) {
            Py_CLEAR(self);
            return NULL;
        }
    } else {
        self->py_friendly_name = Py_None;
        Py_INCREF(self->py_friendly_name);
    }

    if (item->shroudAlg) {
        if ((self->py_shroud_algorithm_id = AlgorithmID_new_from_SECAlgorithmID(item->shroudAlg)) == NULL) {
            Py_CLEAR(self);
            return NULL;
        }
    } else {
        self->py_shroud_algorithm_id = Py_None;
        Py_INCREF(self->py_shroud_algorithm_id);
    }

    if (item->type == SEC_OID_PKCS12_V1_CERT_BAG_ID) {
        if ((self->py_cert = Certificate_new_from_signed_der_secitem(item->der)) == NULL) {
            Py_CLEAR(self);
            return NULL;
        }
    } else {
        self->py_cert = Py_None;
        Py_INCREF(self->py_cert);
    }

    TraceObjNewLeave(self);
    return (PyObject *) self;
}

/* ========================================================================== */
/* ========================== PKCS12Decoder Class =========================== */
/* ========================================================================== */

static SECItem *
PKCS12_default_nickname_collision_callback(SECItem *old_nickname, PRBool *returned_cancel, void *arg)
{
    char *nickname     = NULL;
    SECItem *returned_nickname = NULL;
    CERTCertificate* cert = (CERTCertificate*)arg;

    if (!returned_cancel || !cert) {
	return NULL;
    }

    if ((nickname = CERT_MakeCANickname(cert)) == NULL) {
    	return NULL;
    }

    if (old_nickname && old_nickname->data && old_nickname->len &&
       PORT_Strlen(nickname) == old_nickname->len &&
       PORT_Strncmp((char *)old_nickname->data, nickname, old_nickname->len) == 0) {
	PORT_Free(nickname);
	PORT_SetError(SEC_ERROR_CERT_NICKNAME_COLLISION);
        PySys_WriteStderr("PKCS12_default_nickname_collision_callback: CERT_MakeCANickname() returned existing nickname\n");
	return NULL;
    }

    if ((returned_nickname = PORT_ZNew(SECItem)) == NULL) {
	PORT_Free(nickname);
	return NULL;
    }

    returned_nickname->data = (unsigned char *)nickname;
    returned_nickname->len = PORT_Strlen(nickname);

    return returned_nickname;
}

static SECItem *
PKCS12_nickname_collision_callback(SECItem *old_nickname, PRBool *returned_cancel, void *arg)
{
    CERTCertificate* cert = NULL;
    PyGILState_STATE gstate;
    PyObject *nickname_collision_callback = NULL;
    PyObject *py_old_nickname = NULL;
    PyObject *py_cert = NULL;
    PyObject *result = NULL;
    PyObject *new_args = NULL;
    PyObject *py_new_nickname = NULL;
    PyObject *py_new_nickname_utf8 = NULL;
    PRBool cancel = PR_TRUE;
    PyObject *py_cancel = NULL;
    SECItem *returned_nickname = NULL;

    gstate = PyGILState_Ensure();

    TraceMessage("PKCS12_nickname_collision_callback: enter");

    if ((nickname_collision_callback = get_thread_local("nickname_collision_callback")) == NULL) {
        if (!PyErr_Occurred()) {
            PySys_WriteStderr("PKCS12 nickname collision callback undefined\n");
        } else {
            PyErr_Print();
        }
	PyGILState_Release(gstate);
        return NULL;
    }

    if (!old_nickname || !old_nickname->len || !old_nickname->data) {
        py_old_nickname = Py_None;
        Py_INCREF(py_old_nickname);
    } else {
        py_old_nickname = PyString_FromStringAndSize((char *)old_nickname->data, old_nickname->len);
    }

    cert = (CERTCertificate*)arg;
    if ((py_cert = Certificate_new_from_CERTCertificate(cert, true)) == NULL) {
        Py_DECREF(py_old_nickname);
        return NULL;
    }

    if ((new_args = PyTuple_New(2)) == NULL) {
        PySys_WriteStderr("PKCS12 nickname collision callback: out of memory\n");
        goto exit;
    }

    PyTuple_SetItem(new_args, 0, py_old_nickname);
    PyTuple_SetItem(new_args, 1, py_cert);

    if ((result = PyObject_CallObject(nickname_collision_callback, new_args)) == NULL) {
        PySys_WriteStderr("exception in PKCS12 nickname collision callback\n");
        PyErr_Print();  /* this also clears the error */
        goto exit;
    }

    if (!PyTuple_Check(result) || PyTuple_Size(result) != 2) {
        PySys_WriteStderr("Error, PKCS12 nickname collision callback expected tuple result with 2 values.\n");
        goto exit;
    }

    py_new_nickname = PyTuple_GetItem(result, 0);
    py_cancel       = PyTuple_GetItem(result, 1);

    if (!(PyString_Check(py_new_nickname) || PyUnicode_Check(py_new_nickname) ||
          PyNone_Check(py_new_nickname))) {
        PySys_WriteStderr("Error, PKCS12 nickname collision callback expected 1st returned item to be string or None.\n");
        goto exit;
    }

    if (PyBool_Check(py_cancel)) {
        cancel = PyBoolAsPRBool(py_cancel);
    } else {
        PySys_WriteStderr("Error, PKCS12 nickname collision callback expected 2nd returned item to be boolean.\n");
        goto exit;
    }

    if (PyString_Check(py_new_nickname) || PyUnicode_Check(py_new_nickname)) {
        if (PyString_Check(py_new_nickname)) {
            py_new_nickname_utf8 = py_new_nickname;
            Py_INCREF(py_new_nickname_utf8);
        } else {
            py_new_nickname_utf8 = PyUnicode_AsUTF8String(py_new_nickname);
        }

        if ((returned_nickname = PORT_New(SECItem)) == NULL) {
            PyErr_NoMemory();
            goto exit;
        }

        returned_nickname->data = (unsigned char *)PORT_Strdup(PyString_AsString(py_new_nickname_utf8));
        returned_nickname->len = PyString_Size(py_new_nickname_utf8);
    }


 exit:
    TraceMessage("PKCS12_nickname_collision_callback: exiting");

    Py_XDECREF(new_args);
    Py_XDECREF(result);
    Py_XDECREF(py_new_nickname_utf8);

    PyGILState_Release(gstate);

    *returned_cancel = cancel;
    return returned_nickname;
}

PyDoc_STRVAR(PKCS12_pkcs12_set_nickname_collision_callback_doc,
"pkcs12_set_nickname_collision_callback(callback)\n\
\n\
:Parameters:\n\
    callback : function pointer\n\
        The callback function\n\
\n\
When importing a certificate via a `PKCS12Decoder` object and the\n\
nickname is not set or collides with an existing nickname in the NSS\n\
database then this callback is invoked to resolve the problem. If no\n\
nickname collision callback has been set then an internal default\n\
callback will be used instead which calls the NSS function CERT_MakeCANickname\n\
(available in the Python binding as `Certificate.make_ca_nickname()`).\n\
\n\
The callback has the signature::\n\
    \n\
    nickname_collision_callback(old_nickname, cert) --> new_nickname, cancel\n\
\n\
old_nickname\n\
    the preious nickname or None if previous did not exist\n\
cert\n\
    the `Certificate` object being imported.\n\
\n\
The callback returns 2 values, the new nickname, and a boolean.\n\
\n\
    new_nickname\n\
        The new nickname to try or None\n\
\n\
    cancel\n\
        boolean indicating if collision resolution should be cancelled\n\
\n\
");

static PyObject *
PKCS12_pkcs12_set_nickname_collision_callback(PyObject *self, PyObject *args)
{
    PyObject *callback;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:pkcs12_set_nickname_collision_callback", &callback)) {
        return NULL;
    }

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }

    if (set_thread_local("nickname_collision_callback", callback) < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}

/* ============================ Attribute Access ============================ */

static
PyGetSetDef PKCS12Decoder_getseters[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef PKCS12Decoder_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

PyDoc_STRVAR(PKCS12Decoder_database_import_doc,
"import()\n\
\n\
Import the contents of the `PKCS12Decoder` object into the current NSS database.\n\
\n\
During import if the certificate(s) in the `PKCS12Decoder` object does\n\
not have a nickname or there is a collision with an existing nickname\n\
then a callback will be invoked to provide a new nickname. See\n\
`pkcs12_set_nickname_collision_callback`.\n\
\n\
");

static PyObject *
PKCS12Decoder_database_import(PKCS12Decoder *self, PyObject *args)
{
    SEC_PKCS12NicknameCollisionCallback nickname_callback = NULL;

    TraceMethodEnter(self);

    if (get_thread_local("nickname_collision_callback") == NULL) {
        nickname_callback = PKCS12_default_nickname_collision_callback;
    } else {
        nickname_callback = PKCS12_nickname_collision_callback;
    }

    if (SEC_PKCS12DecoderValidateBags(self->decoder_ctx, nickname_callback) != SECSuccess) {
        return set_nspr_error("PKCS12 decode validate bags failed");
    }

    if (SEC_PKCS12DecoderImportBags(self->decoder_ctx) != SECSuccess) {
        return set_nspr_error("PKCS12 decode import bags failed");
    }

    Py_RETURN_NONE;
}

static PyObject *
PKCS12Decoder_format_lines(PKCS12Decoder *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    char *msg = NULL;
    PyObject *obj = NULL;
    Py_ssize_t i, n_items;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    n_items = PyTuple_Size(self->py_decode_items);

    msg = PR_smprintf(_("%d PKCS12 Decode Items"), n_items);
    FMT_LABEL_AND_APPEND(lines, msg, level, fail);
    PR_smprintf_free(msg);

    for (i = 0; i < n_items; i++) {
        msg = PR_smprintf(_("Item %d"), i+1);
        FMT_LABEL_AND_APPEND(lines, msg, level, fail);
        PR_smprintf_free(msg);

        obj = PKCS12Decoder_item(self, i);
        CALL_FORMAT_LINES_AND_APPEND(lines, obj, level+1, fail);
        Py_CLEAR(obj);

        if (i < n_items-1) {    /* blank separator line */
            FMT_LABEL_AND_APPEND(lines, NULL, level, fail);
        }

    }

    return lines;
 fail:
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
PKCS12Decoder_format(PKCS12Decoder *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)PKCS12Decoder_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
PKCS12Decoder_str(PKCS12Decoder *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  PKCS12Decoder_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef PKCS12Decoder_methods[] = {
    {"database_import", (PyCFunction)PKCS12Decoder_database_import, METH_NOARGS,                PKCS12Decoder_database_import_doc},
    {"format_lines",    (PyCFunction)PKCS12Decoder_format_lines,    METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",          (PyCFunction)PKCS12Decoder_format,          METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Sequence Protocol ============================ */

static Py_ssize_t
PKCS12Decoder_length(PKCS12Decoder *self)
{
    if (!self->py_decode_items) return 0;
    return PyTuple_Size(self->py_decode_items);
}

static PyObject *
PKCS12Decoder_item(PKCS12Decoder *self, register Py_ssize_t i)
{
    PyObject *py_decode_item = NULL;

    if (!self->py_decode_items) {
        return PyErr_Format(PyExc_ValueError, "%s is uninitialized", Py_TYPE(self)->tp_name);
    }
    py_decode_item = PyTuple_GetItem(self->py_decode_items, i);
    Py_XINCREF(py_decode_item);
    return py_decode_item;
}

/* =========================== Class Construction =========================== */

static PyObject *
PKCS12Decoder_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PKCS12Decoder *self;

    TraceObjNewEnter(type);

    if ((self = (PKCS12Decoder *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    self->ucs2_password_item = NULL;
    self->decoder_ctx = NULL;
    self->py_decode_items = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static int
PKCS12Decoder_traverse(PKCS12Decoder *self, visitproc visit, void *arg)
{
    Py_VISIT(self->py_decode_items);
    return 0;
}

static int
PKCS12Decoder_clear(PKCS12Decoder* self)
{
    TraceMethodEnter(self);

    Py_CLEAR(self->py_decode_items);
    return 0;
}

static void
PKCS12Decoder_dealloc(PKCS12Decoder* self)
{
    TraceMethodEnter(self);

    if (self->ucs2_password_item) {
        SECITEM_ZfreeItem(self->ucs2_password_item, PR_TRUE);
    }
    if (self->decoder_ctx) {
	SEC_PKCS12DecoderFinish(self->decoder_ctx);
    }

    PKCS12Decoder_clear(self);
    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(PKCS12Decoder_doc,
"PKCS12Decoder(file, password, slot=None)\n\
\n\
:Parameters:\n\
    file : file name or file object\n\
        pkcs12 input data.\n\
\n\
            * If string treat as file path to open and read.\n\
            * If file object read from the file object.\n\
    password : string\n\
        The password protecting the PKCS12 contents\n\
    slot : `PK11Slot` object\n\
        The PK11 slot to use. If None defaults to internal\n\
        slot, see `nss.get_internal_key_slot()`\n\
\n\
");

static int
PKCS12Decoder_init(PKCS12Decoder *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"file", "password", "slot", NULL};
    PyObject *file_arg = NULL;
    PyObject *py_file_contents = NULL;
    PyObject *py_slot = Py_None;
    char *utf8_password = NULL;
    size_t utf8_password_len = 0;
    unsigned int ucs2_password_alloc_len = 0;

    char *slot_password = NULL;
    PK11SlotInfo *slot = NULL;
    int num_decode_items = 0;
    const SEC_PKCS12DecoderItem *decoder_item = NULL;
    PyObject *py_decode_item = NULL;
    int item_idx;
    int result = 0;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oes|O&:PKCS12Decoder", kwlist,
                                     &file_arg, "utf-8", &utf8_password,
                                     PK11SlotOrNoneConvert, &py_slot)) {
        return -1;
    }


    if ((py_file_contents = read_data_from_file(file_arg)) == NULL) {
        result = -1;
        goto exit;
    }

    /*
     * The +1 for the utf8 password is for the null terminator which is used
     * in the computation of the symetric key. Therefore the conversion to
     * ucs2 must include the null terminator. It's safe for us to read the
     * null terminator at the end of the string Python provides because Python
     * always provides a 1 byte null terminator for all of it's string allocations.
     */
    utf8_password_len = strlen(utf8_password) + 1;
    ucs2_password_alloc_len = utf8_password_len * 2;

    if ((self->ucs2_password_item =
         SECITEM_AllocItem(NULL, NULL, ucs2_password_alloc_len)) == NULL) {
        set_nspr_error(NULL);
        result = -1;
        goto exit;
    }

    if (!PORT_UCS2_UTF8Conversion(PR_TRUE, (unsigned char *)utf8_password, utf8_password_len,
                                  self->ucs2_password_item->data, ucs2_password_alloc_len,
                                  &self->ucs2_password_item->len)) {
        PyErr_SetString(PyExc_ValueError, "password conversion to UCS2 failed");
        result = -1;
        goto exit;
    }

    if (PyNone_Check(py_slot)) {
	slot = PK11_GetInternalKeySlot();
    } else {
        slot = ((PK11Slot *)py_slot)->slot;
    }

    if ((self->decoder_ctx = SEC_PKCS12DecoderStart(self->ucs2_password_item,
                                         slot,
                                         slot_password,
                                         NULL, NULL, NULL, NULL, NULL)) == NULL) {
        set_nspr_error("PKCS12 decoder start failed");
        result = -1;
        goto exit;
    }

    /* decode the item */
    if (SEC_PKCS12DecoderUpdate(self->decoder_ctx,
                                (unsigned char *)PyString_AS_STRING(py_file_contents),
                                PyString_GET_SIZE(py_file_contents)) != SECSuccess) {
        set_nspr_error("PKCS12 decoding failed");
        result = -1;
        goto exit;
    }

    /* does the blob authenticate properly? */
    if ((SEC_PKCS12DecoderVerify(self->decoder_ctx) != SECSuccess)) {
        set_nspr_error("PKCS12 decode not verified");
        result = -1;
        goto exit;
    }

    if (SEC_PKCS12DecoderIterateInit(self->decoder_ctx) != SECSuccess) {
        set_nspr_error("PKCS12 item iteration failed");
        result = -1;
        goto exit;
    }

    num_decode_items = 0;
    while (SEC_PKCS12DecoderIterateNext(self->decoder_ctx, &decoder_item) == SECSuccess) {
        num_decode_items++;
    }
    if ((self->py_decode_items = PyTuple_New(num_decode_items)) == NULL) {
        result = -1;
        goto exit;
    }

    if (SEC_PKCS12DecoderIterateInit(self->decoder_ctx) != SECSuccess) {
        set_nspr_error("PKCS12 item iteration failed");
        result = -1;
        goto exit;
    }

    for (item_idx = 0;
         SEC_PKCS12DecoderIterateNext(self->decoder_ctx, &decoder_item) == SECSuccess;
         item_idx++) {
        if ((py_decode_item = PKCS12DecodeItem_new_from_SEC_PKCS12DecoderItem(decoder_item)) == NULL) {
            result = -1;
            goto exit;
        }
        PyTuple_SetItem(self->py_decode_items, item_idx, py_decode_item);
    }

 exit:
    if (!py_slot && slot) {
    	PK11_FreeSlot(slot);
    }

    if (utf8_password)
        PyMem_Free(utf8_password);
    if (py_file_contents)
        Py_DECREF(py_file_contents);

    return result;
}

static PyObject *
PKCS12Decoder_repr(PKCS12Decoder *self)
{
    return PyString_FromFormat("<%s object at %p>",
                               Py_TYPE(self)->tp_name, self);
}

static PySequenceMethods PKCS12Decoder_as_sequence = {
    (lenfunc)PKCS12Decoder_length,		/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)PKCS12Decoder_item,		/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyTypeObject PKCS12DecoderType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.PKCS12Decoder",			/* tp_name */
    sizeof(PKCS12Decoder),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)PKCS12Decoder_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    (reprfunc)PKCS12Decoder_repr,		/* tp_repr */
    0,						/* tp_as_number */
    &PKCS12Decoder_as_sequence,			/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)PKCS12Decoder_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
    PKCS12Decoder_doc,				/* tp_doc */
    (traverseproc)PKCS12Decoder_traverse,	/* tp_traverse */
    (inquiry)PKCS12Decoder_clear,		/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    PKCS12Decoder_methods,			/* tp_methods */
    PKCS12Decoder_members,			/* tp_members */
    PKCS12Decoder_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    (initproc)PKCS12Decoder_init,		/* tp_init */
    0,						/* tp_alloc */
    PKCS12Decoder_new,				/* tp_new */
};


/* ========================================================================== */
/* ======================== CertVerifyLogNode Class ========================= */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
CertVerifyLogNode_get_certificate(CertVerifyLogNode *self, void *closure)
{
    TraceMethodEnter(self);

    return Certificate_new_from_CERTCertificate(self->node.cert, true);
}

static PyObject *
CertVerifyLogNode_get_error(CertVerifyLogNode *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->node.error);
}

static PyObject *
CertVerifyLogNode_get_depth(CertVerifyLogNode *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->node.depth);
}

static
PyGetSetDef CertVerifyLogNode_getseters[] = {
    {"certificate", (getter)CertVerifyLogNode_get_certificate, NULL,
     "returns the certificate as a `Certificate` object", NULL},
    {"error", (getter)CertVerifyLogNode_get_error, NULL,
     "returns the error code as an integer", NULL},
    {"depth", (getter)CertVerifyLogNode_get_depth, NULL,
     "returns the chain position as an integer", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef CertVerifyLogNode_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
CertVerifyLogNodeError_format_lines(CertVerifyLogNode *self, int level, PyObject *lines)
{
    RepresentationKind repr_kind = AsEnumName;
    PyObject *obj = NULL;
    PyObject *py_cert = NULL;
    NSPRErrorDesc const *error_desc = NULL;
    CERTVerifyLogNode *node = NULL;

    if (!lines) {
        goto fail;
    }

    node = &self->node;

    if ((error_desc = lookup_nspr_error(node->error)) == NULL) {
        if ((obj = PyString_FromFormat(_("Unknown error code %ld (%#lx)"),
                                       node->error, node->error)) == NULL) {
            goto fail;
        }
    } else {
        if ((obj = PyString_FromFormat("[%s] %s",
                                       error_desc->name,
                                       error_desc->string)) == NULL) {
            goto fail;
        }
    }
    FMT_OBJ_AND_APPEND(lines, _("Error"), obj, level, fail);
    Py_CLEAR(obj);

    switch (node->error) {
    case SEC_ERROR_INADEQUATE_KEY_USAGE: {
        // NSS WART - pointers and ints are not the same thing
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
        unsigned int flags = (unsigned int)node->arg;
#pragma GCC diagnostic pop

        if ((obj = key_usage_flags(flags, repr_kind)) == NULL) {
            goto fail;
        }
        FMT_OBJ_AND_APPEND(lines, _("Inadequate Key Usage"), obj, level, fail);
        Py_CLEAR(obj);
    } break;
    case SEC_ERROR_INADEQUATE_CERT_TYPE: {
        // NSS WART - pointers and ints are not the same thing
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
        unsigned int flags = (unsigned int)node->arg;
#pragma GCC diagnostic pop

        if ((obj = cert_type_flags(flags, repr_kind)) == NULL) {
            goto fail;
        }
        FMT_OBJ_AND_APPEND(lines, _("Inadequate Cert Type"), obj, level, fail);
        Py_CLEAR(obj);
    } break;
    case SEC_ERROR_UNKNOWN_ISSUER:
    case SEC_ERROR_UNTRUSTED_ISSUER:
    case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:
        if ((py_cert = Certificate_new_from_CERTCertificate(node->cert, true)) == NULL) {
            goto fail;
        }
        if ((obj = Certificate_get_issuer((Certificate *)py_cert, NULL)) == NULL) {
            goto fail;
        }
        Py_CLEAR(py_cert);

        FMT_OBJ_AND_APPEND(lines, _("Issuer"), obj, level, fail);
        Py_CLEAR(obj);
        break;
    default:
        break;
    }

    return lines;
 fail:
    Py_XDECREF(py_cert);
    Py_XDECREF(obj);
    return NULL;
}

static PyObject *
CertVerifyLogNode_format_lines(CertVerifyLogNode *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    Certificate *py_cert = NULL;
    CERTVerifyLogNode *node = NULL;

    TraceMethodEnter(self);

    node = &self->node;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    FMT_LABEL_AND_APPEND(lines, _("Certificate"), level, fail);

    if ((py_cert = (Certificate *)Certificate_new_from_CERTCertificate(node->cert, true)) == NULL) {
        goto fail;
    }

    if (Certificate_summary_format_lines(py_cert, level+1, lines) == NULL) {
        goto fail;
    }
    Py_CLEAR(py_cert);

    if ((obj = PyInt_FromLong(node->depth)) == NULL){
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Depth"), obj, level, fail);
    Py_CLEAR(obj);

    if (CertVerifyLogNodeError_format_lines(self, level, lines) == NULL) {
        goto fail;
    }

    return lines;
 fail:
    Py_XDECREF(py_cert);
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
CertVerifyLogNode_format(CertVerifyLogNode *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)CertVerifyLogNode_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
CertVerifyLogNode_str(CertVerifyLogNode *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  CertVerifyLogNode_format(self, empty_tuple, NULL);
    return py_formatted_result;

}


static PyMethodDef CertVerifyLogNode_methods[] = {
    {"format_lines", (PyCFunction)CertVerifyLogNode_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)CertVerifyLogNode_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Class Construction =========================== */

static PyObject *
CertVerifyLogNode_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    CertVerifyLogNode *self;

    TraceObjNewEnter(type);

    if ((self = (CertVerifyLogNode *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    memset(&self->node, 0, sizeof(self->node));

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
CertVerifyLogNode_dealloc(CertVerifyLogNode* self)
{
    TraceMethodEnter(self);

    if (self->node.cert) {
        CERT_DestroyCertificate(self->node.cert);
    }

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(CertVerifyLogNode_doc,
"CertVerifyLogNode()\n\
\n\
An object detailing specific diagnostic information concerning\n\
a single failure during certification validation.\n\
These are collected in a `CertVerifyLog` object.\n\
");

static PyTypeObject CertVerifyLogNodeType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.CertVerifyLogNode",				/* tp_name */
    sizeof(CertVerifyLogNode),				/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CertVerifyLogNode_dealloc,		/* tp_dealloc */
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
    (reprfunc)CertVerifyLogNode_str,			/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    CertVerifyLogNode_doc,				/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    CertVerifyLogNode_methods,				/* tp_methods */
    CertVerifyLogNode_members,				/* tp_members */
    CertVerifyLogNode_getseters,				/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    0,						/* tp_init */
    0,						/* tp_alloc */
    CertVerifyLogNode_new,			/* tp_new */
};

static PyObject *
CertVerifyLogNode_new_from_CERTVerifyLogNode(CERTVerifyLogNode *node)
{
    CertVerifyLogNode *self = NULL;

    TraceObjNewEnter(NULL);

    if ((self = (CertVerifyLogNode *) CertVerifyLogNodeType.tp_new(&CertVerifyLogNodeType, NULL, NULL)) == NULL) {
        return NULL;
    }

    self->node.cert  = CERT_DupCertificate(node->cert);
    self->node.error = node->error;
    self->node.depth = node->depth;
    self->node.arg   = node->arg;
    self->node.next  = NULL;
    self->node.prev  = NULL;

    TraceObjNewLeave(self);

    return (PyObject *) self;
}
/* ========================================================================== */
/* ========================== CertVerifyLog Class =========================== */
/* ========================================================================== */

/* ============================ Attribute Access ============================ */

static PyObject *
CertVerifyLog_get_count(CertVerifyLog *self, void *closure)
{
    TraceMethodEnter(self);

    return PyInt_FromLong(self->log.count);
}

static
PyGetSetDef CertVerifyLog_getseters[] = {
    {"count", (getter)CertVerifyLog_get_count,    NULL,
     "number of validation errors", NULL},
    {NULL}  /* Sentinel */
};

static PyMemberDef CertVerifyLog_members[] = {
    {NULL}  /* Sentinel */
};

/* ============================== Class Methods ============================= */

static PyObject *
CertVerifyLog_format_lines(CertVerifyLog *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"level", NULL};
    int level = 0;
    PyObject *lines = NULL;
    PyObject *obj = NULL;
    Py_ssize_t i, n_items;
    unsigned int depth = ~0;
    CertVerifyLogNode *py_node = NULL;
    Certificate *py_cert = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i:format_lines", kwlist, &level))
        return NULL;

    if ((lines = PyList_New(0)) == NULL) {
        return NULL;
    }

    if ((obj = PyInt_FromLong(self->log.count)) == NULL) {
        goto fail;
    }
    FMT_OBJ_AND_APPEND(lines, _("Validation Errors"), obj, level, fail);
    Py_CLEAR(obj);


    n_items = CertVerifyLog_length(self);

    for (i = 0; i < n_items; i++) {
        CERTVerifyLogNode *node = NULL;

        py_node = (CertVerifyLogNode *)CertVerifyLog_item(self, i);
        node = &py_node->node;

        if (depth != node->depth) {
            depth = node->depth;

            if ((obj = PyString_FromFormat(_("Certificate at chain depth %u"), node->depth)) == NULL) {
                goto fail;
            }
            FMT_LABEL_AND_APPEND(lines, PyString_AsString(obj), level, fail);
            Py_CLEAR(obj);

            if ((py_cert = (Certificate *)Certificate_new_from_CERTCertificate(node->cert, true)) == NULL) {
                goto fail;
            }

            if (Certificate_summary_format_lines(py_cert, level+1, lines) == NULL) {
                goto fail;
            }

            Py_CLEAR(py_cert);

            /* Add blank line between cert and errors */
            FMT_LABEL_AND_APPEND(lines, NULL, level, fail);
        }

        if ((obj = PyString_FromFormat(_("Validation Error #%zd"), i+1)) == NULL) {
            goto fail;
        }
        FMT_LABEL_AND_APPEND(lines, PyString_AsString(obj), level+1, fail);
        Py_CLEAR(obj);

        if (CertVerifyLogNodeError_format_lines(py_node, level+2, lines) == NULL) {
            goto fail;
        }

        Py_CLEAR(py_node);

        //if (i < n_items-1) {    /* blank separator line */
        //    FMT_LABEL_AND_APPEND(lines, NULL, level, fail);
        //}

    }

    return lines;
 fail:
    Py_XDECREF(py_node);
    Py_XDECREF(py_cert);
    Py_XDECREF(obj);
    Py_XDECREF(lines);
    return NULL;
}

static PyObject *
CertVerifyLog_format(CertVerifyLog *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    return format_from_lines((format_lines_func)CertVerifyLog_format_lines, (PyObject *)self, args, kwds);
}

static PyObject *
CertVerifyLog_str(CertVerifyLog *self)
{
    PyObject *py_formatted_result = NULL;

    TraceMethodEnter(self);

    py_formatted_result =  CertVerifyLog_format(self, empty_tuple, NULL);
    return py_formatted_result;

}

static PyMethodDef CertVerifyLog_methods[] = {
    {"format_lines", (PyCFunction)CertVerifyLog_format_lines,   METH_VARARGS|METH_KEYWORDS, generic_format_lines_doc},
    {"format",       (PyCFunction)CertVerifyLog_format,         METH_VARARGS|METH_KEYWORDS, generic_format_doc},
    {NULL, NULL}  /* Sentinel */
};

/* =========================== Sequence Protocol ============================ */
static Py_ssize_t
CertVerifyLog_length(CertVerifyLog *self)
{
    return self->log.count;
}

static PyObject *
CertVerifyLog_item(CertVerifyLog *self, register Py_ssize_t i)
{
    CERTVerifyLogNode *node = NULL;
    Py_ssize_t index;

    for (node = self->log.head, index = 0;
         node && index <= i;
         node = node->next, index++) {
        if (i == index) {
            return CertVerifyLogNode_new_from_CERTVerifyLogNode(node);
        }
    }

    PyErr_SetString(PyExc_IndexError, "CertVerifyLog index out of range");
    return NULL;
}


/* =========================== Class Construction =========================== */

static PyObject *
CertVerifyLog_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    CertVerifyLog *self;

    TraceObjNewEnter(type);

    if ((self = (CertVerifyLog *)type->tp_alloc(type, 0)) == NULL) {
        return NULL;
    }

    if ((self->log.arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL) {
        type->tp_free(self);
        return set_nspr_error(NULL);
    }

    self->log.count = 0;
    self->log.head = NULL;
    self->log.tail = NULL;

    TraceObjNewLeave(self);
    return (PyObject *)self;
}

static void
CertVerifyLog_dealloc(CertVerifyLog* self)
{
    CERTVerifyLogNode *node = NULL;

    TraceMethodEnter(self);

    for (node = self->log.head; node; node = node->next) {
        if (node->cert) {
            CERT_DestroyCertificate(node->cert);
        }
    }
    PORT_FreeArena(self->log.arena, PR_FALSE);

    self->ob_type->tp_free((PyObject*)self);
}

PyDoc_STRVAR(CertVerifyLog_doc,
"CertVerifyLog()\n\
\n\
An object which collects diagnostic information during\n\
certification validation.\n\
");

static PySequenceMethods CertVerifyLog_as_sequence = {
    (lenfunc)CertVerifyLog_length,		/* sq_length */
    0,						/* sq_concat */
    0,						/* sq_repeat */
    (ssizeargfunc)CertVerifyLog_item,		/* sq_item */
    0,						/* sq_slice */
    0,						/* sq_ass_item */
    0,						/* sq_ass_slice */
    0,						/* sq_contains */
    0,						/* sq_inplace_concat */
    0,						/* sq_inplace_repeat */
};

static PyTypeObject CertVerifyLogType = {
    PyObject_HEAD_INIT(NULL)
    0,						/* ob_size */
    "nss.nss.CertVerifyLog",			/* tp_name */
    sizeof(CertVerifyLog),			/* tp_basicsize */
    0,						/* tp_itemsize */
    (destructor)CertVerifyLog_dealloc,		/* tp_dealloc */
    0,						/* tp_print */
    0,						/* tp_getattr */
    0,						/* tp_setattr */
    0,						/* tp_compare */
    0,						/* tp_repr */
    0,						/* tp_as_number */
    &CertVerifyLog_as_sequence,			/* tp_as_sequence */
    0,						/* tp_as_mapping */
    0,						/* tp_hash */
    0,						/* tp_call */
    (reprfunc)CertVerifyLog_str,		/* tp_str */
    0,						/* tp_getattro */
    0,						/* tp_setattro */
    0,						/* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
    CertVerifyLog_doc,				/* tp_doc */
    (traverseproc)0,				/* tp_traverse */
    (inquiry)0,					/* tp_clear */
    0,						/* tp_richcompare */
    0,						/* tp_weaklistoffset */
    0,						/* tp_iter */
    0,						/* tp_iternext */
    CertVerifyLog_methods,			/* tp_methods */
    CertVerifyLog_members,			/* tp_members */
    CertVerifyLog_getseters,			/* tp_getset */
    0,						/* tp_base */
    0,						/* tp_dict */
    0,						/* tp_descr_get */
    0,						/* tp_descr_set */
    0,						/* tp_dictoffset */
    0,						/* tp_init */
    0,						/* tp_alloc */
    CertVerifyLog_new,				/* tp_new */
};
/* ========================== PK11 Methods =========================== */

static char *
PK11_password_callback(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    PyGILState_STATE gstate;
    Py_ssize_t n_base_args = 2;
    PyObject *password_callback = NULL;
    PyObject *pin_args = arg; /* borrowed reference, don't decrement */
    PyObject *py_slot = NULL;
    PyObject *item;
    PyObject *result = NULL;
    PyObject *new_args = NULL;
    Py_ssize_t argc;
    int i, j;
    char *password = NULL;

    gstate = PyGILState_Ensure();

    TraceMessage("PK11_password_callback: enter");

    if ((password_callback = get_thread_local("password_callback")) == NULL) {
        if (!PyErr_Occurred()) {
            PySys_WriteStderr("PK11 password callback undefined\n");
        } else {
            PyErr_Print();
        }
	PyGILState_Release(gstate);
        return NULL;
    }

    argc = n_base_args;
    if (pin_args) {
        if (PyTuple_Check(pin_args)) {
            argc += PyTuple_Size(pin_args);
        } else {
            PySys_WriteStderr("Error, PK11 password callback expected args to be tuple\n");
            PyErr_Print();
        }
    }

    if ((new_args = PyTuple_New(argc)) == NULL) {
        PySys_WriteStderr("PK11 password callback: out of memory\n");
        goto exit;
    }

    if ((py_slot = PK11Slot_new_from_PK11SlotInfo(slot)) == NULL) {
        PySys_WriteStderr("exception in PK11 password callback\n");
        PyErr_Print();
        goto exit;
    }
    /*
     * Every NSS function that returns a slot has it's reference count
     * incremented. We wrap that slot in a PK11Slot Python object and
     * when the PK11Slot Python object is deallocated we decrement the
     * NSS slot reference count by calling PK11_FreeSlot.
     *
     * However in this callback we're not returned a slot, rather we
     * are passed a slot, it's reference count has not been
     * incremented. But we still wrap the NSS slot with a PK11Slot
     * Python object which when deallocated will decrement the NSS
     * slot reference count. Therefore we increment the NSS slots
     * reference count by calling PK11_ReferenceSlot.
     */
    PK11_ReferenceSlot(((PK11Slot *)py_slot)->slot);

    PyTuple_SetItem(new_args, 0, py_slot);
    PyTuple_SetItem(new_args, 1, PyBool_FromLong(retry));

    for (i = n_base_args, j = 0; i < argc; i++, j++) {
        item = PyTuple_GetItem(pin_args, j);
        Py_INCREF(item);
        PyTuple_SetItem(new_args, i, item);
    }

    if ((result = PyObject_CallObject(password_callback, new_args)) == NULL) {
        PySys_WriteStderr("exception in PK11 password callback\n");
        PyErr_Print();  /* this also clears the error */
        goto exit;
    }

    if (PyString_Check(result) || PyUnicode_Check(result)) {
        PyObject *py_password = NULL;

        if ((py_password = PyString_UTF8(result, "PK11 password callback result")) != NULL) {
            password = PORT_Strdup(PyString_AsString(py_password));
            Py_DECREF(py_password);
        } else {
            goto exit;
        }
    } else if (PyNone_Check(result)) {
        password = NULL;
    } else {
        PySys_WriteStderr("Error, PK11 password callback expected string result or None.\n");
        goto exit;
    }

 exit:
    TraceMessage("PK11_password_callback: exiting");

    Py_XDECREF(new_args);
    Py_XDECREF(result);

    PyGILState_Release(gstate);

    return password;
}

/* ========================================================================== */
/* ========================= Global PK11 Functions ========================== */
/* ========================================================================== */

PyDoc_STRVAR(pk11_set_password_callback_doc,
"set_password_callback(callback)\n\
\n\
:Parameters:\n\
    callback : function pointer\n\
        The callback function\n\
        \n\
\n\
Defines a callback function used by the NSS libraries whenever\n\
information protected by a password needs to be retrieved from the key\n\
or certificate databases.\n\
\n\
Many tokens keep track of the number of attempts to enter a password\n\
and do not allow further attempts after a certain point. Therefore, if\n\
the retry argument is True, indicating that the password was tried and\n\
is wrong, the callback function should return None to indicate that it\n\
is unsuccessful, rather than attempting to return the same password\n\
again. Failing to terminate when the retry argument is True can result\n\
in an endless loop. The user_dataN arguments can also be used to keep\n\
track of the number of times the callback has been invoked.\n\
\n\
Several functions in the NSS libraries use the password callback\n\
function to obtain the password before performing operations that\n\
involve the protected information.  The extra user_dataN parameters to\n\
the password callback function is application-defined and can be used\n\
for any purpose. When NSS libraries call the password callback\n\
function the value they pass for the user_dataN arguments is\n\
determined by `ssl.SSLSocket.set_pkcs11_pin_arg()`.\n\
\n\
The callback has the signature::\n\
    \n\
    password_callback(slot, retry, [user_data1, ...]) -> string or None\n\
\n\
slot\n\
    PK11Slot object\n\
retry\n\
    boolean indicating if this is a retry. This implies that the\n\
    callback has previously returned the wrong password.\n\
user_dataN\n\
    zero or more caller supplied optional parameters\n\
\n\
The callback should return a string or None to indicate a valid\n\
password cannot be supplied. Returning None will prevent the callback\n\
from being invoked again.\n\
");

static PyObject *
pk11_set_password_callback(PyObject *self, PyObject *args)
{
    PyObject *callback = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:set_password_callback", &callback)) {
        return NULL;
    }

    if (!PyCallable_Check(callback)) {
        PyErr_SetString(PyExc_TypeError, "callback must be callable");
        return NULL;
    }

    if (set_thread_local("password_callback", callback) < 0) {
        return NULL;
    }

    PK11_SetPasswordFunc(PK11_password_callback);

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pk11_list_certs_doc,
"list_certs(type, [user_data1, ...]) -> (`Certificate`, ...)\n\
\n\
:Parameters:\n\
    type : int\n\
        PK11CertList* enumerated constant.\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Given the type of certificates to list return a tuple of `Certificate`\n\
objects matching that type.\n\
");

static PyObject *
pk11_list_certs(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    int type = PK11CertListAll;
    CERTCertList *cert_list = NULL;
    PyObject *tuple = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "i:list_certs", &type)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((cert_list = PK11_ListCerts(type, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    tuple = CERTCertList_to_tuple(cert_list, true);
    CERT_DestroyCertList(cert_list);
    return tuple;
}

PyDoc_STRVAR(pk11_find_certs_from_email_addr_doc,
"find_certs_from_email_addr(email, [user_data1, ...]) -> (`Certificate`, ...)\n\
\n\
:Parameters:\n\
    email : string\n\
        email address.\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Given an email address return a tuple of `Certificate`\n\
objects containing that address.\n\
");

static PyObject *
pk11_find_certs_from_email_addr(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    char *email_addr = NULL;
    CERTCertList *cert_list = NULL;
    PyObject *tuple = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "s:find_certs_from_email_addr",
                          &email_addr)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((cert_list = PK11_FindCertsFromEmailAddress(email_addr, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    tuple = CERTCertList_to_tuple(cert_list, true);
    CERT_DestroyCertList(cert_list);
    return tuple;
}

PyDoc_STRVAR(pk11_find_certs_from_nickname_doc,
"find_certs_from_nickname(email, [user_data1, ...]) -> (`Certificate`, ...)\n\
\n\
:Parameters:\n\
    nickname : string\n\
        certificate nickname.\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Given a certificate nickname return a tuple of `Certificate`\n\
objects matching that nickname.\n\
");

static PyObject *
pk11_find_certs_from_nickname(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    char *nickname = NULL;
    CERTCertList *cert_list = NULL;
    PyObject *tuple = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "s:find_certs_from_nickname",
                          &nickname)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((cert_list = PK11_FindCertsFromNickname(nickname, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    tuple = CERTCertList_to_tuple(cert_list, true);
    CERT_DestroyCertList(cert_list);
    return tuple;
}

PyDoc_STRVAR(pk11_find_cert_from_nickname_doc,
"find_cert_from_nickname(nickname, [user_data1, ...]) -> Certificate\n\
\n\
:Parameters:\n\
    nickname : string\n\
        certificate nickname to search for\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
A nickname is an alias for a certificate subject. There may be\n\
multiple certificates with the same subject, and hence the same\n\
nickname. This function will return the newest certificate that\n\
matches the subject, based on the NotBefore / NotAfter fields of the\n\
certificate.\n\
");

static PyObject *
pk11_find_cert_from_nickname(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    char *nickname = NULL;
    CERTCertificate *cert = NULL;
    PyObject *py_cert = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "s:find_cert_from_nickname", &nickname)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((cert = PK11_FindCertFromNickname(nickname, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    if ((py_cert = Certificate_new_from_CERTCertificate(cert, false)) == NULL) {
        return NULL;
    }

    return py_cert;
}

PyDoc_STRVAR(pk11_find_key_by_any_cert_doc,
"find_key_by_any_cert(cert, [user_data1, ...]) -> Certificate\n\
\n\
:Parameters:\n\
    cert : Certificate object\n\
        certificate whose private key is being searched for\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Finds the private key associated with a specified certificate in any\n\
available slot.\n\
");

static PyObject *
pk11_find_key_by_any_cert(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    Certificate *py_cert = NULL;
    PyObject *pin_args = NULL;
    SECKEYPrivateKey *private_key;
    PyObject *py_private_key = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "O!:find_key_by_any_cert",
                          &CertificateType, &py_cert)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((private_key = PK11_FindKeyByAnyCert(py_cert->cert, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    if ((py_private_key = PrivateKey_new_from_SECKEYPrivateKey(private_key)) == NULL) {
        return NULL;
    }

    return py_private_key;
}

PyDoc_STRVAR(pk11_generate_random_doc,
"generate_random(num_bytes) -> string\n\
\n\
:Parameters:\n\
    num_bytes : integer\n\
        Number of num_bytes to generate (must be non-negative)\n\
\n\
Generates random data..\n\
");

static PyObject *
pk11_generate_random(PyObject *self, PyObject *args)
{
    int num_bytes;
    unsigned char *buf;
    SECStatus status;
    PyObject *res;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:generate_random", &num_bytes))
        return NULL;

    if (num_bytes < 0) {
        PyErr_SetString(PyExc_ValueError, "byte count must be non-negative");
        return NULL;
    }

    buf = PyMem_Malloc(num_bytes);
    if (buf == NULL) {
        return PyErr_NoMemory();
    }

    Py_BEGIN_ALLOW_THREADS
    status = PK11_GenerateRandom(buf, num_bytes);
    Py_END_ALLOW_THREADS
    if (status != SECSuccess) {
	PyMem_Free(buf);
	return set_nspr_error(NULL);
    }

    res = PyString_FromStringAndSize((char *)buf, num_bytes);
    PyMem_Free(buf);
    return res;
}

PyDoc_STRVAR(pk11_pk11_need_pw_init_doc,
"pk11_need_pw_init() -> bool\n\
\n\
Returns True if the internal slot needs to be initialized, False otherwise.\n\
\n\
The internal slot token should be initalized if:\n\
\n\
The token is not initialized\n\
\n\
   `PK11Slot.need_login()` == True and `PK11Slot.need_user_init()` == True\n\
\n\
Or\n\
\n\
The token has a NULL password.\n\
\n\
   `PK11Slot.need_login()` == False and `PK11Slot.need_user_init()` == False\n\
\n\
+------------------+------------------------+---------------------+\n\
|CKF_LOGIN_REQUIRED|CKF_USER_PIN_INITIALIZED|CKF_TOKEN_INITIALIZED|\n\
+==================+========================+=====================+\n\
|      False       |         False          |        True         |\n\
+------------------+------------------------+---------------------+\n\
|       True       |         False          |        False        |\n\
+------------------+------------------------+---------------------+\n\
|      False       |          True          |        True         |\n\
+------------------+------------------------+---------------------+\n\
|       True       |          True          |        True         |\n\
+------------------+------------------------+---------------------+\n\
\n\
`PK11Slot.need_login()` == CKF_LOGIN_REQUIRED\n\
\n\
`PK11Slot.need_user_init()` == !CKF_USER_PIN_INITIALIZED\n\
\n\
");

static PyObject *
pk11_pk11_need_pw_init(PyObject *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    if (PK11_NeedPWInit())
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}


PyDoc_STRVAR(pk11_pk11_token_exists_doc,
"pk11_token_exists(mechanism) -> bool\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
\n\
Return True if a token is available which can perform\n\
the desired mechanism, False otherwise.\n\
");

static PyObject *
pk11_pk11_token_exists(PyObject *self, PyObject *args)
{
    unsigned long mechanism;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:pk11_token_exists",
                          &mechanism))
        return NULL;

    if (PK11_TokenExists(mechanism))
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;

}

PyDoc_STRVAR(pk11_pk11_is_fips_doc,
"pk11_is_fips() -> bool\n\
\n\
Returns True if the internal module has FIPS enabled, False otherwise.\n\
");

static PyObject *
pk11_pk11_is_fips(PyObject *self, PyObject *args, PyObject *kwds)
{
    TraceMethodEnter(self);

    if (PK11_IsFIPS())
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}
/* ============================== Module Methods ============================= */

PyDoc_STRVAR(nss_nss_get_version_doc,
"nss_get_version() -> string\n\
\n\
Return a string of the NSS library version\n\
");

static PyObject *
nss_nss_get_version(PyObject *self, PyObject *args)
{
    const char *nss_version = NULL;

    TraceMethodEnter(self);

    Py_BEGIN_ALLOW_THREADS
    if ((nss_version = NSS_GetVersion()) == NULL) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    return PyString_FromString(nss_version);
}

PyDoc_STRVAR(nss_nss_version_check_doc,
"nss_version_check(version) --> bool\n\
\n\
:Parameters:\n\
    version : string\n\
        Required version\n\
\n\
Return a boolean that indicates whether the underlying NSS library\n\
will perform as the caller expects.\n\
\n\
The the version parameter is a string identifier of the NSS\n\
library. That string will be compared against a string that represents\n\
the actual build version of the NSS library. Return True if supplied\n\
version is compatible, False otherwise.\n\
");

static PyObject *
nss_nss_version_check(PyObject *self, PyObject *args)
{
    char *version = NULL;
    PRBool valid;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "s:nss_version_check", &version))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    valid = NSS_VersionCheck(version);
    Py_END_ALLOW_THREADS

    if (valid) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static SECStatus
NSS_Shutdown_Callback(void *app_data, void *nss_data)
{
    PyGILState_STATE gstate;
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *shutdown_callback = NULL;
    PyObject *callback_args = app_data; /* borrowed reference, don't decrement */
    PyObject *item;
    PyObject *new_args = NULL;
    PyObject *py_nss_data = NULL;
    int i, j;
    PyObject *py_result = NULL;
    SECStatus status_result = SECSuccess;

    gstate = PyGILState_Ensure();

    TraceMessage("NSS_Shutdown_Callback: enter");

    if ((shutdown_callback = get_thread_local("shutdown_callback")) == NULL) {
        if (!PyErr_Occurred()) {
            PySys_WriteStderr("shutdown callback undefined\n");
        } else {
            PyErr_Print();
        }
	PyGILState_Release(gstate);
        return status_result;
    }

    argc = n_base_args;
    if (callback_args) {
        if (PyTuple_Check(callback_args)) {
            argc += PyTuple_Size(callback_args);
        } else {
            PySys_WriteStderr("Error, shutdown callback expected args to be tuple\n");
            PyErr_Print();
        }
    }

    if ((new_args = PyTuple_New(argc)) == NULL) {
        PySys_WriteStderr("shutdown callback: out of memory\n");
        goto exit;
    }

    if ((py_nss_data = PyDict_New()) == NULL){
        goto exit;
    }

    PyTuple_SetItem(new_args, 0, py_nss_data);

    for (i = n_base_args, j = 0; i < argc; i++, j++) {
        item = PyTuple_GetItem(callback_args, j);
        Py_INCREF(item);
        PyTuple_SetItem(new_args, i, item);
    }

    if ((py_result = PyObject_CallObject(shutdown_callback, new_args)) == NULL) {
        PySys_WriteStderr("exception in shutdown callback\n");
        PyErr_Print();  /* this also clears the error */
        goto exit;
    }

    if (PyBool_Check(py_result)) {
        status_result = py_result == Py_True ? SECSuccess : SECFailure;
    } else {
        PySys_WriteStderr("Error, shutdown callback expected int result, not %.50s\n",
                      Py_TYPE(py_result)->tp_name);
        status_result = SECFailure;
        goto exit;
    }

 exit:
    TraceMessage("NSS_Shutdown_Callback: exiting");

    Py_XDECREF(py_nss_data);
    Py_XDECREF(new_args);
    Py_XDECREF(py_result);

    PyGILState_Release(gstate);

    return status_result;
}

PyDoc_STRVAR(nss_set_shutdown_callback_doc,
"set_shutdown_callback(callback, [user_data1, ...])\n\
\n\
:Parameters:\n\
    callback : function pointer or None\n\
        The callback function. If None cancel the previous callback\n\
        \n\
    user_dataN : object\n\
        zero or more caller supplied parameters which will\n\
        be passed to the shutdown callback function\n\
\n\
Defines a callback function which is invoked when NSS is shutdown.\n\
If the callback is None the previous callback is cancelled.\n\
\n\
After NSS is shutdown the shutdown callback is cancelled, you must\n\
reset the shutdown callback again after initializing NSS.\n\
\n\
The callback has the signature::\n\
    \n\
    shutdown_callback(nss_data, [user_data1, ...]) -> bool\n\
\n\
nss_data\n\
    dict of NSS values (currently empty)\n\
user_dataN\n\
    zero or more caller supplied optional parameters\n\
\n\
The callback should return True for success. If it returns False the\n\
NSS shutdown function will complete but will result in an error.\n\
");
static PyObject *
nss_set_shutdown_callback(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *new_callback_args = NULL;
    PyObject *prev_callback_args = NULL;
    PyObject *callback = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "O:set_shutdown_callback",
                          &callback)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    new_callback_args = PyTuple_GetSlice(args, n_base_args, argc);

    if (PyNone_Check(callback)) {
        if ((prev_callback_args = get_thread_local("shutdown_callback_args")) != NULL) {
            NSS_UnregisterShutdown(NSS_Shutdown_Callback, prev_callback_args);
            Py_CLEAR(prev_callback_args);
        }

        del_thread_local("shutdown_callback");
        del_thread_local("shutdown_callback_args");

    } else {
        if (!PyCallable_Check(callback)) {
            PyErr_SetString(PyExc_TypeError, "callback must be callable");
            return NULL;
        }

        if ((prev_callback_args = get_thread_local("shutdown_callback_args")) != NULL) {
            NSS_UnregisterShutdown(NSS_Shutdown_Callback, prev_callback_args);
            Py_CLEAR(prev_callback_args);
        }

        if (set_thread_local("shutdown_callback", callback) < 0) {
            return NULL;
        }

        if (set_thread_local("shutdown_callback_args", new_callback_args) < 0) {
            return NULL;
        }

        NSS_RegisterShutdown(NSS_Shutdown_Callback, new_callback_args);
    }

    Py_XDECREF(new_callback_args);

    Py_RETURN_NONE;
}

PyDoc_STRVAR(nss_nss_is_initialized_doc,
"nss_is_initialized() --> bool\n\
\n\
Returns whether Network Security Services has already been initialized or not.\n\
");

static PyObject *
nss_nss_is_initialized(PyObject *self, PyObject *args)
{
    PRBool is_init;
    TraceMethodEnter(self);

    Py_BEGIN_ALLOW_THREADS
    is_init = NSS_IsInitialized();
    Py_END_ALLOW_THREADS

    if (is_init) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

PyDoc_STRVAR(nss_nss_init_doc,
"nss_init(cert_dir)\n\
\n\
:Parameters:\n\
    cert_dir : string\n\
        Pathname of the directory where the certificate, key, and\n\
        security module databases reside.\n\
\n\
Sets up configuration files and performs other tasks required to run\n\
Network Security Services. `nss.nss_init()` differs from\n\
`nss.nss_init_read_write()` because the internal PK11 slot (see\n\
`nss.get_internal_slot()`) is created in Read Only (RO) mode as\n\
opposed to Read Write (RW) mode.\n\
");

static PyObject *
nss_nss_init(PyObject *self, PyObject *args)
{
    char *cert_dir;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "es:nss_init",
                          "utf-8", &cert_dir)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if (NSS_Init(cert_dir) != SECSuccess) {
        Py_BLOCK_THREADS
        PyMem_Free(cert_dir);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    PyMem_Free(cert_dir);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(nss_nss_init_read_write_doc,
"nss_init_read_write(cert_dir)\n\
\n\
:Parameters:\n\
    cert_dir : string\n\
        Pathname of the directory where the certificate, key, and\n\
        security module databases reside.\n\
\n\
Sets up configuration files and performs other tasks required to run\n\
Network Security Services. `nss.nss_init_read_write()` differs from\n\
`nss.nss_init()` because the internal PK11 slot (see\n\
`nss.get_internal_slot()`) is created in Read Write (RW) mode as\n\
opposed to Read Only (RO) mode.\n\
");

static PyObject *
nss_nss_init_read_write(PyObject *self, PyObject *args)
{
    char *cert_dir;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "es:nss_init_read_write",
                          "utf-8", &cert_dir)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if (NSS_InitReadWrite(cert_dir) != SECSuccess) {
        Py_BLOCK_THREADS
        PyMem_Free(cert_dir);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    PyMem_Free(cert_dir);
    Py_RETURN_NONE;
}

PyDoc_STRVAR(nss_init_nodb_doc,
"nss_init_nodb()\n\
\n\
Performs tasks required to run Network Security Services without setting up\n\
configuration files. Important: This NSS function is not intended for use with\n\
SSL, which requires that the certificate and key database files be opened.\n\
\n\
nss_init_nodb opens only the temporary database and the internal PKCS #112\n\
module. Unlike nss_init, nss_init_nodb allows applications that do not have\n\
access to storage for databases to run raw crypto, hashing, and certificate\n\
functions. nss_init_nodb is not idempotent, so call it only once. The policy\n\
flags for all cipher suites are turned off by default, disallowing all cipher\n\
suites. Therefore, an application cannot use NSS to perform any cryptographic\n\
operations until after it enables appropriate cipher suites by calling one of\n\
the SSL Export Policy Functions.\n\
");

static PyObject *
nss_init_nodb(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    Py_BEGIN_ALLOW_THREADS
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

PyDoc_STRVAR(nss_nss_initialize_doc,
"nss_initialize(cert_dir=None, cert_prefix=None, key_prefix=None, secmod_name=None, flags=0)\n\
\n\
:Parameters:\n\
    cert_dir : string\n\
        Pathname of the directory where the certificate, key, and\n\
        security module databases reside.\n\
 \n\
    cert_prefix : string\n\
        Prefix added to the beginning of the certificate database,\n\
        for example,\"https-server1-\".\n\
\n\
    key_prefix : string\n\
        Prefix added to the beginning of the key database,\n\
        for example, \"https-server1-\".\n\
\n\
    secmod_name : string\n\
        Name of the security module database,\n\
        usually \"secmod.db\".\n\
\n\
    flags\n\
        Bit flags that specify how NSS should be initialized.\n\
\n\
`nss_initialize()` initializes NSS. It is more flexible than `nss_init()`,\n\
`nss_init_read_write()`, and `nss_init_nodb()`. If any of those simpler NSS\n\
initialization functions suffices for your needs, call that instead.\n\
\n\
By default `nss_initialize()` and `nss_init_context()` open the\n\
internal PK11 slot (see `get_internal_slot()`) in Read Write (RW) mode\n\
as opposed to `nss_init()` which opens it in Read Only (RO) mode. If\n\
you want RO mode you pass the `NSS_INIT_READONLY` flag.\n\
\n\
The flags parameter is a bitwise OR of the following flags:\n\
\n\
NSS_INIT_READONLY\n\
    Open the databases read only.\n\
\n\
NSS_INIT_NOCERTDB\n\
    Don't open the cert DB and key DB's, just initialize the volatile\n\
    certdb.\n\
\n\
NSS_INIT_NOMODDB\n\
    Don't open the security module DB, just initialize the PKCS #11 module.\n\
\n\
NSS_INIT_FORCEOPEN\n\
    Continue to force initializations even if the databases cannot be\n\
    opened.\n\
\n\
NSS_INIT_NOROOTINIT\n\
    Don't try to look for the root certs module automatically.\n\
\n\
NSS_INIT_OPTIMIZESPACE\n\
    Optimize for space instead of speed. Use smaller tables and caches.\n\
\n\
NSS_INIT_PK11THREADSAFE\n\
    Only load PKCS#11 modules that are thread-safe, i.e., that support\n\
    locking - either OS locking or NSS-provided locks . If a PKCS#11 module\n\
    isn't thread-safe, don't serialize its calls; just don't load it\n\
    instead. This is necessary if another piece of code is using the same\n\
    PKCS#11 modules that NSS is accessing without going through NSS, for\n\
    example, the Java SunPKCS11 provider.\n\
\n\
NSS_INIT_PK11RELOAD\n\
    Ignore the CKR_CRYPTOKI_ALREADY_INITIALIZED error when loading PKCS#11\n\
    modules. This is necessary if another piece of code is using the same\n\
    PKCS#11 modules that NSS is accessing without going through NSS, for\n\
    example, Java SunPKCS11 provider.\n\
\n\
NSS_INIT_NOPK11FINALIZE\n\
    Never call C_Finalize on any PKCS#11 module. This may be necessary in\n\
    order to ensure continuous operation and proper shutdown sequence if\n\
    another piece of code is using the same PKCS#11 modules that NSS is\n\
    accessing without going through NSS, for example, Java SunPKCS11\n\
    provider. The following limitation applies when this is set :\n\
    SECMOD_WaitForAnyTokenEvent will not use C_WaitForSlotEvent, in order\n\
    to prevent the need for C_Finalize. This call will be emulated instead.\n\
\n\
NSS_INIT_RESERVED\n\
    Currently has no effect, but may be used in the future to trigger\n\
    better cooperation between PKCS#11 modules used by both NSS and the\n\
    Java SunPKCS11 provider. This should occur after a new flag is defined\n\
    for C_Initialize by the PKCS#11 working group.\n\
\n\
NSS_INIT_COOPERATE\n\
    Sets the above four recommended options for applications that use both\n\
    NSS and the Java SunPKCS11 provider.\n\
\n\
Hint: You can obtain a printable representation of the flags via `nss_init_flags`.\n\
");

static PyObject *
nss_nss_initialize(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"cert_dir", "cert_prefix", "key_prefix", "secmod_name", "flags", NULL};
    char *cert_dir = NULL;
    char *cert_prefix = NULL;
    char *key_prefix = NULL;
    char *secmod_name = NULL;
    unsigned long flags = 0;
    SECStatus status;


    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|esesesesk:nss_initialize", kwlist,
                                     "utf-8", &cert_dir,
                                     "utf-8", &cert_prefix,
                                     "utf-8", &key_prefix,
                                     "utf-8", &secmod_name,
                                     &flags))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    if ((status = NSS_Initialize(cert_dir, cert_prefix, key_prefix, secmod_name, flags)) != SECSuccess) {
        set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    if (cert_dir)    PyMem_Free(cert_dir);
    if (cert_prefix) PyMem_Free(cert_prefix);
    if (key_prefix)  PyMem_Free(key_prefix);
    if (secmod_name) PyMem_Free(secmod_name);

    if (status == SECSuccess) {
        Py_RETURN_NONE;
    } else {
        return NULL;
    }
}

PyDoc_STRVAR(nss_nss_init_context_doc,
"nss_init_context(cert_dir=None, cert_prefix=None, key_prefix=None, secmod_name=None, init_params=None, flags=0) -> `InitContext`\n\
\n\
:Parameters:\n\
    cert_dir : string\n\
        Pathname of the directory where the certificate, key, and\n\
        security module databases reside.\n\
 \n\
    cert_prefix : string\n\
        Prefix added to the beginning of the certificate database,\n\
        for example,\"https-server1-\".\n\
\n\
    key_prefix : string\n\
        Prefix added to the beginning of the key database,\n\
        for example, \"https-server1-\".\n\
\n\
    secmod_name : string\n\
        Name of the security module database,\n\
        usually \"secmod.db\".\n\
\n\
    init_params : `InitContext` object\n\
        Object with a set of initialization parameters.\n\
        See `InitContext`.\n\
\n\
    flags\n\
        Bit flags that specify how NSS should be initialized.\n\
\n\
`nss_init_context()` initializes NSS within a context and returns a\n\
`InitContext` object. Contexts are used when multiple entities within\n\
a single process wish to use NSS without colliding such as\n\
libraries.\n\
\n\
You must hold onto the returned InitContext object and call shutdown\n\
on it when you are done. The context will automatically be shutdown\n\
when the InitContext object is destroyed if you have not already shut\n\
it down.\n\
\n\
By default `nss_initialize()` and `nss_init_context()` open the\n\
internal PK11 slot (see `get_internal_slot()`) in Read Write (RW) mode\n\
as opposed to `nss_init()` which opens it in Read Only (RO) mode. If\n\
you want RO mode you pass the `NSS_INIT_READONLY` flag.\n\
\n\
The flags parameter is a bitwise OR of the following flags:\n\
\n\
NSS_INIT_READONLY\n\
    Open the databases read only.\n\
\n\
NSS_INIT_NOCERTDB\n\
    Don't open the cert DB and key DB's, just initialize the volatile\n\
    certdb.\n\
\n\
NSS_INIT_NOMODDB\n\
    Don't open the security module DB, just initialize the PKCS #11 module.\n\
\n\
NSS_INIT_FORCEOPEN\n\
    Continue to force initializations even if the databases cannot be\n\
    opened.\n\
\n\
NSS_INIT_NOROOTINIT\n\
    Don't try to look for the root certs module automatically.\n\
\n\
NSS_INIT_OPTIMIZESPACE\n\
    Optimize for space instead of speed. Use smaller tables and caches.\n\
\n\
NSS_INIT_PK11THREADSAFE\n\
    Only load PKCS#11 modules that are thread-safe, i.e., that support\n\
    locking - either OS locking or NSS-provided locks . If a PKCS#11 module\n\
    isn't thread-safe, don't serialize its calls; just don't load it\n\
    instead. This is necessary if another piece of code is using the same\n\
    PKCS#11 modules that NSS is accessing without going through NSS, for\n\
    example, the Java SunPKCS11 provider.\n\
\n\
NSS_INIT_PK11RELOAD\n\
    Ignore the CKR_CRYPTOKI_ALREADY_INITIALIZED error when loading PKCS#11\n\
    modules. This is necessary if another piece of code is using the same\n\
    PKCS#11 modules that NSS is accessing without going through NSS, for\n\
    example, Java SunPKCS11 provider.\n\
\n\
NSS_INIT_NOPK11FINALIZE\n\
    Never call C_Finalize on any PKCS#11 module. This may be necessary in\n\
    order to ensure continuous operation and proper shutdown sequence if\n\
    another piece of code is using the same PKCS#11 modules that NSS is\n\
    accessing without going through NSS, for example, Java SunPKCS11\n\
    provider. The following limitation applies when this is set :\n\
    SECMOD_WaitForAnyTokenEvent will not use C_WaitForSlotEvent, in order\n\
    to prevent the need for C_Finalize. This call will be emulated instead.\n\
\n\
NSS_INIT_RESERVED\n\
    Currently has no effect, but may be used in the future to trigger\n\
    better cooperation between PKCS#11 modules used by both NSS and the\n\
    Java SunPKCS11 provider. This should occur after a new flag is defined\n\
    for C_Initialize by the PKCS#11 working group.\n\
\n\
NSS_INIT_COOPERATE\n\
    Sets the above four recommended options for applications that use both\n\
    NSS and the Java SunPKCS11 provider.\n\
\n\
Hint: You can obtain a printable representation of the flags via `nss_init_flags`.\n\
");

static PyObject *
nss_nss_init_context(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"cert_dir", "cert_prefix", "key_prefix",
                             "secmod_name", "init_params", "flags", NULL};
    char *cert_dir = NULL;
    char *cert_prefix = NULL;
    char *key_prefix = NULL;
    char *secmod_name = NULL;
    InitParameters *py_init_params = NULL;
    unsigned long flags = 0;
    NSSInitContext *init_context = NULL;
    PyObject *py_init_context = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|esesesesO!k:nss_init_context", kwlist,
                                     "utf-8", &cert_dir,
                                     "utf-8", &cert_prefix,
                                     "utf-8", &key_prefix,
                                     "utf-8", &secmod_name,
                                     &InitParametersType, &py_init_params,
                                     &flags))
        return NULL;

    if ((init_context = NSS_InitContext(cert_dir, cert_prefix, key_prefix, secmod_name,
                                        py_init_params ? &py_init_params->params : NULL,
                                        flags)) == NULL) {
        set_nspr_error(NULL);
    }

    Py_BEGIN_ALLOW_THREADS
    if ((py_init_context = InitContext_new_from_NSSInitContext(init_context)) == NULL) {
        NSS_ShutdownContext(init_context);
        init_context = NULL;
    }
    Py_END_ALLOW_THREADS

    if (cert_dir)    PyMem_Free(cert_dir);
    if (cert_prefix) PyMem_Free(cert_prefix);
    if (key_prefix)  PyMem_Free(key_prefix);
    if (secmod_name) PyMem_Free(secmod_name);

    if (init_context != NULL) {
        return py_init_context;
    } else {
        return NULL;
    }
}

PyDoc_STRVAR(nss_nss_shutdown_context_doc,
"nss_shutdown_context(context) -> \n\
\n\
:Parameters:\n\
    context : `InitContext` object\n\
        A `InitContext` returned from a previous\n\
        call to `nss_init_context`.\n\
\n\
Shutdown NSS for the users of this context. When all contexts\n\
have been shutdown NSS will fully shutdown.\n\
");

static PyObject *
nss_nss_shutdown_context(PyObject *self, PyObject *args)
{
    InitContext *py_context = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O!:nss_shutdown_context",
                          &InitContextType, &py_context))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    if (NSS_ShutdownContext(py_context->context) != SECSuccess) {
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

PyDoc_STRVAR(nss_nss_shutdown_doc,
"nss_shutdown()\n\
\n\
Closes the key and certificate databases that were opened by nss_init().\n\
\n\
NSS can only shutdown successfully if all NSS objects have been\n\
released, otherwise nss_shutdown will fail with the error code\n\
SEC_ERROR_BUSY. Here are some tips to make sure nss_shutdown will\n\
succeed. [1]_\n\
\n\
* If the process is a SSL client make sure you call\n\
  `ssl.clear_session_cache`.\n\
\n\
* If the process is a SSL server make sure you call\n\
  `ssl.shutdown_server_session_id_cache()`.\n\
\n\
* Make sure all sockets have been closed, open SSL sockets hold\n\
  references NSS objects.\n\
\n\
* Explicitly delete Python objects which contain NSS objects using the\n\
  del command. [2]_\n\
\n\
* Use `nss.dump_certificate_cache_info()` to provide information about\n\
  which cached objects may still persist and be responsible for\n\
  preventing a full NSS shutdown.\n\
\n\
.. [1] If the leaked objects are subsequently released after\n\
       nss_shutdown is called NSS can be reinitialized with the\n\
       various NSS initialization routines. In this cass teh\n\
       SEC_ERROR_BUSY error can be thought of as an informatiive\n\
       warning.\n\
\n\
.. [2] This Python binding to NSS wraps each NSS object inside a\n\
       Python object. Like NSS objects Python objects are reference\n\
       counted. When the last reference to the Python object\n\
       disappears the Python object is destroyed. The destructor for a\n\
       Python object wrapping an NSS object releases the NSS reference\n\
       to the NSS object. Thus if any Python objects which wrap NSS\n\
       objects remain \"live\" nss_shutdown will fail. Python objects\n\
       are typically released by the Python interpretor when the\n\
       variable holding the object is assigned a new object or when\n\
       the variable holding the object goes out of scope. This means\n\
       you may need to manually delete some objects using the del\n\
       command rather relying on Python's automatic garbage\n\
       collection. Consider this example:\n\
\n\
       def foo():\n\
           nss.nss_init(certdir)\n\
           sock = ssl.SSLSocket()\n\
           nss.nss_shutdown()\n\
\n\
       When nss_shutown() is called the sock object is still alive and\n\
       holds references to NSS objects. The sock object won't be\n\
       released by Python until it goes out of scope when the function\n\
       exits. Thus the shutdown will fail with SEC_ERROR_BUSY. But you\n\
       can explicitly force the sock object to be released by\n\
       explictily deleting it, for example:\n\
\n\
       def foo():\n\
           nss.nss_init(certdir)\n\
           sock = ssl.SSLSocket()\n\
           del sock\n\
           nss.nss_shutdown()\n\
\n\
       Another way to avoid this issue is to arrange your code such\n\
       that nss_shutdown is called from a location in your code which\n\
       is not in scope for any NSS objects created. This also implies\n\
       you shouldn't assign NSS objects to globals.\n\
");

static PyObject *
nss_nss_shutdown(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    Py_BEGIN_ALLOW_THREADS
    if (NSS_Shutdown() != SECSuccess) {
        Py_BLOCK_THREADS
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_RETURN_NONE;
}

PyDoc_STRVAR(nss_dump_certificate_cache_info_doc,
"dump_certificate_cache_info()\n\
\n\
Dump the contents of the certificate cache and the temporary\n\
cert store to stdout.\n\
\n\
Use this as a debugging aid to detect leaked references of certs at\n\
shutdown time. For example if `nss.nss_shutdown()` throws a\n\
SEC_ERROR_BUSY exception.\n\
");

static PyObject *
nss_dump_certificate_cache_info(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    nss_DumpCertificateCacheInfo();
    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_oid_str_doc,
"oid_str(oid) -> string\n\
\n\
:Parameters:\n\
     oid : may be one of integer, string, SecItem\n\
         May be one of:\n\
         \n\
         * integer:: A SEC OID enumeration constant, also known as a tag\n\
           (i.e. SEC_OID_*) for example SEC_OID_AVA_COMMON_NAME.\n\
         * string:: A string in dotted decimal representation, for example\n\
           'OID.2.5.4.3'. The 'OID.' prefix is optional.\n\
           Or a string for the tag name (e.g. 'SEC_OID_AVA_COMMON_NAME')\n\
           The 'SEC_OID\\_' prefix is optional. Or one of the canonical\n\
           abbreviations (e.g. 'cn'). Case is not significant.\n\
         * SecItem:: A SecItem object encapsulating the OID in \n\
           DER format.\n\
\n\
Given an oid return it's description as a string.\n\
");
static PyObject *
cert_oid_str(PyObject *self, PyObject *args)
{
    PyObject *arg;
    int oid_tag;
    SECOidData *oiddata;

    TraceMethodEnter(self);

   if (!PyArg_ParseTuple(args, "O:oid_str", &arg))
        return NULL;

   oid_tag = get_oid_tag_from_object(arg);
   if (oid_tag == SEC_OID_UNKNOWN || oid_tag == -1) {
       return NULL;
   }

   if ((oiddata = SECOID_FindOIDByTag(oid_tag)) == NULL) {
       return set_nspr_error(NULL);
   }

   return PyString_FromString(oiddata->desc);
}


PyDoc_STRVAR(cert_oid_tag_name_doc,
"oid_tag_name(oid) -> string\n\
\n\
:Parameters:\n\
     oid : may be one of integer, string, SecItem\n\
         May be one of:\n\
         \n\
         * integer:: A SEC OID enumeration constant, also known as a tag\n\
           (i.e. SEC_OID_*) for example SEC_OID_AVA_COMMON_NAME.\n\
         * string:: A string in dotted decimal representation, for example\n\
           'OID.2.5.4.3'. The 'OID.' prefix is optional.\n\
           Or a string for the tag name (e.g. 'SEC_OID_AVA_COMMON_NAME')\n\
           The 'SEC_OID\\_' prefix is optional. Or one of the canonical\n\
           abbreviations (e.g. 'cn'). Case is not significant.\n\
         * SecItem:: A SecItem object encapsulating the OID in \n\
           DER format.\n\
\n\
Given an oid return it's tag constant as a string.\n\
");
static PyObject *
cert_oid_tag_name(PyObject *self, PyObject *args)
{
    PyObject *arg;
    int oid_tag;
    PyObject *py_name;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:oid_tag_name", &arg))
        return NULL;

    oid_tag = get_oid_tag_from_object(arg);
    if (oid_tag == SEC_OID_UNKNOWN || oid_tag == -1) {
        return NULL;
    }

    py_name = oid_tag_name_from_tag(oid_tag);
    return py_name;
}

PyDoc_STRVAR(cert_oid_tag_doc,
"oid_tag(oid) -> int\n\
\n\
:Parameters:\n\
     oid : may be one of integer, string, SecItem\n\
         May be one of:\n\
         \n\
         * integer:: A SEC OID enumeration constant, also known as a tag\n\
           (i.e. SEC_OID_*) for example SEC_OID_AVA_COMMON_NAME.\n\
         * string:: A string in dotted decimal representation, for example\n\
           'OID.2.5.4.3'. The 'OID.' prefix is optional.\n\
           Or a string for the tag name (e.g. 'SEC_OID_AVA_COMMON_NAME')\n\
           The 'SEC_OID\\_' prefix is optional. Or one of the canonical\n\
           abbreviations (e.g. 'cn'). Case is not significant.\n\
         * SecItem:: A SecItem object encapsulating the OID in \n\
           DER format.\n\
\n\
Given an oid return it's tag constant.\n\
");
static PyObject *
cert_oid_tag(PyObject *self, PyObject *args)
{
    PyObject *result;
    PyObject *arg;
    int oid_tag;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:oid_tag", &arg))
        return NULL;

    oid_tag = get_oid_tag_from_object(arg);
    if (oid_tag == SEC_OID_UNKNOWN || oid_tag == -1) {
        return NULL;
    }

    result = PyInt_FromLong(oid_tag);
    return result;
}

PyDoc_STRVAR(cert_oid_dotted_decimal_doc,
"oid_dotted_decimal(oid) -> string\n\
\n\
:Parameters:\n\
     oid : may be one of integer, string, SecItem\n\
         May be one of:\n\
         \n\
         * integer:: A SEC OID enumeration constant, also known as a tag\n\
           (i.e. SEC_OID_*) for example SEC_OID_AVA_COMMON_NAME.\n\
         * string:: A string in dotted decimal representation, for example\n\
           'OID.2.5.4.3'. The 'OID.' prefix is optional.\n\
           Or a string for the tag name (e.g. 'SEC_OID_AVA_COMMON_NAME')\n\
           The 'SEC_OID\\_' prefix is optional. Or one of the canonical\n\
           abbreviations (e.g. 'cn'). Case is not significant.\n\
         * SecItem:: A SecItem object encapsulating the OID in \n\
           DER format.\n\
\n\
Given an oid return it's tag constant as a string.\n\
");
static PyObject *
cert_oid_dotted_decimal(PyObject *self, PyObject *args)
{
    PyObject *arg;
    int oid_tag;
    SECOidData *oiddata;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O:oid_dotted_decimal", &arg))
        return NULL;

    oid_tag = get_oid_tag_from_object(arg);
    if (oid_tag == SEC_OID_UNKNOWN || oid_tag == -1) {
        return NULL;
    }

    if ((oiddata = SECOID_FindOIDByTag(oid_tag)) == NULL) {
        return set_nspr_error(NULL);
    }

    return oid_secitem_to_pystr_dotted_decimal(&oiddata->oid);
}


static PyObject *
key_mechanism_type_to_pystr(CK_MECHANISM_TYPE mechanism)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyInt_FromLong(mechanism)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create object");
        return NULL;
    }

    if ((py_name = PyDict_GetItem(ckm_value_to_name, py_value)) == NULL) {
        Py_DECREF(py_value);
	PyErr_Format(PyExc_KeyError, "mechanism name not found: %lu", mechanism);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}

PyDoc_STRVAR(pk11_key_mechanism_type_name_doc,
"key_mechanism_type_name(mechanism) -> string\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
\n\
Given a key mechanism enumeration constant (CKM_*)\n\
return it's name as a string\n\
");
static PyObject *
pk11_key_mechanism_type_name(PyObject *self, PyObject *args)
{
    unsigned long mechanism;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:key_mechanism_type_name", &mechanism))
        return NULL;

    return key_mechanism_type_to_pystr(mechanism);
}

PyDoc_STRVAR(pk11_key_mechanism_type_from_name_doc,
"key_mechanism_type_from_name(name) -> int\n\
\n\
:Parameters:\n\
    name : string\n\
        name of key mechanism enumeration constant (CKM_*)\n\
\n\
Given the name of a key mechanism enumeration constant (CKM_*)\n\
return it's integer constant\n\
The string comparison is case insensitive and will match with\n\
or without the CKM\\_ prefix\n\
");
static PyObject *
pk11_key_mechanism_type_from_name(PyObject *self, PyObject *args)
{
    PyObject *py_name;
    PyObject *py_lower_name;
    PyObject *py_value;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "S:key_mechanism_type_from_name", &py_name))
        return NULL;

    if ((py_lower_name = PyObject_CallMethod(py_name, "lower", NULL)) == NULL) {
        return NULL;
    }

    if ((py_value = PyDict_GetItem(ckm_name_to_value, py_lower_name)) == NULL) {
	PyErr_Format(PyExc_KeyError, "mechanism name not found: %s", PyString_AsString(py_name));
        Py_DECREF(py_lower_name);
        return NULL;
    }

    Py_DECREF(py_lower_name);
    Py_INCREF(py_value);

    return py_value;
}

static PyObject *
pk11_attribute_type_to_pystr(CK_ATTRIBUTE_TYPE type)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyInt_FromLong(type)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create object");
        return NULL;
    }

    if ((py_name = PyDict_GetItem(cka_value_to_name, py_value)) == NULL) {
        Py_DECREF(py_value);
	PyErr_Format(PyExc_KeyError, "attribute type name not found: %lu", type);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}

PyDoc_STRVAR(pk11_attribute_type_name_doc,
"pk11_attribute_type_name(type) -> string\n\
\n\
:Parameters:\n\
    type : int\n\
        PK11 attribute type constant (CKA_*)\n\
\n\
Given a PK11 attribute type constant (CKA_*)\n\
return it's name as a string\n\
");
static PyObject *
pk11_pk11_attribute_type_name(PyObject *self, PyObject *args)
{
    unsigned long type;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:pk11_attribute_type_name", &type))
        return NULL;

    return pk11_attribute_type_to_pystr(type);
}

PyDoc_STRVAR(pk11_pk11_attribute_type_from_name_doc,
"pk11_attribute_type_from_name(name) -> int\n\
\n\
:Parameters:\n\
    name : string\n\
        name of PK11 attribute type constant (CKA_*)\n\
\n\
Given the name of a PK11 attribute type constant (CKA_*)\n\
return it's integer constant\n\
The string comparison is case insensitive and will match with\n\
or without the CKA\\_ prefix\n\
");
static PyObject *
pk11_pk11_attribute_type_from_name(PyObject *self, PyObject *args)
{
    PyObject *py_name;
    PyObject *py_lower_name;
    PyObject *py_value;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "S:pk11_attribute_type_from_name", &py_name))
        return NULL;

    if ((py_lower_name = PyObject_CallMethod(py_name, "lower", NULL)) == NULL) {
        return NULL;
    }

    if ((py_value = PyDict_GetItem(cka_name_to_value, py_lower_name)) == NULL) {
	PyErr_Format(PyExc_KeyError, "attribute name not found: %s", PyString_AsString(py_name));
        Py_DECREF(py_lower_name);
        return NULL;
    }

    Py_DECREF(py_lower_name);
    Py_INCREF(py_value);

    return py_value;
}

PyDoc_STRVAR(pk11_disabled_reason_str_doc,
"pk11_disabled_reason_str(reason) -> string\n\
\n\
:Parameters:\n\
    reason : int\n\
        PK11 slot disabled reason constant (PK11_DIS_*)\n\
\n\
Given a PK11 slot disabled reason constant (PK11_DIS_*)\n\
return a descriptive string\n\
");
static PyObject *
pk11_pk11_disabled_reason_str(PyObject *self, PyObject *args)
{
    unsigned long reason;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:pk11_disabled_reason_str", &reason))
        return NULL;

    return PyString_FromString(pk11_disabled_reason_str(reason));
}

PyDoc_STRVAR(pk11_disabled_reason_name_doc,
"pk11_disabled_reason_name(reason) -> string\n\
\n\
:Parameters:\n\
    reason : int\n\
        PK11 slot disabled reason constant (PK11_DIS_*)\n\
\n\
Given a PK11 slot disabled reason constant (PK11_DIS_*)\n\
return the constant as a string.\n\
");
static PyObject *
pk11_pk11_disabled_reason_name(PyObject *self, PyObject *args)
{
    unsigned long reason;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:pk11_disabled_reason_name", &reason))
        return NULL;

    return PyString_FromString(pk11_disabled_reason_name(reason));
}

PyDoc_STRVAR(pk11_pk11_logout_all_doc,
"pk11_logout_all()\n\
\n\
Logout of every slot for all modules.\n\
");
static PyObject *
pk11_pk11_logout_all(PK11Slot *self, PyObject *args)
{
    TraceMethodEnter(self);

    PK11_LogoutAll();
    Py_RETURN_NONE;
}

PyDoc_STRVAR(pk11_get_best_slot_doc,
"get_best_slot(mechanism, [user_data1, ...]) -> PK11Slot\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Find the best slot which supports the given mechanism.\n\
");

static PyObject *
pk11_get_best_slot(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 1;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    unsigned long mechanism;
    PK11SlotInfo *slot = NULL;
    PyObject *py_slot = NULL;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }
    if (!PyArg_ParseTuple(parse_args, "k:get_best_slot", &mechanism)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((slot = PK11_GetBestSlot(mechanism, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    if ((py_slot = PK11Slot_new_from_PK11SlotInfo(slot)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create PK11Slot object");
        return NULL;
    }

    return py_slot;
}

PyDoc_STRVAR(pk11_get_internal_slot_doc,
"get_internal_slot() -> PK11Slot\n\
\n\
Get the default internal slot.\n\
");

static PyObject *
pk11_get_internal_slot(PyObject *self, PyObject *args)
{
    PK11SlotInfo *slot = NULL;
    PyObject *py_slot = NULL;

    TraceMethodEnter(self);

    if ((slot = PK11_GetInternalSlot()) == NULL) {
        return set_nspr_error(NULL);
    }

    if ((py_slot = PK11Slot_new_from_PK11SlotInfo(slot)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create PK11Slot object");
        return NULL;
    }

    return py_slot;
}

PyDoc_STRVAR(pk11_get_internal_key_slot_doc,
"get_internal_key_slot() -> PK11Slot\n\
\n\
Get the default internal key slot.\n\
");

static PyObject *
pk11_get_internal_key_slot(PyObject *self, PyObject *args)
{
    PK11SlotInfo *slot = NULL;
    PyObject *py_slot = NULL;

    TraceMethodEnter(self);

    if ((slot = PK11_GetInternalKeySlot()) == NULL) {
        return set_nspr_error(NULL);
    }

    if ((py_slot = PK11Slot_new_from_PK11SlotInfo(slot)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create PK11Slot object");
        return NULL;
    }

    return py_slot;
}

PyDoc_STRVAR(pk11_find_slot_by_name_doc,
"find_slot_by_name(name) -> `PK11Slot`\n\
\n\
:Parameters:\n\
    name : string\n\
        slot name\n\
\n\
Given a slot name return a `PK11Slot` object.\n\
");

static PyObject *
pk11_find_slot_by_name(PyObject *self, PyObject *args)
{
    char *slot_name = NULL;
    PK11SlotInfo *slot = NULL;
    PyObject *py_slot = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "es:find_slot_by_name",
                          "utf-8", &slot_name))
        return NULL;

    if ((slot = PK11_FindSlotByName(slot_name)) == NULL) {
        PyMem_Free(slot_name);
        return set_nspr_error("could not find slot name \"%s\"", slot_name);
    }
    PyMem_Free(slot_name);

    if ((py_slot = PK11Slot_new_from_PK11SlotInfo(slot)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create PK11Slot object");
        return NULL;
    }

    return py_slot;
}

PyDoc_STRVAR(pk11_create_context_by_sym_key_doc,
"create_context_by_sym_key(mechanism, operation, sym_key, sec_param=None) -> PK11Context\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    operation : int\n\
        type of operation this context will be doing. A (CKA_*) constant\n\
        (e.g. CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_DIGEST)\n\
    sym_key : PK11SymKey object\n\
        symmetric key\n\
    sec_param : SecItem object or None\n\
        mechanism parameters used to build this context or None.\n\
\n\
Create a context from a symmetric key)\n\
");
static PyObject *
pk11_create_context_by_sym_key(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"mechanism", "operation", "sym_key", "sec_param", NULL};
    unsigned long mechanism;
    unsigned long operation;
    PyPK11SymKey *py_sym_key;
    SecItem *py_sec_param;
    PK11Context *pk11_context;
    PyObject *py_pk11_context;
    SECItem null_param = {0};

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "kkO!|O&:create_context_by_sym_key", kwlist,
                                     &mechanism, &operation,
                                     &PK11SymKeyType, &py_sym_key,
                                     SecItemOrNoneConvert, &py_sec_param))
        return NULL;

    if ((pk11_context =
         PK11_CreateContextBySymKey(mechanism, operation, py_sym_key->pk11_sym_key,
                                    py_sec_param ? &py_sec_param->item : &null_param)) == NULL) {
        return set_nspr_error(NULL);
    }

    if ((py_pk11_context = PyPK11Context_new_from_PK11Context(pk11_context)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create PK11Context object");
        return NULL;
    }

    return py_pk11_context;
}

PyDoc_STRVAR(pk11_import_sym_key_doc,
"import_sym_key(slot, mechanism, origin, operation, key_data, [user_data1, ...]) -> PK11SymKey\n\
\n\
:Parameters:\n\
    slot : PK11Slot object\n\
        designated PK11 slot\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    origin : int\n\
        PK11 origin enumeration (PK11Origin*)\n\
        e.g. PK11_OriginDerive, PK11_OriginUnwrap, etc.\n\
    operation : int\n\
        type of operation this context will be doing. A (CKA_*) constant\n\
        (e.g. CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_DIGEST)\n\
    key_data: SecItem object\n\
        key data encapsulated in a SECItem used to build the symmetric key.\n\
    user_dataN : object ...\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
Create a PK11SymKey from data)\n\
");
static PyObject *
pk11_import_sym_key(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 5;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    PK11Slot *py_slot;
    unsigned long mechanism;
    unsigned long origin;
    unsigned long operation;
    SecItem *py_key_data;
    PK11SymKey *sym_key;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }

    if (!PyArg_ParseTuple(parse_args, "O!kkkO!:import_sym_key",
                          &PK11SlotType, &py_slot,
                          &mechanism, &origin, &operation,
                          &SecItemType, &py_key_data)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((sym_key = PK11_ImportSymKey(py_slot->slot, mechanism, origin, operation,
                                     &py_key_data->item, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    return PyPK11SymKey_new_from_PK11SymKey(sym_key);
}

PyDoc_STRVAR(pk11_pub_wrap_sym_key_doc,
"pub_wrap_sym_key(mechanism, pub_key, sym_key) -> SecItem\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        CK_MECHANISM_TYPE enumerated constant\n\
    pub_key : `PublicKey` object\n\
        Public key used to wrap.\n\
    sym_key : `PK11SymKey` object\n\
        Symmetric key that will be wrapped.\n\
:returns:\n\
    Wrapped symmetric key as SecItem\n\
\n\
Wraps a public key wrap (which only RSA can do).\n\
");
static PyObject *
pk11_pub_wrap_sym_key(PyObject *self, PyObject *args)
{
    unsigned long mechanism;
    PublicKey *py_pub_key = NULL;
    PyPK11SymKey *py_sym_key = NULL;
    size_t key_len = 0;
    SecItem  *py_wrapped_key = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "kO!O!:pub_wrap_sym_key",
                          &mechanism,
                          &PublicKeyType, &py_pub_key,
                          &PK11SymKeyType, &py_sym_key))
        return NULL;

    key_len = SECKEY_PublicKeyStrength(py_pub_key->pk);
    if ((py_wrapped_key = (SecItem *)SecItem_new_alloc(key_len, siBuffer, SECITEM_wrapped_key)) == NULL) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if ((PK11_PubWrapSymKey(mechanism, py_pub_key->pk, py_sym_key->pk11_sym_key,
                            &py_wrapped_key->item) != SECSuccess)) {
	Py_BLOCK_THREADS
        Py_CLEAR(py_wrapped_key);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    return (PyObject *)py_wrapped_key;
}

PyDoc_STRVAR(pk11_create_digest_context_doc,
"create_digest_context(hash_alg) -> PK11Context\n\
\n\
:Parameters:\n\
    hash_alg : int\n\
        hash algorithm enumeration (SEC_OID_*)\n\
        e.g.: SEC_OID_MD5, SEC_OID_SHA1, SEC_OID_SHA256, SEC_OID_SHA512, etc.\n\
\n\
Create a context for performing digest (hash) operations)\n\
");
static PyObject *
pk11_create_digest_context(PyObject *self, PyObject *args)
{
    unsigned long hash_alg;
    PK11Context *pk11_context;
    PyObject *py_pk11_context;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:create_digest_context", &hash_alg))
        return NULL;

    if ((pk11_context = PK11_CreateDigestContext(hash_alg)) == NULL) {
        return set_nspr_error(NULL);
    }

    if ((py_pk11_context =
         PyPK11Context_new_from_PK11Context(pk11_context)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create PK11Context object");
        return NULL;
    }

    return py_pk11_context;
}

PyDoc_STRVAR(pk11_param_from_iv_doc,
"param_from_iv(mechanism, iv=None) -> SecItem\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    iv : SecItem object\n\
        initialization vector. If there is no initialization vector you may also pass\n\
        None or an empty SecItem object (e.g. SecItem())\n\
\n\
Return a SecItem to be used as the initialization vector for encryption/decryption.\n\
");
static PyObject *
pk11_param_from_iv(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"mechanism", "iv", NULL};
    unsigned long mechanism;
    SecItem *py_iv;
    SECItem *sec_param;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "k|O&:param_from_iv", kwlist,
                                     &mechanism, SecItemOrNoneConvert, &py_iv))
        return NULL;

    if ((sec_param = PK11_ParamFromIV(mechanism, py_iv ? &py_iv->item : NULL)) == NULL) {
        return set_nspr_error(NULL);
    }

    // FIXME - SecItem_new_from_SECItem makes a copy, the sec_param should be freed)
    return SecItem_new_from_SECItem(sec_param, SECITEM_iv_param);
}

PyDoc_STRVAR(pk11_param_from_algid_doc,
"param_from_algid(algid) -> SecItem\n\
\n\
:Parameters:\n\
    algid : AlgorithmID object\n\
        algorithm id\n\
\n\
Return a SecItem containing a encryption param derived from a AlgorithmID.\n\
");
static PyObject *
pk11_param_from_algid(PyObject *self, PyObject *args)
{
    AlgorithmID *py_algorithm;
    SECItem *param;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O!:param_from_algid", &AlgorithmIDType, &py_algorithm))
        return NULL;

    if ((param = PK11_ParamFromAlgid(&py_algorithm->id)) == NULL) {
        return set_nspr_error(NULL);
    }

    return SecItem_new_from_SECItem(param, SECITEM_unknown);
}

PyDoc_STRVAR(pk11_generate_new_param_doc,
"generate_new_param(mechanism, sym_key=None) -> SecItem\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    sym_key : PK11SymKey object or None\n\
        symmetric key or None\n\
\n\
Return a SecItem containing a encryption param.\n\
");
static PyObject *
pk11_generate_new_param(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"mechanism", "sym_key", NULL};
    unsigned long mechanism;
    PyPK11SymKey *py_sym_key;
    SECItem *param;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "k|O&:generate_new_param", kwlist,
                                     &mechanism, SymKeyOrNoneConvert, &py_sym_key))
        return NULL;

    if ((param = PK11_GenerateNewParam(mechanism,
                                       py_sym_key ? py_sym_key->pk11_sym_key : NULL)) == NULL) {
        return set_nspr_error(NULL);
    }

    return SecItem_new_from_SECItem(param, SECITEM_unknown);
}

PyDoc_STRVAR(pk11_algtag_to_mechanism_doc,
"algtag_to_mechanism(algtag) -> mechanism\n\
\n\
:Parameters:\n\
    algtag : int\n\
        algorithm tag (e.g. SEC_OID_*)\n\
\n\
Returns the key mechanism enumeration constant (CKM_*)\n\
given an algorithm tag. Throws a KeyError exception if the \n\
algorithm tag is invalid.\n\
");
static PyObject *
pk11_algtag_to_mechanism(PyObject *self, PyObject *args)
{
    unsigned long algtag;
    unsigned long mechanism;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:algtag_to_mechanism", &algtag))
        return NULL;

    if ((mechanism = PK11_AlgtagToMechanism(algtag)) == CKM_INVALID_MECHANISM) {
	PyErr_Format(PyExc_KeyError, "algtag not found: %#lx", algtag);
        return NULL;
    }

    return PyInt_FromLong(mechanism);
}

PyDoc_STRVAR(pk11_mechanism_to_algtag_doc,
"mechanism_to_algtag(mechanism) -> algtag\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
\n\
Returns the algtag given key mechanism enumeration constant (CKM_*)\n\
Throws an KeyError exception if the mechanism is invalid.\n\
");
static PyObject *
pk11_mechanism_to_algtag(PyObject *self, PyObject *args)
{
    unsigned long algtag;
    unsigned long mechanism;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:mechanism_to_algtag", &mechanism))
        return NULL;

    if ((algtag = PK11_MechanismToAlgtag(mechanism)) == SEC_OID_UNKNOWN) {
	PyErr_Format(PyExc_KeyError, "mechanism not found: %#lx", mechanism);
        return NULL;
    }

    return PyInt_FromLong(algtag);
}
PyDoc_STRVAR(pk11_get_iv_length_doc,
"get_iv_length(mechanism) -> algtag\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
\n\
Returns the length of the mechanism's initialization vector.\n\
");
static PyObject *
pk11_get_iv_length(PyObject *self, PyObject *args)
{
    unsigned long mechanism;
    int iv_length;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:get_iv_length", &mechanism))
        return NULL;

    iv_length = PK11_GetIVLength(mechanism);

    return PyInt_FromLong(iv_length);
}

PyDoc_STRVAR(pk11_get_block_size_doc,
"get_block_size(mechanism, sec_param=None) -> int\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
    sec_param : SecItem object or None\n\
        mechanism parameters used to build this context or None.\n\
\n\
Get the mechanism block size\n\
");
static PyObject *
pk11_get_block_size(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"mechanism", "sec_param", NULL};
    unsigned long mechanism;
    SecItem *py_sec_param;
    int block_size;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "k|O&:get_block_size", kwlist,
                                     &mechanism, SecItemOrNoneConvert, &py_sec_param))
        return NULL;

    block_size = PK11_GetBlockSize(mechanism, py_sec_param ? &py_sec_param->item : NULL);

    return PyInt_FromLong(block_size);
}

PyDoc_STRVAR(pk11_get_pad_mechanism_doc,
"get_pad_mechanism(mechanism) -> int\n\
\n\
:Parameters:\n\
    mechanism : int\n\
        key mechanism enumeration constant (CKM_*)\n\
\n\
Determine appropriate mechanism to use when padding is required.\n\
If the mechanism does not map to a padding mechanism return the mechanism.\n\
");
static PyObject *
pk11_get_pad_mechanism(PyObject *self, PyObject *args)
{
    unsigned long mechanism;
    unsigned long pad_mechanism;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:get_pad_mechanism", &mechanism))
        return NULL;

    pad_mechanism = PK11_GetPadMechanism(mechanism);

    return PyInt_FromLong(pad_mechanism);
}

PyDoc_STRVAR(pk11_import_crl_doc,
"import_crl(slot, der_crl, url, type, import_options, decode_options, [user_data1, ...]) -> SignedCRL\n\
\n\
:Parameters:\n\
    slot : PK11Slot object\n\
        designated PK11 slot\n\
    der_crl : SecItem object\n\
        signed DER CRL data encapsulated in a SecItem object.\n\
    url : string\n\
        URL of the CRL\n\
    type : int\n\
        revocation list type\n\
        \n\
        may be one of:\n\
          - SEC_CRL_TYPE\n\
          - SEC_KRL_TYPE\n\
        \n\
    import_options : int\n\
        bit-wise OR of the following flags:\n\
          - CRL_IMPORT_BYPASS_CHECKS\n\
        \n\
        or use CRL_IMPORT_DEFAULT_OPTIONS\n\
    decode_options : int\n\
        bit-wise OR of the following flags:\n\
          - CRL_DECODE_DONT_COPY_DER\n\
          - CRL_DECODE_SKIP_ENTRIES\n\
          - CRL_DECODE_KEEP_BAD_CRL\n\
          - CRL_DECODE_ADOPT_HEAP_DER\n\
        \n\
        or use CRL_DECODE_DEFAULT_OPTIONS\n\
    user_dataN : object\n\
        zero or more caller supplied parameters which will\n\
        be passed to the password callback function\n\
\n\
\n\
");
static PyObject *
pk11_import_crl(PyObject *self, PyObject *args)
{
    Py_ssize_t n_base_args = 6;
    Py_ssize_t argc;
    PyObject *parse_args = NULL;
    PyObject *pin_args = NULL;
    PK11Slot *py_slot;
    char *url;
    int type;
    int import_options;
    int decode_options;
    SecItem *py_der_signed_crl;
    CERTSignedCrl *signed_crl;

    TraceMethodEnter(self);

    argc = PyTuple_Size(args);
    if (argc == n_base_args) {
        Py_INCREF(args);
        parse_args = args;
    } else {
        parse_args = PyTuple_GetSlice(args, 0, n_base_args);
    }

    if (!PyArg_ParseTuple(parse_args, "O!O!siii:import_crl",
                          &PK11SlotType, &py_slot,
                          &SecItemType, &py_der_signed_crl,
                          &url, &type, &import_options, &decode_options)) {
        Py_DECREF(parse_args);
        return NULL;
    }
    Py_DECREF(parse_args);

    pin_args = PyTuple_GetSlice(args, n_base_args, argc);

    Py_BEGIN_ALLOW_THREADS
    if ((signed_crl = PK11_ImportCRL(py_slot->slot, &py_der_signed_crl->item, url,
                                     type, pin_args, import_options, NULL, decode_options)) == NULL) {
	Py_BLOCK_THREADS
        Py_DECREF(pin_args);
        return set_nspr_error(NULL);
    }
    Py_END_ALLOW_THREADS

    Py_DECREF(pin_args);

    return SignedCRL_new_from_CERTSignedCRL(signed_crl);
}

PyDoc_STRVAR(pk11_create_pbev2_algorithm_id_doc,
"create_pbev2_algorithm_id(pbe_alg=SEC_OID_PKCS5_PBKDF2, cipher_alg=SEC_OID_AES_256_CBC, prf_alg=SEC_OID_HMAC_SHA1, key_length=0, iterations=100, salt=None) -> AlgorithmID \n\
\n\
:Parameters:\n\
    pbe_alg : may be one of integer, string or SecItem (see below)\n\
        password based encryption algorithm\n\
    cipher_alg : may be one of integer, string or SecItem (see below)\n\
        cipher algorithm\n\
    prf_alg : may be one of integer, string or SecItem (see below)\n\
        pseudo-random function algorithm\n\
    key_length : int\n\
        Number of octets in derived key DK. Must be a valid value for the\n\
        cipher_alg. If zero then NSS will select the longest key length\n\
        appropriate for the cipher\n\
    iterations : int\n\
        Number of times the pseudo-random function is applied to generate\n\
        the symmetric key.\n\
    salt : SecItem or str or any buffer compatible object or None\n\
        Cyrptographic salt. If None a random salt will be generated.\n\
\n\
The default values are appropriate for most users desiring a PKCS5v2\n\
PBE symmetric key.\n\
\n\
The pbe, cipher and prf algorithms may be specified in any of the\n\
following manners:\n\
\n\
    * integer:: A SEC OID enumeration constant, also known as a tag\n\
      (i.e. SEC_OID_*) for example SEC_OID_PKCS5_PBKDF2.\n\
    * string:: A string for the tag name\n\
      (e.g. 'SEC_OID_PKCS5_PBKDF2') The 'SEC_OID\\_' prefix is\n\
      optional. A string in dotted decimal representation, for\n\
      example 'OID.1.2.840.113549.1.5.12'.\n\
      The 'OID.' prefix is optional. Case is not significant.\n\
    * SecItem:: A SecItem object encapsulating the OID in \n\
          DER format.\n\
\n\
");

static PyObject *
pk11_create_pbev2_algorithm_id(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"pbe_alg", "cipher_alg", "prf_alg",
                             "key_length", "iterations", "salt", NULL};
    PyObject *py_pbe_alg = NULL;
    SECOidTag pbe_alg_tag = SEC_OID_PKCS5_PBKDF2;

    PyObject *py_cipher_alg = NULL;
    SECOidTag cipher_alg_tag = SEC_OID_AES_256_CBC;

    PyObject *py_prf_alg = NULL;
    SECOidTag prf_alg_tag = SEC_OID_HMAC_SHA1;

    int key_length = 0;
    int iterations = 100;

    PyObject *py_salt = NULL;
    SECItem salt_tmp_item;
    SECItem *salt_item = NULL;

    SECAlgorithmID *algid = NULL;
    PyObject *py_algorithm_id = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOOiiO:create_pbev2_algorithm_id", kwlist,
                                     &py_pbe_alg, &py_cipher_alg, &py_prf_alg,
                                     &key_length, &iterations, &py_salt))
        return NULL;

    if (py_pbe_alg) {
        if ((pbe_alg_tag = get_oid_tag_from_object(py_pbe_alg)) == -1) {
            return NULL;
        }
    }

    if (py_cipher_alg) {
        if ((cipher_alg_tag = get_oid_tag_from_object(py_cipher_alg)) == -1) {
            return NULL;
        }
    }

    if (py_prf_alg) {
        if ((prf_alg_tag = get_oid_tag_from_object(py_prf_alg)) == -1) {
            return NULL;
        }
    }

    if (SecItem_param(py_salt, &salt_item, &salt_tmp_item,
                      true, "salt") != SECSuccess) {
        return NULL;
    }

    if ((algid = PK11_CreatePBEV2AlgorithmID(pbe_alg_tag,
                                             cipher_alg_tag,
                                             prf_alg_tag,
                                             key_length,
                                             iterations,
                                             salt_item)) == NULL) {
        return set_nspr_error(NULL);
    }

    if ((py_algorithm_id = AlgorithmID_new_from_SECAlgorithmID(algid)) == NULL) {
        SECOID_DestroyAlgorithmID(algid, PR_TRUE);
        return NULL;
    }
    SECOID_DestroyAlgorithmID(algid, PR_TRUE);
    return py_algorithm_id;
}

PyDoc_STRVAR(cert_decode_der_crl_doc,
"decode_der_crl(der_crl, type=SEC_CRL_TYPE, decode_options=CRL_DECODE_DEFAULT_OPTIONS) -> SignedCRL\n\
\n\
:Parameters:\n\
    der_crl : SecItem object\n\
        DER encoded CRL data encapsulated in a SECItem.\n\
    type : int\n\
        revocation list type\n\
        \n\
        may be one of:\n\
          - SEC_CRL_TYPE\n\
          - SEC_KRL_TYPE\n\
    decode_options : int\n\
        bit-wise OR of the following flags:\n\
          - CRL_DECODE_DONT_COPY_DER\n\
          - CRL_DECODE_SKIP_ENTRIES\n\
          - CRL_DECODE_KEEP_BAD_CRL\n\
          - CRL_DECODE_ADOPT_HEAP_DER\n\
        \n\
        or use CRL_DECODE_DEFAULT_OPTIONS\n\
\n\
");

static PyObject *
cert_decode_der_crl(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"der_crl", "type", "decode_options", NULL};
    SecItem *py_der_crl;
    int type = SEC_CRL_TYPE;
    int decode_options = CRL_DECODE_DEFAULT_OPTIONS;
    CERTSignedCrl *signed_crl;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|ii:decode_der_crl", kwlist,
                                     &SecItemType, &py_der_crl,
                                     &py_der_crl, &type, &decode_options))
        return NULL;

    if ((signed_crl = CERT_DecodeDERCrlWithFlags(NULL, &py_der_crl->item, type,  decode_options)) == NULL) {
        return set_nspr_error(NULL);
    }

    return SignedCRL_new_from_CERTSignedCRL(signed_crl);
}

PyDoc_STRVAR(nss_read_der_from_file_doc,
"read_der_from_file(file, ascii=False) -> SecItem\n\
\n\
:Parameters:\n\
    file : file name or file object\n\
        If string treat as file path to open and read,\n\
        if file object read from file object.\n\
    ascii : bool\n\
        If True treat file contents as ascii data.\n\
        If PEM delimiters are found strip them.\n\
        Then base64 decode the contents.\n\
\n\
Read the contents of a file and return as a SecItem object.\n\
If file is a string then treat it as a file pathname and open\n\
and read the contents of that file. If file is a file object\n\
then read the contents from the file object\n\
\n\
If the file contents begin with a PEM header then treat the\n\
the file as PEM encoded and decode the payload into DER form.\n\
Otherwise the file contents is assumed to already be in DER form.\n\
The returned SecItem contains the DER contents of the file.\n\
");

static PyObject *
nss_read_der_from_file(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"file", "ascii", NULL};
    PyObject *file_arg;
    int ascii = 0;
    PyObject *py_sec_item;
    PyObject *py_file_contents;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:read_der_from_file", kwlist,
                                     &file_arg, &ascii))
        return NULL;

    if ((py_file_contents = read_data_from_file(file_arg)) == NULL) {
        goto fail;
    }

    if (ascii) {
        if ((py_sec_item = base64_to_SecItem(PyString_AsString(py_file_contents))) == NULL) {
            goto fail;
        }
    } else {
        SECItem der;

        der.data = (unsigned char *)PyString_AsString(py_file_contents);
        der.len = PyString_GET_SIZE(py_file_contents);
        der.type = siBuffer;

        if ((py_sec_item = SecItem_new_from_SECItem(&der, SECITEM_unknown)) == NULL) {
            goto fail;
        }
    }

    Py_DECREF(py_file_contents);
    return (PyObject *)py_sec_item;

 fail:
    Py_XDECREF(py_file_contents);
    return NULL;
}

PyDoc_STRVAR(nss_base64_to_binary_doc,
"base64_to_binary(text) -> SecItem\n\
\n\
:Parameters:\n\
    text : string\n\
        string containing base64 data.\n\
\n\
Convert the base64 encoded data to binary data.\n\
\n\
The text is assumed to contain base64 text. The base64 text may\n\
optionally be wrapped in a PEM header and footer.\n\
\n\
Returns a SecItem containg the binary data.\n\
\n\
Note, a SecItem can be initialized directly from base64 text by\n\
utilizing the ascii parameter to the SecItem constructor, thus\n\
the two are equivalent:\n\
\n\
    sec_item = nss.base64_to_binary(text)\n\
    sec_tiem = nss.SecItem(text, ascii=True)\n\
\n\
");

static PyObject *
nss_base64_to_binary(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"text", NULL};
    char *text = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s:base64_to_binary", kwlist,
                                     &text))
        return NULL;

    return base64_to_SecItem(text);
}

PyDoc_STRVAR(cert_x509_key_usage_doc,
"x509_key_usage(bitstr, repr_kind=AsEnumDescription) -> (str, ...)\n\
\n\
:Parameters:\n\
    bitstr : SecItem object\n\
        A SecItem containing a DER encoded bit string.\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant.\n\
            (e.g. nss.KU_DIGITAL_SIGNATURE)\n\
        AsEnumDescription\n\
            A friendly human readable description of the enumerated constant as a string.\n\
             (e.g. \"Digital Signature\")\n\
        AsIndex\n\
            The bit position within the bit string.\n\
\n\
Return a tuple of string name for each enabled bit in the key\n\
usage bit string.\n\
");

static PyObject *
cert_x509_key_usage(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"bitstr", "repr_kind", NULL};
    PyObject *result;
    SecItem *py_sec_item;
    SECItem bitstr_item;
    int repr_kind = AsEnumDescription;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|i:x509_key_usage", kwlist,
                                     &SecItemType, &py_sec_item, &repr_kind))
        return NULL;

    if (der_bitstring_to_nss_bitstring(&bitstr_item, &py_sec_item->item) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    result = key_usage_bitstr_to_tuple(&bitstr_item, repr_kind);

    return result;
}

PyDoc_STRVAR(cert_x509_cert_type_doc,
"x509_cert_type(bitstr, repr_kind=AsEnumDescription) -> (str, ...)\n\
\n\
:Parameters:\n\
    bitstr : SecItem object\n\
        A SecItem containing a DER encoded bit string.\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant.\n\
            (e.g. nss.NS_CERT_TYPE_SSL_SERVER)\n\
        AsEnumDescription\n\
            A friendly human readable description of the enumerated constant as a string.\n\
             (e.g. \"SSL Server\")\n\
        AsIndex\n\
            The bit position within the bit string.\n\
\n\
Return a tuple of string name for each enabled bit in the key\n\
usage bit string.\n\
");

static PyObject *
cert_x509_cert_type(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"bitstr", "repr_kind", NULL};
    PyObject *result;
    SecItem *py_sec_item;
    SECItem bitstr_item;
    int repr_kind = AsEnumDescription;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|i:x509_cert_type", kwlist,
                                     &SecItemType, &py_sec_item, &repr_kind))
        return NULL;

    if (der_bitstring_to_nss_bitstring(&bitstr_item, &py_sec_item->item) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    result = cert_type_bitstr_to_tuple(&bitstr_item, repr_kind);

    return result;
}

PyDoc_STRVAR(cert_x509_ext_key_usage_doc,
"x509_ext_key_usage(sec_item, repr_kind=AsString) -> (obj, ...)\n\
\n\
:Parameters:\n\
    sec_item : SecItem object\n\
        A SecItem containing a DER encoded sequence of OID's\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsObject\n\
            Each extended key usage will be a SecItem object embedding\n\
            the OID in DER format.\n\
        AsString\n\
            Each extended key usage will be a descriptive string.\n\
            (e.g. \"TLS Web Server Authentication Certificate\")\n\
        AsDottedDecimal\n\
            Each extended key usage will be OID rendered as a dotted decimal string.\n\
            (e.g. \"OID.1.3.6.1.5.5.7.3.1\")\n\
        AsEnum\n\
            Each extended key usage will be OID tag enumeration constant (int).\n\
            (e.g. nss.SEC_OID_EXT_KEY_USAGE_SERVER_AUTH)\n\
\n\
Return a tuple of OID's according the representation kind.\n\
");

static PyObject *
cert_x509_ext_key_usage(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"sec_item", "repr_kind", NULL};
    SecItem *py_sec_item;
    int repr_kind = AsString;

    if (!PyArg_ParseTupleAndKeywords(args, kwds,"O!|i:x509_ext_key_usage", kwlist,
                          &SecItemType, &py_sec_item, &repr_kind))
        return NULL;

    return decode_oid_sequence_to_tuple(&py_sec_item->item, repr_kind);
}


PyDoc_STRVAR(cert_x509_alt_name_doc,
"x509_alt_name(sec_item, repr_kind=AsString) -> (SecItem, ...)\n\
\n\
:Parameters:\n\
    sec_item : SecItem object\n\
        A SecItem containing a DER encoded alternative name extension.\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned tuple will be.\n\
        May be one of:\n\
\n\
        AsObject\n\
            The general name as a nss.GeneralName object\n\
        AsString\n\
            The general name as a string.\n\
            (e.g. \"http://crl.geotrust.com/crls/secureca.crl\")\n\
        AsTypeString\n\
            The general name type as a string.\n\
             (e.g. \"URI\")\n\
        AsTypeEnum\n\
            The general name type as a general name type enumerated constant.\n\
             (e.g. nss.certURI )\n\
        AsLabeledString\n\
            The general name as a string with it's type prepended.\n\
            (e.g. \"URI: http://crl.geotrust.com/crls/secureca.crl\"\n\
\n\
Return a tuple of GeneralNames according the representation kind.\n\
");

static PyObject *
cert_x509_alt_name(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"sec_item", "repr_kind", NULL};
    SecItem *py_sec_item;
    int repr_kind = AsString;
    CERTGeneralName *names;
    PLArenaPool *arena;
    PyObject *result;


    if (!PyArg_ParseTupleAndKeywords(args, kwds,"O!|i:x509_alt_name", kwlist,
                          &SecItemType, &py_sec_item, &repr_kind))
        return NULL;

    if ((arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE)) == NULL ) {
        return set_nspr_error(NULL);
    }

    if ((names = CERT_DecodeAltNameExtension(arena, &py_sec_item->item)) == NULL) {
        set_nspr_error(NULL);
        PORT_FreeArena(arena, PR_FALSE);
        return NULL;
    }

    result = CERTGeneralName_list_to_tuple(names, repr_kind);
    PORT_FreeArena(arena, PR_FALSE);
    return result;
}


static PyObject *
crl_reason_to_pystr(CERTCRLEntryReasonCode reason)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyInt_FromLong(reason)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create object");
        return NULL;
    }

    if ((py_name = PyDict_GetItem(crl_reason_value_to_name, py_value)) == NULL) {
        Py_DECREF(py_value);
	PyErr_Format(PyExc_KeyError, "CRL reason name not found: %u", reason);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}

PyDoc_STRVAR(cert_crl_reason_name_doc,
"crl_reason_name(reason) -> string\n\
\n\
:Parameters:\n\
    reason : int\n\
        CERTCRLEntryReasonCode constant\n\
\n\
Given a CERTCRLEntryReasonCode constant\n\
return it's name as a string\n\
");
static PyObject *
cert_crl_reason_name(PyObject *self, PyObject *args)
{
    unsigned long reason;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:crl_reason_name", &reason))
        return NULL;

    return crl_reason_to_pystr(reason);
}

PyDoc_STRVAR(cert_crl_reason_from_name_doc,
"crl_reason_from_name(name) -> int\n\
\n\
:Parameters:\n\
    name : string\n\
        name of CERTCRLEntryReasonCode constant\n\
\n\
Given the name of a CERTCRLEntryReasonCode constant\n\
return it's integer constant\n\
The string comparison is case insensitive and will match with\n\
or without the crlEntry prefix\n\
");
static PyObject *
cert_crl_reason_from_name(PyObject *self, PyObject *args)
{
    PyObject *py_name;
    PyObject *py_lower_name;
    PyObject *py_value;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "S:crl_reason_from_name", &py_name))
        return NULL;

    if ((py_lower_name = PyObject_CallMethod(py_name, "lower", NULL)) == NULL) {
        return NULL;
    }

    if ((py_value = PyDict_GetItem(crl_reason_name_to_value, py_lower_name)) == NULL) {
	PyErr_Format(PyExc_KeyError, "CRL reason name not found: %s", PyString_AsString(py_name));
        Py_DECREF(py_lower_name);
        return NULL;
    }

    Py_DECREF(py_lower_name);
    Py_INCREF(py_value);

    return py_value;
}

static PyObject *
pkcs12_cipher_to_pystr(long cipher)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyInt_FromLong(cipher)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create object");
        return NULL;
    }

    if ((py_name = PyDict_GetItem(pkcs12_cipher_value_to_name, py_value)) == NULL) {
        Py_DECREF(py_value);
	PyErr_Format(PyExc_KeyError, "PKCS12 cipher name not found: %ld", cipher);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}

PyDoc_STRVAR(pkcs12_cipher_name_doc,
"pkcs12_cipher_name(cipher) -> string\n\
\n\
:Parameters:\n\
    cipher : int\n\
        PKCS12_* constant\n\
\n\
Given a PKCS12_* constant\n\
return it's name as a string\n\
");
static PyObject *
pkcs12_cipher_name(PyObject *self, PyObject *args)
{
    unsigned long cipher;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:pkcs12_cipher_name", &cipher))
        return NULL;

    return pkcs12_cipher_to_pystr(cipher);
}

PyDoc_STRVAR(pkcs12_cipher_from_name_doc,
"pkcs12_cipher_from_name(name) -> int\n\
\n\
:Parameters:\n\
    name : string\n\
        name of PKCS12_* constant\n\
\n\
Given the name of a PKCS12_* constant\n\
return it's integer constant\n\
The string comparison is case insensitive and will match with\n\
or without the PKCS12\\_ prefix\n\
");
static PyObject *
pkcs12_cipher_from_name(PyObject *self, PyObject *args)
{
    PyObject *py_name;
    PyObject *py_lower_name;
    PyObject *py_value;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "S:pkcs12_cipher_from_name", &py_name))
        return NULL;

    if ((py_lower_name = PyObject_CallMethod(py_name, "lower", NULL)) == NULL) {
        return NULL;
    }

    if ((py_value = PyDict_GetItem(pkcs12_cipher_name_to_value, py_lower_name)) == NULL) {
	PyErr_Format(PyExc_KeyError, "PKCS12 cipher name not found: %s", PyString_AsString(py_name));
        Py_DECREF(py_lower_name);
        return NULL;
    }

    Py_DECREF(py_lower_name);
    Py_INCREF(py_value);

    return py_value;
}

PyDoc_STRVAR(pkcs12_map_cipher_doc,
"pkcs12_map_cipher(cipher, key_length=0) -> int\n\
\n\
:Parameters:\n\
    cipher : may be one of integer, string or SecItem\n\
        May be one of:\n\
\n\
        * integer:: A SEC OID enumeration constant, also known as a tag\n\
          (i.e. SEC_OID_*) for example SEC_OID_DES_EDE3_CBC.\n\
        * string:: A string for the tag name\n\
          (e.g. 'SEC_OID_DES_EDE3_CBC') The 'SEC_OID\\_' prefix is\n\
          optional. A string in dotted decimal representation, for\n\
          example 'OID.2.5.4.3'. The 'OID.' prefix is optional.  Case\n\
          is not significant.\n\
        * SecItem:: A SecItem object encapsulating the OID in \n\
          DER format.\n\
    key_length : int\n\
        The number of bits in the key. If zero a default will be selected.\n\
\n\
Given an cipher and optionally a key length, map that to a PKCS12 encryption\n\
method returned as a SEC_OID tag.\n\
");
static PyObject *
pkcs12_map_cipher(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"cipher", "key_length", NULL};
    PyObject *py_cipher;
    int key_length;
    int tag;
    SECOidTag cipher_tag = SEC_OID_UNKNOWN;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:pkcs12_map_cipher", kwlist,
                                     &py_cipher, &key_length))
        return NULL;

    if ((tag = get_oid_tag_from_object(py_cipher)) == -1) {
        return NULL;
    }

    if (!SEC_PKCS5IsAlgorithmPBEAlgTag(tag)) {
        cipher_tag = SEC_PKCS5GetPBEAlgorithm(tag, key_length);
        /* no eqivalent PKCS5/PKCS12 cipher, use the raw
         * encryption tag we got and pass it directly in,
         * pkcs12 will use the pkcsv5 mechanism */
        if (cipher_tag == SEC_OID_PKCS5_PBES2) {
            cipher_tag = tag;
        } else if (cipher_tag == SEC_OID_PKCS5_PBMAC1) {
            /* make sure we do not have MAC'ing ciphers here */
            cipher_tag = SEC_OID_UNKNOWN;
        }
    } else {
        cipher_tag = tag;
    }

    return PyInt_FromLong(cipher_tag);
}

static PyObject *
general_name_type_to_pystr(CERTGeneralNameType type)
{
    PyObject *py_value;
    PyObject *py_name;

    if ((py_value = PyInt_FromLong(type)) == NULL) {
        PyErr_SetString(PyExc_MemoryError, "unable to create object");
        return NULL;
    }

    if ((py_name = PyDict_GetItem(general_name_value_to_name, py_value)) == NULL) {
        Py_DECREF(py_value);
	PyErr_Format(PyExc_KeyError, "GeneralName type name not found: %u", type);
        return NULL;
    }

    Py_DECREF(py_value);
    Py_INCREF(py_name);

    return py_name;
}

PyDoc_STRVAR(cert_general_name_type_name_doc,
"general_name_type_name(type) -> string\n\
\n\
:Parameters:\n\
    type : int\n\
        CERTGeneralNameType constant\n\
\n\
Given a CERTGeneralNameType constant\n\
return it's name as a string\n\
");
static PyObject *
cert_general_name_type_name(PyObject *self, PyObject *args)
{
    unsigned long type;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "k:general_name_type_name", &type))
        return NULL;

    return general_name_type_to_pystr(type);
}

PyDoc_STRVAR(cert_general_name_type_from_name_doc,
"general_name_type_from_name(name) -> int\n\
\n\
:Parameters:\n\
    name : string\n\
        name of CERTGeneralNameType constant\n\
\n\
Given the name of a CERTGeneralNameType constant\n\
return it's integer constant\n\
The string comparison is case insensitive and will match with\n\
or without the cert prefix\n\
");
static PyObject *
cert_general_name_type_from_name(PyObject *self, PyObject *args)
{
    PyObject *py_name;
    PyObject *py_lower_name;
    PyObject *py_value;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "S:general_name_type_from_name", &py_name))
        return NULL;

    if ((py_lower_name = PyObject_CallMethod(py_name, "lower", NULL)) == NULL) {
        return NULL;
    }

    if ((py_value = PyDict_GetItem(general_name_name_to_value, py_lower_name)) == NULL) {
	PyErr_Format(PyExc_KeyError, "GeneralName type name not found: %s", PyString_AsString(py_name));
        Py_DECREF(py_lower_name);
        return NULL;
    }

    Py_DECREF(py_lower_name);
    Py_INCREF(py_value);

    return py_value;
}

PyDoc_STRVAR(cert_cert_usage_flags_doc,
"cert_usage_flags(flags, repr_kind=AsEnumDescription) -> ['flag_name', ...]\n\
\n\
:Parameters:\n\
    flags : int\n\
        certificateUsage* bit flags\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned list will be.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsEnumDescription\n\
            A friendly human readable description of the enumerated constant as a string.\n\
\n\
Given an integer with certificateUsage*\n\
(e.g. nss.certificateUsageSSLServer) bit flags return a sorted\n\
list of their string names.\n\
");

static PyObject *
cert_cert_usage_flags(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"flags", "repr_kind", NULL};
    int flags = 0;
    RepresentationKind repr_kind = AsEnumDescription;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|i:cert_usage_flags", kwlist,
                                     &flags, &repr_kind))
        return NULL;

    return cert_usage_flags(flags, repr_kind);
}

PyDoc_STRVAR(cert_key_usage_flags_doc,
"key_usage_flags(flags, repr_kind=AsEnumName) -> ['flag_name', ...]\n\
\n\
:Parameters:\n\
    flags : int\n\
        KU_* bit flags\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned list will be.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsEnumDescription\n\
            A friendly human readable description of the enumerated constant as a string.\n\
\n\
Given an integer with KU_*\n\
(e.g. nss.KU_DIGITAL_SIGNATURE) bit flags return a sorted\n\
list of their string names.\n\
");

static PyObject *
cert_key_usage_flags(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"flags", "repr_kind", NULL};
    int flags = 0;
    RepresentationKind repr_kind = AsEnumName;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|i:key_usage_flags", kwlist,
                                     &flags, &repr_kind))
        return NULL;

    return key_usage_flags(flags, repr_kind);
}

PyDoc_STRVAR(cert_cert_type_flags_doc,
"cert_type_flags(flags, repr_kind=AsEnumName) -> ['flag_name', ...]\n\
\n\
:Parameters:\n\
    flags : int\n\
        KU_* bit flags\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned list will be.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsEnumDescription\n\
            A friendly human readable description of the enumerated constant as a string.\n\
\n\
\n\
Given an integer with NS_CERT_TYPE_*\n\
(e.g. nss.NS_CERT_TYPE_SSL_SERVER) bit flags return a sorted\n\
list of their string names.\n\
");

static PyObject *
cert_cert_type_flags(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"flags", "repr_kind", NULL};
    int flags = 0;
    RepresentationKind repr_kind = AsEnumName;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|i:cert_type_flags", kwlist,
                          &flags, &repr_kind))
        return NULL;

    return cert_type_flags(flags, repr_kind);
}

PyDoc_STRVAR(nss_nss_init_flags_doc,
"nss_init_flags(flags, repr_kind=AsEnumName) -> ['flag_name', ...]\n\
\n\
:Parameters:\n\
    flags : int\n\
        NSS_INIT* bit flags\n\
    repr_kind : RepresentationKind constant\n\
        Specifies what the contents of the returned list will be.\n\
        May be one of:\n\
\n\
        AsEnum\n\
            The enumerated constant as an integer value.\n\
        AsEnumName\n\
            The name of the enumerated constant as a string.\n\
        AsEnumDescription\n\
            A friendly human readable description of the enumerated constant as a string.\n\
\n\
\n\
Given an integer with NSS_INIT*\n\
(e.g. nss.NSS_INIT_READONLY) bit flags return a sorted\n\
list of their string names.\n\
");

static PyObject *
nss_nss_init_flags(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"flags", "repr_kind", NULL};
    int flags = 0;
    RepresentationKind repr_kind = AsEnumName;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:nss_init_flags", kwlist,
                          &flags, &repr_kind))
        return NULL;

    return nss_init_flags(flags, repr_kind);
}

PyDoc_STRVAR(pkcs12_enable_cipher_doc,
"pkcs12_enable_cipher(cipher, enabled)\n\
\n\
:Parameters:\n\
    cipher : integer\n\
        The PKCS12 cipher suite enumeration (e.g. `PKCS12_DES_EDE3_168`, etc.)\n\
    enabled : bool or int\n\
        True enables, False disables\n\
\n\
The cipher may be one of: \n\
    - PKCS12_RC2_CBC_40 \n\
    - PKCS12_RC2_CBC_128 \n\
    - PKCS12_RC4_40 \n\
    - PKCS12_RC4_128 \n\
    - PKCS12_DES_56 \n\
    - PKCS12_DES_EDE3_168 \n\
");

static PyObject *
pkcs12_enable_cipher(PyObject *self, PyObject *args)
{
    long cipher;
    int enabled;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "li:pkcs12_enable_cipher", &cipher, &enabled))
        return NULL;

    if (SEC_PKCS12EnableCipher(cipher, enabled ? PR_TRUE : PR_FALSE) != SECSuccess) {
        PyObject *py_cipher_name = pkcs12_cipher_to_pystr(cipher);
        PyObject *py_err_msg = PyString_FromFormat("Failed to %s %s (%lx) pkcs12 cipher",
                                                   enabled ? _("enable") : _("disable"),
                                                   PyString_AsString(py_cipher_name), cipher);
        set_nspr_error("%s", PyString_AsString(py_err_msg));
        Py_DECREF(py_cipher_name);
        Py_DECREF(py_err_msg);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pkcs12_enable_all_ciphers_doc,
"pkcs12_enable_all_ciphers()\n\
\n\
Enables all PKCS12 ciphers, which are: \n\
    - `PKCS12_RC2_CBC_40` \n\
    - `PKCS12_RC2_CBC_128` \n\
    - `PKCS12_RC4_40` \n\
    - `PKCS12_RC4_128` \n\
    - `PKCS12_DES_56` \n\
    - `PKCS12_DES_EDE3_168` \n\
");

static PyObject *
pkcs12_enable_all_ciphers(PyObject *self, PyObject *args)
{
    int i;
    long cipher;
    long all_ciphers[] = {PKCS12_RC4_40,
                          PKCS12_RC4_128,
                          PKCS12_RC2_CBC_40,
                          PKCS12_RC2_CBC_128,
                          PKCS12_DES_56,
                          PKCS12_DES_EDE3_168};

    TraceMethodEnter(self);

    for (i = 0; i < sizeof(all_ciphers)/sizeof(all_ciphers[0]); i++) {
        cipher = all_ciphers[i];
        if (SEC_PKCS12EnableCipher(cipher, PR_TRUE) != SECSuccess) {
            PyObject *py_cipher_name = pkcs12_cipher_to_pystr(cipher);
            PyObject *py_err_msg = PyString_FromFormat("Failed to enable %s (%lx) pkcs12 cipher",
                                                       PyString_AsString(py_cipher_name), cipher);
            set_nspr_error("%s", PyString_AsString(py_err_msg));
            Py_DECREF(py_cipher_name);
            Py_DECREF(py_err_msg);
            return NULL;
        }
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pkcs12_set_preferred_cipher_doc,
"pkcs12_set_preferred_cipher(cipher, enabled)\n\
\n\
:Parameters:\n\
    cipher : integer\n\
        The PKCS12 cipher suite enumeration (e.g. `PKCS12_DES_EDE3_168`, etc.)\n\
    enabled : bool or int\n\
        True enables, False disables\n\
\n\
This function enables or disables the preferred flag on a \n\
PKCS cipher. The default preferred cipher is `PKCS12_RC2_CBC_40`.\n\
\n\
The cipher may be one of: \n\
    - `PKCS12_RC2_CBC_40` \n\
    - `PKCS12_RC2_CBC_128` \n\
    - `PKCS12_RC4_40` \n\
    - `PKCS12_RC4_128` \n\
    - `PKCS12_DES_56` \n\
    - `PKCS12_DES_EDE3_168` \n\
");

static PyObject *
pkcs12_set_preferred_cipher(PyObject *self, PyObject *args)
{
    long cipher;
    int enabled;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "li:pkcs12_set_preferred_cipher", &cipher, &enabled))
        return NULL;

    if (SEC_PKCS12SetPreferredCipher(cipher, enabled ? PR_TRUE : PR_FALSE) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

static void
pkcs12_export_feed(void *arg, const char *buf, unsigned long len)
{
    PyObject **py_encoded_buf = arg;
    PyObject *py_new_string = NULL;

    if (*py_encoded_buf == NULL) {
	return;
    }

    if ((py_new_string = PyString_FromStringAndSize(buf, len)) == NULL) {
        Py_CLEAR(*py_encoded_buf);
        return;
    }

    PyString_ConcatAndDel(py_encoded_buf, py_new_string);
}

PyDoc_STRVAR(pkcs12_export_doc,
"pkcs12_export(nickname, pkcs12_password, key_cipher=SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC, cert_cipher=SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC, pin_args=None) \n\
\n\
:Parameters:\n\
    nickname : string\n\
        Certificate nickname to search for.\n\
    pkcs12_password : string\n\
        The password used to protect the pkcs12_file.\n\
    key_cipher : int\n\
        A SEC OID TAG enumerated constant selecting the\n\
        encryption for the private key (see below).\n\
        Also see `nss.pkcs12_map_cipher()` for an alternative\n\
        method to select the encryption cipher.\n\
    cert_cipher : int\n\
        A SEC OID TAG enumerated constant selecting the\n\
        encryption for the certificates (see below).\n\
        Also see `nss.pkcs12_map_cipher()` for an alternative\n\
        method to select the encryption cipher.\n\
    pin_args : tuple\n\
        Extra parameters which will\n\
        be passed to the password callback function.\n\
\n\
pkcs12_export() is used to export a certificate and private key pair\n\
from the NSS database in a protected manner. It produces the binary\n\
content of what is typically called a .p12 file (e.g. PKCS12). This\n\
function does not write the file, if you want to write a .p12 file\n\
you must write it's output to a file, for example:\n\
\n\
::\n\
\n\
    pkcs12_data = nss.pkcs12_export(nickname, pkcs12_file_password)\n\
    f = open(p12_file_path, 'w')\n\
    f.write(pkcs12_data)\n\
    f.close()\n\
\n\
Password Based Encryption\n\
-------------------------\n\
\n\
PKCS #12 provides for not only the protection of the private keys but\n\
also the certificate and meta-data associated with the keys. Password\n\
based encryption is used to protect private keys (i.e. key_cipher) on\n\
export to a PKCS #12 file and also the entire package when allowed\n\
(i.e. cert_cipher). If no algorithm is specified it defaults to using\n\
'PKCS #12 V2 PBE With SHA-1 And 3KEY Triple DES-CBC' for private key\n\
encryption. For historical export control reasons 'PKCS #12 V2 PBE\n\
With SHA-1 And 40 Bit RC2 CBC' is the default for the overall package\n\
encryption when not in FIPS mode and no package encryption when in\n\
FIPS mode. The private key is always protected with strong encryption\n\
by default.\n\
\n\
A list of ciphers follows, the term is the SEC OID TAG followd by a\n\
friendly description.\n\
\n\
* symmetric CBC ciphers for PKCS #5 V2:\n\
    SEC_OID_DES_CBC\n\
        DES-CBC.\n\
    SEC_OID_RC2_CBC\n\
        RC2-CBC.\n\
    SEC_OID_RC5_CBC_PAD\n\
        RC5-CBCPad.\n\
    SEC_OID_DES_EDE3_CBC\n\
        DES-EDE3-CBC.\n\
    SEC_OID_AES_128_CBC\n\
        AES-128-CBC.\n\
    SEC_OID_AES_192_CBC\n\
        AES-192-CBC.\n\
    SEC_OID_AES_256_CBC\n\
        AES-256-CBC.\n\
    SEC_OID_CAMELLIA_128_CBC\n\
        CAMELLIA-128-CBC.\n\
    SEC_OID_CAMELLIA_192_CBC\n\
        CAMELLIA-192-CBC.\n\
    SEC_OID_CAMELLIA_256_CBC\n\
        CAMELLIA-256-CBC.\n\
\n\
* PKCS #12 PBE Ciphers:\n\
    SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4\n\
        PKCS #12 PBE With SHA-1 and 128 Bit RC4.\n\
    SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4\n\
        PKCS #12 PBE With SHA-1 and 40 Bit RC4.\n\
    SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC\n\
        PKCS #12 PBE With SHA-1 and Triple DES-CBC.\n\
    SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC\n\
        PKCS #12 PBE With SHA-1 and 128 Bit RC2 CBC.\n\
    SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC\n\
        PKCS #12 PBE With SHA-1 and 40 Bit RC2 CBC.\n\
    SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4\n\
        PKCS #12 V2 PBE With SHA-1 And 128 Bit RC4.\n\
    SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4\n\
        PKCS #12 V2 PBE With SHA-1 And 40 Bit RC4.\n\
    SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC\n\
        PKCS #12 V2 PBE With SHA-1 And 3KEY Triple DES-CBC.\n\
    SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC\n\
        PKCS #12 V2 PBE With SHA-1 And 2KEY Triple DES-CBC.\n\
    SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC\n\
        PKCS #12 V2 PBE With SHA-1 And 128 Bit RC2 CBC.\n\
    SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC\n\
        PKCS #12 V2 PBE With SHA-1 And 40 Bit RC2 CBC.\n\
\n\
* PKCS #5 PBE Ciphers:\n\
    SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC\n\
        PKCS #5 Password Based Encryption with MD2 and DES-CBC.\n\
    SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC\n\
        PKCS #5 Password Based Encryption with MD5 and DES-CBC.\n\
    SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC\n\
        PKCS #5 Password Based Encryption with SHA-1 and DES-CBC.\n\
\n\
");

static PyObject *
pkcs12_export(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"nickname", "pkcs12_password", "key_cipher",
                             "cert_cipher", "pin_args", NULL};
    char *utf8_nickname = NULL;
    char *utf8_pkcs12_password = NULL;
    Py_ssize_t utf8_pkcs12_password_len = 0;
    unsigned int key_cipher = SEC_OID_UNKNOWN;
    unsigned int cert_cipher = SEC_OID_UNKNOWN;
    PyObject *pin_args = Py_None;
    PyObject *py_encoded_buf = NULL;

    SEC_PKCS12ExportContext *export_ctx = NULL;
    SEC_PKCS12SafeInfo *key_safe = NULL, *cert_safe = NULL;
    SECItem utf8_pkcs12_password_item = {siUTF8String, NULL, 0};
    CERTCertList* cert_list = NULL;
    CERTCertListNode* node = NULL;
    PK11SlotInfo* slot = NULL;

    TraceMethodEnter(self);

    /*
     * NSS WART
     * Despite the name UCS2_ASCIIConversion it's really UCS2 <-> arbitrary_encoding.
     */
    PORT_SetUCS2_ASCIIConversionFunction(secport_ucs2_to_utf8);

    key_cipher = SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC;
    cert_cipher = PK11_IsFIPS() ? SEC_OID_UNKNOWN : SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "eses#|IIO&:pkcs12_export", kwlist,
                                     "utf-8", &utf8_nickname,
                                     "utf-8", &utf8_pkcs12_password, &utf8_pkcs12_password_len,
                                     &key_cipher, &cert_cipher,
                                     TupleOrNoneConvert, &pin_args))
        return NULL;

    utf8_pkcs12_password_item.len = utf8_pkcs12_password_len;
    utf8_pkcs12_password_item.data = (unsigned char *)utf8_pkcs12_password;
    if (PyNone_Check(pin_args)) {
        pin_args = NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    if ((cert_list = PK11_FindCertsFromNickname(utf8_nickname, pin_args)) == NULL) {
	Py_BLOCK_THREADS
        PyErr_Format(PyExc_ValueError, "failed to find certs for nickname = \"%s\"", utf8_nickname);
        goto exit;
    }
    Py_END_ALLOW_THREADS

    /* User certs are those with private keys, retain only those */
    if (CERT_FilterCertListForUserCerts(cert_list) != SECSuccess ||
        CERT_LIST_EMPTY(cert_list)) {
        PyErr_Format(PyExc_ValueError, "no certs with keys for nickname = \"%s\"", utf8_nickname);
        goto exit;
    }

    if (cert_list) {
        CERTCertificate* cert = NULL;
        node = CERT_LIST_HEAD(cert_list);
        if (node) {
            cert = node->cert;
        }
        if (cert) {
            /* Use the slot from the first matching certificate to
             * create the context. This is for keygen */
            slot = cert->slot;
        }
    }

    if (!slot) {
        PyErr_SetString(PyExc_ValueError, "cert does not have a slot");
        goto exit;
    }

    if ((export_ctx = SEC_PKCS12CreateExportContext(NULL, NULL, slot, pin_args)) == NULL) {
        set_nspr_error("export context creation failed");
        goto exit;
    }

    if (SEC_PKCS12AddPasswordIntegrity(export_ctx, &utf8_pkcs12_password_item, SEC_OID_SHA1) != SECSuccess) {
        set_nspr_error("PKCS12 add password integrity failed");
        goto exit;
    }

    for (node = CERT_LIST_HEAD(cert_list); !CERT_LIST_END(node,cert_list); node = CERT_LIST_NEXT(node)) {
        CERTCertificate* cert = node->cert;
        if (!cert->slot) {
            PyErr_SetString(PyExc_ValueError, "cert does not have a slot");
            goto exit;
        }

        key_safe = SEC_PKCS12CreateUnencryptedSafe(export_ctx);
        if (cert_cipher == SEC_OID_UNKNOWN) {
            cert_safe = key_safe;
        } else {
            cert_safe = SEC_PKCS12CreatePasswordPrivSafe(export_ctx, &utf8_pkcs12_password_item, cert_cipher);
        }

        if (!cert_safe || !key_safe) {
            PyErr_SetString(PyExc_ValueError, "key or cert safe creation failed");
            goto exit;
        }

        if (SEC_PKCS12AddCertAndKey(export_ctx, cert_safe, NULL, cert,
                                    CERT_GetDefaultCertDB(), key_safe, NULL,
                                    PR_TRUE, &utf8_pkcs12_password_item, key_cipher) != SECSuccess) {
            set_nspr_error("add cert and key failed");
            goto exit;
        }
    }

    if ((py_encoded_buf = PyString_FromStringAndSize(NULL, 0)) == NULL) {
        goto exit;
    }

    if (SEC_PKCS12Encode(export_ctx, pkcs12_export_feed, &py_encoded_buf) != SECSuccess) {
        set_nspr_error("PKCS12 encode failed");
        Py_CLEAR(py_encoded_buf);
        goto exit;
    }

 exit:
    if (utf8_nickname) {
        PyMem_Free(utf8_nickname);
    }
    if (utf8_pkcs12_password) {
        PyMem_Free(utf8_pkcs12_password);
    }
    if (cert_list) {
        CERT_DestroyCertList(cert_list);
    }
    if (export_ctx) {
        SEC_PKCS12DestroyExportContext(export_ctx);
    }

    return py_encoded_buf;
}

PyDoc_STRVAR(nss_fingerprint_format_lines_doc,
"fingerprint_format_lines(data, level=0) -> \n\
\n\
:Parameters:\n\
    data : SecItem or str or any buffer compatible object\n\
        Data to initialize the certificate request from, must be in DER format\n\
    level : integer\n\
        Initial indentation level, all subsequent indents are relative\n\
        to this starting level.\n\
\n\
Generates digests of data (i.e. fingerprint) and formats\n\
it into line tuples for text output.\n\
");

static PyObject *
nss_fingerprint_format_lines(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"data", "level", NULL};
    int level = 0;
    PyObject *py_data = NULL;
    SECItem tmp_item;
    SECItem *der_item = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i:fingerprint_format_lines", kwlist,
                                     &py_data, &level))
        return NULL;

    // FIXME: Should this be SecItem_param()?
    if (PySecItem_Check(py_data)) {
        der_item = &((SecItem *)py_data)->item;
    } else if (PyObject_CheckReadBuffer(py_data)) {
        unsigned char *data = NULL;
        Py_ssize_t data_len;

        if (PyObject_AsReadBuffer(py_data, (void *)&data, &data_len))
            return NULL;

        tmp_item.data = data;
        tmp_item.len = data_len;
        der_item = &tmp_item;
    } else {
        PyErr_SetString(PyExc_TypeError, "data must be SecItem or buffer compatible");
        return NULL;
    }

    return fingerprint_format_lines(der_item, level);
}

PyDoc_STRVAR(cert_get_use_pkix_for_validation_doc,
"get_use_pkix_for_validation() -> flag\n\
\n\
Returns the current value of the flag used to enable or disable the\n\
use of PKIX for certificate validation. See also:\n\
`set_use_pkix_for_validation`.\n\
");

static PyObject *
cert_get_use_pkix_for_validation(PyObject *self, PyObject *args)
{
    PRBool flag;

    TraceMethodEnter(self);

    flag = CERT_GetUsePKIXForValidation();

    if (flag) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

PyDoc_STRVAR(cert_set_use_pkix_for_validation_doc,
"set_use_pkix_for_validation(flag) -> prev_flag\n\
\n\
:Parameters:\n\
    flag : bool\n\
        Boolean flag, True to enable PKIX validation,\n\
        False to disable PKIX validation.\n\
\n\
Sets the flag to enable or disable the use of PKIX for certificate\n\
validation. Returns the previous value of the flag.\n\
See also: `get_use_pkix_for_validation`.\n\
");

static PyObject *
cert_set_use_pkix_for_validation(PyObject *self, PyObject *args)
{
    int flag;
    PRBool prev_flag;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:set_use_pkix_for_validation",
                          &flag))
        return NULL;

    prev_flag = CERT_GetUsePKIXForValidation();

    if (CERT_SetUsePKIXForValidation(flag ? PR_TRUE : PR_FALSE) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    if (prev_flag) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

PyDoc_STRVAR(cert_enable_ocsp_checking_doc,
"enable_ocsp_checking(certdb=get_default_certdb())\n\
\n\
:Parameters:\n\
    certdb : CertDB object or None\n\
        CertDB certificate database object, if None then the default\n\
        certdb will be supplied by calling `nss.get_default_certdb()`.\n\
\n\
Turns on OCSP checking for the given certificate database.\n\
");

static PyObject *
cert_enable_ocsp_checking(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"certdb", NULL};
    CertDB *py_certdb = NULL;
    CERTCertDBHandle *certdb_handle = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O!:enable_ocsp_checking", kwlist,
                                     &CertDBType, &py_certdb))
        return NULL;

    if (py_certdb) {
        certdb_handle = py_certdb->handle;
    } else {
        certdb_handle = CERT_GetDefaultCertDB();
    }

    if (CERT_EnableOCSPChecking(certdb_handle) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_disable_ocsp_checking_doc,
"disable_ocsp_checking(certdb=get_default_certdb())\n\
\n\
:Parameters:\n\
    certdb : CertDB object or None\n\
        CertDB certificate database object, if None then the default\n\
        certdb will be supplied by calling `nss.get_default_certdb()`.\n\
\n\
Turns off OCSP checking for the given certificate database. It will\n\
raise an exception with SEC_ERROR_OCSP_NOT_ENABLED as the error code\n\
if OCSP checking is not enabled. It is safe to call it when OCSP\n\
checking is disabled, you can just ignore the exception if it is\n\
easier to just call it than to remember if it was enabled.\n\
");

static PyObject *
cert_disable_ocsp_checking(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"certdb", NULL};
    CertDB *py_certdb = NULL;
    CERTCertDBHandle *certdb_handle = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O!:disable_ocsp_checking", kwlist,
                                     &CertDBType, &py_certdb))
        return NULL;

    if (py_certdb) {
        certdb_handle = py_certdb->handle;
    } else {
        certdb_handle = CERT_GetDefaultCertDB();
    }

    if (CERT_DisableOCSPChecking(certdb_handle) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_set_ocsp_cache_settings_doc,
"set_ocsp_cache_settings(max_cache_entries, min_secs_till_next_fetch, max_secs_till_next_fetch)\n\
\n\
:Parameters:\n\
    max_cache_entries : int\n\
        Maximum number of cache entries.\n\
        Special values, -1 disables the cache, 0 indicates unlimited cache entries.\n\
    min_secs_till_next_fetch : int\n\
        Whenever an OCSP request was attempted or completed over the network,\n\
        wait at least this number of seconds before trying to fetch again.\n\
    max_secs_till_next_fetch : int\n\
        The maximum age of a cached response we allow, until we try\n\
        to fetch an updated response, even if the OCSP responder expects\n\
        that a newer information update will not be available yet.\n\
\n\
Sets parameters that control NSS' internal OCSP cache.\n\
");
static PyObject *
cert_set_ocsp_cache_settings(PyObject *self, PyObject *args)
{
    int max_cache_entries;
    unsigned int min_secs_till_next_fetch;
    unsigned int max_secs_till_next_fetch;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "iII:set_ocsp_cache_settings",
                          &max_cache_entries,
                          &min_secs_till_next_fetch, &max_secs_till_next_fetch))
        return NULL;

    if (CERT_OCSPCacheSettings(max_cache_entries,
                               min_secs_till_next_fetch,
                               max_secs_till_next_fetch) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_set_ocsp_failure_mode_doc,
"set_ocsp_failure_mode(failure_mode)\n\
\n\
:Parameters:\n\
    failure_mode : int\n\
        A ocspMode_Failure* constant\n\
\n\
Set the desired behaviour on OCSP failures.\n\
failure_mode may be one of:\n\
\n\
    - ocspMode_FailureIsVerificationFailure\n\
    - ocspMode_FailureIsNotAVerificationFailure\n\
\n\
");
static PyObject *
cert_set_ocsp_failure_mode(PyObject *self, PyObject *args)
{
    int failure_mode;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "i:set_ocsp_failure_mode",
                          &failure_mode))
        return NULL;

    if (CERT_SetOCSPFailureMode(failure_mode) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_set_ocsp_timeout_doc,
"set_ocsp_timeout(seconds)\n\
\n\
:Parameters:\n\
    seconds : int\n\
        Maximum number of seconds NSS will wait for an OCSP response.\n\
\n\
Configure the maximum time NSS will wait for an OCSP response.\n\
\n\
");
static PyObject *
cert_set_ocsp_timeout(PyObject *self, PyObject *args)
{
    unsigned int seconds;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "I:set_ocsp_timeout",
                          &seconds))
        return NULL;

    if (CERT_SetOCSPTimeout(seconds) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_clear_ocsp_cache_doc,
"clear_ocsp_cache()\n\
\n\
Removes all items currently stored in the OCSP cache.\n\
\n\
");
static PyObject *
cert_clear_ocsp_cache(PyObject *self, PyObject *args)
{
    TraceMethodEnter(self);

    if (CERT_ClearOCSPCache() != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_set_ocsp_default_responder_doc,
"set_ocsp_default_responder(certdb, url, nickname)\n\
\n\
:Parameters:\n\
    certdb : CertDB object\n\
        CertDB certificate database object.\n\
    url : string\n\
        The location of the default responder (e.g. \"http://foo.com:80/ocsp\")\n\
        Note that the location will not be tested until the first attempt\n\
        to send a request there.\n\
    nickname : string\n\
        The nickname of the cert to trust (expected) to sign the OCSP responses.\n\
        If the corresponding cert cannot be found, SECFailure is returned.\n\
\n\
Specify the location and cert of the default responder.  If OCSP\n\
checking is already enabled and use of a default responder is also\n\
already enabled, all OCSP checking from now on will go directly to the\n\
specified responder. If OCSP checking is not enabled, or if it is\n\
enabled but use of a default responder is not enabled, the information\n\
will be recorded and take effect whenever both are enabled.\n\
");

static PyObject *
cert_set_ocsp_default_responder(PyObject *self, PyObject *args)
{
    CertDB *py_certdb = NULL;
    PyObject *py_url = NULL;
    PyObject *py_url_utf8 = NULL;
    PyObject *py_nickname = NULL;
    PyObject *py_nickname_utf8 = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTuple(args, "O!OO:set_ocsp_default_responder",
                          &CertDBType, &py_certdb,
                          &py_url, &py_nickname))
        return NULL;

    if ((py_url_utf8 = PyString_UTF8(py_url, "url")) == NULL) {
        goto exit;
    }

    if ((py_nickname_utf8 = PyString_UTF8(py_nickname, "nickname")) == NULL) {
        goto exit;
    }

    if (CERT_SetOCSPDefaultResponder(py_certdb->handle,
                                     PyString_AsString(py_url_utf8),
                                     PyString_AsString(py_nickname_utf8)) != SECSuccess) {
        return set_nspr_error(NULL);
    }

 exit:
    Py_XDECREF(py_url_utf8);
    Py_XDECREF(py_nickname_utf8);

    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_enable_ocsp_default_responder_doc,
"enable_ocsp_default_responder(certdb=get_default_certdb())\n\
\n\
:Parameters:\n\
    certdb : CertDB object or None\n\
        CertDB certificate database object, if None then the default\n\
        certdb will be supplied by calling `nss.get_default_certdb()`.\n\
\n\
Turns on use of a default responder when OCSP checking.  If OCSP\n\
checking is already enabled, this will make subsequent checks go\n\
directly to the default responder.  (The location of the responder and\n\
the nickname of the responder cert must already be specified.)  If\n\
OCSP checking is not enabled, this will be recorded and take effect\n\
whenever it is enabled.\n\
");
static PyObject *
cert_enable_ocsp_default_responder(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"certdb", NULL};
    CertDB *py_certdb = NULL;
    CERTCertDBHandle *certdb_handle = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O!:enable_ocsp_default_responder", kwlist,
                                     &CertDBType, &py_certdb))
        return NULL;

    if (py_certdb) {
        certdb_handle = py_certdb->handle;
    } else {
        certdb_handle = CERT_GetDefaultCertDB();
    }

    if (CERT_EnableOCSPDefaultResponder(certdb_handle) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(cert_disable_ocsp_default_responder_doc,
"disable_ocsp_default_responder(certdb=get_default_certdb())\n\
\n\
:Parameters:\n\
    certdb : CertDB object or None\n\
        CertDB certificate database object, if None then the default\n\
        certdb will be supplied by calling `nss.get_default_certdb()`.\n\
\n\
Turns off use of a default responder when OCSP checking.\n\
(Does nothing if use of a default responder is not enabled.)\n\
");
static PyObject *
cert_disable_ocsp_default_responder(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"certdb", NULL};
    CertDB *py_certdb = NULL;
    CERTCertDBHandle *certdb_handle = NULL;

    TraceMethodEnter(self);

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O!:disable_ocsp_default_responder", kwlist,
                                     &CertDBType, &py_certdb))
        return NULL;

    if (py_certdb) {
        certdb_handle = py_certdb->handle;
    } else {
        certdb_handle = CERT_GetDefaultCertDB();
    }

    if (CERT_DisableOCSPDefaultResponder(certdb_handle) != SECSuccess) {
        return set_nspr_error(NULL);
    }

    Py_RETURN_NONE;
}

/* List of functions exported by this module. */
static PyMethodDef
module_methods[] = {
    {"nss_get_version",                  (PyCFunction)nss_nss_get_version,                 METH_NOARGS,                nss_nss_get_version_doc},
    {"nss_version_check",                (PyCFunction)nss_nss_version_check,               METH_VARARGS,               nss_nss_version_check_doc},
    {"set_shutdown_callback",            (PyCFunction)nss_set_shutdown_callback,           METH_VARARGS,               nss_set_shutdown_callback_doc},
    {"nss_is_initialized",               (PyCFunction)nss_nss_is_initialized,              METH_NOARGS,                nss_nss_is_initialized_doc},
    {"nss_init",                         (PyCFunction)nss_nss_init,                        METH_VARARGS,               nss_nss_init_doc},
    {"nss_init_read_write",              (PyCFunction)nss_nss_init_read_write,             METH_VARARGS,               nss_nss_init_read_write_doc},
    {"nss_init_nodb",                    (PyCFunction)nss_init_nodb,                       METH_NOARGS,                nss_init_nodb_doc},
    {"nss_initialize",                   (PyCFunction)nss_nss_initialize,                  METH_VARARGS|METH_KEYWORDS, nss_nss_initialize_doc},
    {"nss_init_context",                 (PyCFunction)nss_nss_init_context,                METH_VARARGS|METH_KEYWORDS, nss_nss_init_context_doc},
    {"nss_shutdown",                     (PyCFunction)nss_nss_shutdown,                    METH_NOARGS,                nss_nss_shutdown_doc},
    {"nss_shutdown_context",             (PyCFunction)nss_nss_shutdown_context,            METH_VARARGS,               nss_nss_shutdown_context_doc},
    {"dump_certificate_cache_info",      (PyCFunction)nss_dump_certificate_cache_info,     METH_NOARGS,                nss_dump_certificate_cache_info_doc},
    {"set_password_callback",            (PyCFunction)pk11_set_password_callback,          METH_VARARGS,               pk11_set_password_callback_doc},
    {"list_certs",                       (PyCFunction)pk11_list_certs,                     METH_VARARGS,               pk11_list_certs_doc},
    {"find_certs_from_email_addr",       (PyCFunction)pk11_find_certs_from_email_addr,     METH_VARARGS,               pk11_find_certs_from_email_addr_doc},
    {"find_certs_from_nickname",         (PyCFunction)pk11_find_certs_from_nickname,       METH_VARARGS,               pk11_find_certs_from_nickname_doc},
    {"find_cert_from_nickname",          (PyCFunction)pk11_find_cert_from_nickname,        METH_VARARGS,               pk11_find_cert_from_nickname_doc},
    {"find_key_by_any_cert",             (PyCFunction)pk11_find_key_by_any_cert,           METH_VARARGS,               pk11_find_key_by_any_cert_doc},
    {"generate_random",                  (PyCFunction)pk11_generate_random,                METH_VARARGS,               pk11_generate_random_doc},
    {"get_default_certdb",               (PyCFunction)cert_get_default_certdb,             METH_NOARGS,                cert_get_default_certdb_doc},
    {"get_cert_nicknames",               (PyCFunction)cert_get_cert_nicknames,             METH_VARARGS,               cert_get_cert_nicknames_doc},
    {"data_to_hex",                      (PyCFunction)cert_data_to_hex,                    METH_VARARGS|METH_KEYWORDS, cert_data_to_hex_doc},
    {"read_hex",                         (PyCFunction)read_hex,                            METH_VARARGS|METH_KEYWORDS, read_hex_doc},
    {"hash_buf",                         (PyCFunction)pk11_hash_buf,                       METH_VARARGS,               pk11_hash_buf_doc},
    {"md5_digest",                       (PyCFunction)pk11_md5_digest,                     METH_VARARGS,               pk11_md5_digest_doc},
    {"sha1_digest",                      (PyCFunction)pk11_sha1_digest,                    METH_VARARGS,               pk11_sha1_digest_doc},
    {"sha256_digest",                    (PyCFunction)pk11_sha256_digest,                  METH_VARARGS,               pk11_sha256_digest_doc},
    {"sha512_digest",                    (PyCFunction)pk11_sha512_digest,                  METH_VARARGS,               pk11_sha512_digest_doc},
    {"indented_format",                  (PyCFunction)py_indented_format,                  METH_VARARGS|METH_KEYWORDS, py_indented_format_doc},
    {"make_line_fmt_tuples",             (PyCFunction)py_make_line_fmt_tuples,             METH_VARARGS|METH_KEYWORDS, py_make_line_fmt_tuples_doc},
    {"der_universal_secitem_fmt_lines",  (PyCFunction)cert_der_universal_secitem_fmt_lines, METH_VARARGS|METH_KEYWORDS, cert_der_universal_secitem_fmt_lines_doc},
    {"oid_str",                          (PyCFunction)cert_oid_str,                        METH_VARARGS,               cert_oid_str_doc},
    {"oid_tag_name",                     (PyCFunction)cert_oid_tag_name,                   METH_VARARGS,               cert_oid_tag_name_doc},
    {"oid_tag",                          (PyCFunction)cert_oid_tag,                        METH_VARARGS,               cert_oid_tag_doc},
    {"oid_dotted_decimal",               (PyCFunction)cert_oid_dotted_decimal,             METH_VARARGS,               cert_oid_dotted_decimal_doc},
    {"key_mechanism_type_name",          (PyCFunction)pk11_key_mechanism_type_name,        METH_VARARGS,               pk11_key_mechanism_type_name_doc},
    {"key_mechanism_type_from_name",     (PyCFunction)pk11_key_mechanism_type_from_name,   METH_VARARGS,               pk11_key_mechanism_type_from_name_doc},
    {"pk11_attribute_type_name",         (PyCFunction)pk11_pk11_attribute_type_name,       METH_VARARGS,               pk11_attribute_type_name_doc},
    {"pk11_attribute_type_from_name",    (PyCFunction)pk11_pk11_attribute_type_from_name,  METH_VARARGS,               pk11_pk11_attribute_type_from_name_doc},
    {"cert_crl_reason_name",             (PyCFunction)cert_crl_reason_name,                METH_VARARGS,               cert_crl_reason_name_doc},
    {"cert_crl_reason_from_name",        (PyCFunction)cert_crl_reason_from_name,           METH_VARARGS,               cert_crl_reason_from_name_doc},
    {"cert_general_name_type_name",      (PyCFunction)cert_general_name_type_name,         METH_VARARGS,               cert_general_name_type_name_doc},
    {"cert_general_name_type_from_name", (PyCFunction)cert_general_name_type_from_name,    METH_VARARGS,               cert_general_name_type_from_name_doc},
    {"pk11_disabled_reason_str",         (PyCFunction)pk11_pk11_disabled_reason_str,       METH_VARARGS,               pk11_disabled_reason_str_doc},
    {"pk11_disabled_reason_name",        (PyCFunction)pk11_pk11_disabled_reason_name,      METH_VARARGS,               pk11_disabled_reason_name_doc},
    {"pk11_logout_all",                  (PyCFunction)pk11_pk11_logout_all,                METH_NOARGS,                pk11_pk11_logout_all_doc},
    {"get_best_slot",                    (PyCFunction)pk11_get_best_slot,                  METH_VARARGS,               pk11_get_best_slot_doc},
    {"get_internal_slot",                (PyCFunction)pk11_get_internal_slot,              METH_NOARGS,                pk11_get_internal_slot_doc},
    {"get_internal_key_slot",            (PyCFunction)pk11_get_internal_key_slot,          METH_NOARGS,                pk11_get_internal_key_slot_doc},
    {"find_slot_by_name",                (PyCFunction)pk11_find_slot_by_name,              METH_VARARGS,               pk11_find_slot_by_name_doc},
    {"create_context_by_sym_key",        (PyCFunction)pk11_create_context_by_sym_key,      METH_VARARGS|METH_KEYWORDS, pk11_create_context_by_sym_key_doc},
    {"import_sym_key",                   (PyCFunction)pk11_import_sym_key,                 METH_VARARGS,               pk11_import_sym_key_doc},
    {"pub_wrap_sym_key",                 (PyCFunction)pk11_pub_wrap_sym_key,               METH_VARARGS,               pk11_pub_wrap_sym_key_doc},
    {"create_digest_context",            (PyCFunction)pk11_create_digest_context,          METH_VARARGS,               pk11_create_digest_context_doc},
    {"param_from_iv",                    (PyCFunction)pk11_param_from_iv,                  METH_VARARGS|METH_KEYWORDS, pk11_param_from_iv_doc},
    {"param_from_algid",                 (PyCFunction)pk11_param_from_algid,               METH_VARARGS,               pk11_param_from_algid_doc},
    {"generate_new_param",               (PyCFunction)pk11_generate_new_param,             METH_VARARGS|METH_KEYWORDS, pk11_generate_new_param_doc},
    {"algtag_to_mechanism",              (PyCFunction)pk11_algtag_to_mechanism,            METH_VARARGS,               pk11_algtag_to_mechanism_doc},
    {"mechanism_to_algtag",              (PyCFunction)pk11_mechanism_to_algtag,            METH_VARARGS,               pk11_mechanism_to_algtag_doc},
    {"get_iv_length",                    (PyCFunction)pk11_get_iv_length,                  METH_VARARGS,               pk11_get_iv_length_doc},
    {"get_block_size",                   (PyCFunction)pk11_get_block_size,                 METH_VARARGS|METH_KEYWORDS, pk11_get_block_size_doc},
    {"get_pad_mechanism",                (PyCFunction)pk11_get_pad_mechanism,              METH_VARARGS,               pk11_get_pad_mechanism_doc},
    {"import_crl",                       (PyCFunction)pk11_import_crl,                     METH_VARARGS,               pk11_import_crl_doc},
    {"create_pbev2_algorithm_id",        (PyCFunction)pk11_create_pbev2_algorithm_id,      METH_VARARGS|METH_KEYWORDS, pk11_create_pbev2_algorithm_id_doc},
    {"need_pw_init",                     (PyCFunction)pk11_pk11_need_pw_init,              METH_NOARGS,                pk11_pk11_need_pw_init_doc},
    {"token_exists",                     (PyCFunction)pk11_pk11_token_exists,              METH_NOARGS,                pk11_pk11_token_exists_doc},
    {"is_fips",                          (PyCFunction)pk11_pk11_is_fips,                   METH_NOARGS,                pk11_pk11_is_fips_doc},
    {"decode_der_crl",                   (PyCFunction)cert_decode_der_crl,                 METH_VARARGS|METH_KEYWORDS, cert_decode_der_crl_doc},
    {"read_der_from_file",               (PyCFunction)nss_read_der_from_file,              METH_VARARGS|METH_KEYWORDS, nss_read_der_from_file_doc},
    {"base64_to_binary",                 (PyCFunction)nss_base64_to_binary,                METH_VARARGS|METH_KEYWORDS, nss_base64_to_binary_doc},
    {"x509_key_usage",                   (PyCFunction)cert_x509_key_usage,                 METH_VARARGS|METH_KEYWORDS, cert_x509_key_usage_doc},
    {"x509_cert_type",                   (PyCFunction)cert_x509_cert_type,                 METH_VARARGS|METH_KEYWORDS, cert_x509_cert_type_doc},
    {"x509_ext_key_usage",               (PyCFunction)cert_x509_ext_key_usage,             METH_VARARGS|METH_KEYWORDS, cert_x509_ext_key_usage_doc},
    {"x509_alt_name",                    (PyCFunction)cert_x509_alt_name,                  METH_VARARGS|METH_KEYWORDS, cert_x509_alt_name_doc},
    {"cert_usage_flags",                 (PyCFunction)cert_cert_usage_flags,               METH_VARARGS|METH_KEYWORDS, cert_cert_usage_flags_doc},
    {"key_usage_flags",                  (PyCFunction)cert_key_usage_flags,                METH_VARARGS|METH_KEYWORDS, cert_key_usage_flags_doc},
    {"cert_type_flags",                  (PyCFunction)cert_cert_type_flags,                METH_VARARGS|METH_KEYWORDS, cert_cert_type_flags_doc},
    {"nss_init_flags",                   (PyCFunction)nss_nss_init_flags,                  METH_VARARGS|METH_KEYWORDS, nss_nss_init_flags_doc},
    {"pkcs12_enable_cipher",             (PyCFunction)pkcs12_enable_cipher,                METH_VARARGS,               pkcs12_enable_cipher_doc},
    {"pkcs12_enable_all_ciphers",        (PyCFunction)pkcs12_enable_all_ciphers,           METH_NOARGS,                pkcs12_enable_all_ciphers_doc},
    {"pkcs12_set_preferred_cipher",      (PyCFunction)pkcs12_set_preferred_cipher,         METH_VARARGS,               pkcs12_set_preferred_cipher_doc},
    {"pkcs12_cipher_name",               (PyCFunction)pkcs12_cipher_name,                  METH_VARARGS,               pkcs12_cipher_name_doc},
    {"pkcs12_cipher_from_name",          (PyCFunction)pkcs12_cipher_from_name,             METH_VARARGS,               pkcs12_cipher_from_name_doc},
    {"pkcs12_map_cipher",                (PyCFunction)pkcs12_map_cipher,                   METH_VARARGS|METH_KEYWORDS, pkcs12_map_cipher_doc},
    {"pkcs12_set_nickname_collision_callback", (PyCFunction)PKCS12_pkcs12_set_nickname_collision_callback, METH_VARARGS,      PKCS12_pkcs12_set_nickname_collision_callback_doc},
    {"pkcs12_export",                    (PyCFunction)pkcs12_export,                       METH_VARARGS|METH_KEYWORDS, pkcs12_export_doc},
    {"fingerprint_format_lines",         (PyCFunction)nss_fingerprint_format_lines,        METH_VARARGS|METH_KEYWORDS, nss_fingerprint_format_lines_doc},
    {"get_use_pkix_for_validation",      (PyCFunction)cert_get_use_pkix_for_validation,    METH_NOARGS,                cert_get_use_pkix_for_validation_doc},
    {"set_use_pkix_for_validation",      (PyCFunction)cert_set_use_pkix_for_validation,    METH_VARARGS,               cert_set_use_pkix_for_validation_doc},
    {"enable_ocsp_checking",             (PyCFunction)cert_enable_ocsp_checking,           METH_VARARGS|METH_KEYWORDS, cert_enable_ocsp_checking_doc},
    {"disable_ocsp_checking",            (PyCFunction)cert_disable_ocsp_checking,          METH_VARARGS|METH_KEYWORDS, cert_disable_ocsp_checking_doc},
    {"set_ocsp_cache_settings",          (PyCFunction)cert_set_ocsp_cache_settings,        METH_VARARGS,               cert_set_ocsp_cache_settings_doc},
    {"set_ocsp_failure_mode",            (PyCFunction)cert_set_ocsp_failure_mode,          METH_VARARGS,               cert_set_ocsp_failure_mode_doc},
    {"set_ocsp_timeout",                 (PyCFunction)cert_set_ocsp_timeout,               METH_VARARGS,               cert_set_ocsp_timeout_doc},
    {"clear_ocsp_cache",                 (PyCFunction)cert_clear_ocsp_cache,               METH_NOARGS,                cert_clear_ocsp_cache_doc},
    {"set_ocsp_default_responder",       (PyCFunction)cert_set_ocsp_default_responder,     METH_VARARGS,               cert_set_ocsp_default_responder_doc},
    {"enable_ocsp_default_responder",    (PyCFunction)cert_enable_ocsp_default_responder,  METH_VARARGS|METH_KEYWORDS, cert_enable_ocsp_default_responder_doc},
    {"disable_ocsp_default_responder",   (PyCFunction)cert_disable_ocsp_default_responder, METH_VARARGS|METH_KEYWORDS, cert_disable_ocsp_default_responder_doc},
    {NULL, NULL} /* Sentinel */
};

/* ============================== Module Exports ============================= */

static PyNSPR_NSS_C_API_Type nspr_nss_c_api =
{
    &PK11SlotType,
    &CertDBType,
    &CertificateType,
    &PrivateKeyType,
    &SecItemType,
    Certificate_new_from_CERTCertificate,
    PrivateKey_new_from_SECKEYPrivateKey,
    SecItem_new_from_SECItem,
    cert_distnames_new_from_CERTDistNames,
    cert_distnames_as_CERTDistNames,
    _AddIntConstantWithLookup,
    _AddIntConstantAlias,
    format_from_lines,
    line_fmt_tuple,
    obj_sprintf,
    obj_to_hex,
    raw_data_to_hex,
    fmt_label,
    timestamp_to_DateTime
};

/* ============================== Module Construction ============================= */

PyDoc_STRVAR(module_doc,
"This module implements the NSS functions\n\
\n\
");

#if PY_MAJOR_VERSION >= 3

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    NSS_NSS_MODULE_NAME,        /* m_name */
    doc,                        /* m_doc */
    -1,                         /* m_size */
    methods                     /* m_methods */
    NULL,                       /* m_reload */
    NULL,                       /* m_traverse */
    NULL,                       /* m_clear */
    NULL                        /* m_free */
};

#else /* PY_MAOR_VERSION < 3 */
#endif /* PY_MAJOR_VERSION */

MOD_INIT(nss)
{
    PyObject *m;

    if (import_nspr_error_c_api() < 0) {
        return MOD_ERROR_VAL;
    }

    PyDateTime_IMPORT;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&module_def);
#else
    m = Py_InitModule3(NSS_NSS_MODULE_NAME, module_methods, module_doc);
#endif

    if (m == NULL) {
        return MOD_ERROR_VAL MOD_ERROR_VAL;
    }

    if ((empty_tuple = PyTuple_New(0)) == NULL) {
        return MOD_ERROR_VAL;
    }
    Py_INCREF(empty_tuple);

    TYPE_READY(SecItemType);
    TYPE_READY(AlgorithmIDType);
    TYPE_READY(RSAGenParamsType);
    TYPE_READY(KEYPQGParamsType);
    TYPE_READY(RSAPublicKeyType);
    TYPE_READY(DSAPublicKeyType);
    TYPE_READY(SignedDataType);
    TYPE_READY(PublicKeyType);
    TYPE_READY(SubjectPublicKeyInfoType);
    TYPE_READY(CertDBType);
    TYPE_READY(CertificateExtensionType);
    TYPE_READY(CertificateType);
    TYPE_READY(PrivateKeyType);
    TYPE_READY(SignedCRLType);
    TYPE_READY(PK11SlotType);
    TYPE_READY(PK11SymKeyType);
    TYPE_READY(PK11ContextType);
    TYPE_READY(CRLDistributionPtType);
    TYPE_READY(CRLDistributionPtsType);
    TYPE_READY(AuthorityInfoAccessType);
    TYPE_READY(AuthorityInfoAccessesType);
    TYPE_READY(AVAType);
    TYPE_READY(RDNType);
    TYPE_READY(DNType);
    TYPE_READY(GeneralNameType);
    TYPE_READY(AuthKeyIDType);
    TYPE_READY(BasicConstraintsType);
    TYPE_READY(CertAttributeType);
    TYPE_READY(CertificateRequestType);
    TYPE_READY(InitParametersType);
    TYPE_READY(InitContextType);
    TYPE_READY(PKCS12DecodeItemType);
    TYPE_READY(PKCS12DecoderType);
    TYPE_READY(CertVerifyLogNodeType);
    TYPE_READY(CertVerifyLogType);

    /* Export C API */
    if (PyModule_AddObject(m, "_C_API",
                           PyCapsule_New((void *)&nspr_nss_c_api, "_C_API", NULL)) != 0) {
        return MOD_ERROR_VAL;
    }

    AddIntConstant(OCTETS_PER_LINE_DEFAULT);
    PyModule_AddStringMacro(m, HEX_SEPARATOR_DEFAULT);

    AddIntConstant(AsObject);
    AddIntConstant(AsString);
    AddIntConstant(AsTypeString);
    AddIntConstant(AsTypeEnum);
    AddIntConstant(AsLabeledString);
    AddIntConstant(AsEnum);
    AddIntConstant(AsEnumName);
    AddIntConstant(AsEnumDescription);
    AddIntConstant(AsIndex);
    AddIntConstant(AsDottedDecimal);

    AddIntConstant(generalName);
    AddIntConstant(relativeDistinguishedName);

    AddIntConstant(PK11CertListUnique);
    AddIntConstant(PK11CertListUser);
    AddIntConstant(PK11CertListRootUnique);
    AddIntConstant(PK11CertListCA);
    AddIntConstant(PK11CertListCAUnique);
    AddIntConstant(PK11CertListUserUnique);
    AddIntConstant(PK11CertListAll);

    AddIntConstant(certUsageSSLClient);
    AddIntConstant(certUsageSSLServer);
    AddIntConstant(certUsageSSLServerWithStepUp);
    AddIntConstant(certUsageSSLCA);
    AddIntConstant(certUsageEmailSigner);
    AddIntConstant(certUsageEmailRecipient);
    AddIntConstant(certUsageObjectSigner);
    AddIntConstant(certUsageUserCertImport);
    AddIntConstant(certUsageVerifyCA);
    AddIntConstant(certUsageProtectedObjectSigner);
    AddIntConstant(certUsageStatusResponder);
    AddIntConstant(certUsageAnyCA);

    AddIntConstant(certificateUsageCheckAllUsages);
    AddIntConstant(certificateUsageSSLClient);
    AddIntConstant(certificateUsageSSLServer);
    AddIntConstant(certificateUsageSSLServerWithStepUp);
    AddIntConstant(certificateUsageSSLCA);
    AddIntConstant(certificateUsageEmailSigner);
    AddIntConstant(certificateUsageEmailRecipient);
    AddIntConstant(certificateUsageObjectSigner);
    AddIntConstant(certificateUsageUserCertImport);
    AddIntConstant(certificateUsageVerifyCA);
    AddIntConstant(certificateUsageProtectedObjectSigner);
    AddIntConstant(certificateUsageStatusResponder);
    AddIntConstant(certificateUsageAnyCA);

    AddIntConstant(NSS_INIT_READONLY);
    AddIntConstant(NSS_INIT_NOCERTDB);
    AddIntConstant(NSS_INIT_NOMODDB);
    AddIntConstant(NSS_INIT_FORCEOPEN);
    AddIntConstant(NSS_INIT_NOROOTINIT);
    AddIntConstant(NSS_INIT_OPTIMIZESPACE);
    AddIntConstant(NSS_INIT_PK11THREADSAFE);
    AddIntConstant(NSS_INIT_PK11RELOAD);
    AddIntConstant(NSS_INIT_NOPK11FINALIZE);
    AddIntConstant(NSS_INIT_RESERVED);
    AddIntConstant(NSS_INIT_COOPERATE);

    AddIntConstant(ssl_kea_null);
    AddIntConstant(ssl_kea_rsa);
    AddIntConstant(ssl_kea_dh);
    AddIntConstant(ssl_kea_fortezza);
    AddIntConstant(ssl_kea_ecdh);

    AddIntConstant(nullKey);
    AddIntConstant(rsaKey);
    AddIntConstant(dsaKey);
    AddIntConstant(fortezzaKey);
    AddIntConstant(dhKey);
    AddIntConstant(keaKey);
    AddIntConstant(ecKey);

    AddIntConstant(SEC_CERT_NICKNAMES_ALL);
    AddIntConstant(SEC_CERT_NICKNAMES_USER);
    AddIntConstant(SEC_CERT_NICKNAMES_SERVER);
    AddIntConstant(SEC_CERT_NICKNAMES_CA);

    AddIntConstant(SEC_CRL_TYPE);
    AddIntConstant(SEC_KRL_TYPE);

    AddIntConstant(CRL_DECODE_DEFAULT_OPTIONS);
    AddIntConstant(CRL_DECODE_DONT_COPY_DER);
    AddIntConstant(CRL_DECODE_SKIP_ENTRIES);
    AddIntConstant(CRL_DECODE_KEEP_BAD_CRL);
    AddIntConstant(CRL_DECODE_ADOPT_HEAP_DER);

    AddIntConstant(CRL_IMPORT_DEFAULT_OPTIONS);
    AddIntConstant(CRL_IMPORT_BYPASS_CHECKS);


    AddIntConstant(secCertTimeValid);
    AddIntConstant(secCertTimeExpired);
    AddIntConstant(secCertTimeNotValidYet);

    AddIntConstant(KU_DIGITAL_SIGNATURE);
    AddIntConstant(KU_NON_REPUDIATION);
    AddIntConstant(KU_KEY_ENCIPHERMENT);
    AddIntConstant(KU_DATA_ENCIPHERMENT);
    AddIntConstant(KU_KEY_AGREEMENT);
    AddIntConstant(KU_KEY_CERT_SIGN);
    AddIntConstant(KU_CRL_SIGN);
    AddIntConstant(KU_ENCIPHER_ONLY);
    AddIntConstant(KU_ALL);
    AddIntConstant(KU_DIGITAL_SIGNATURE_OR_NON_REPUDIATION);
    AddIntConstant(KU_KEY_AGREEMENT_OR_ENCIPHERMENT);
    AddIntConstant(KU_NS_GOVT_APPROVED);

#if (NSS_VMAJOR > 3) || (NSS_VMAJOR == 3 && NSS_VMINOR >= 13)
    AddIntConstant(CERTDB_TERMINAL_RECORD);
#else
    AddIntConstant(CERTDB_VALID_PEER);
#endif
    AddIntConstant(CERTDB_TRUSTED);
    AddIntConstant(CERTDB_SEND_WARN);
    AddIntConstant(CERTDB_VALID_CA);
    AddIntConstant(CERTDB_TRUSTED_CA);
    AddIntConstant(CERTDB_NS_TRUSTED_CA);
    AddIntConstant(CERTDB_USER);
    AddIntConstant(CERTDB_TRUSTED_CLIENT_CA);
    AddIntConstant(CERTDB_GOVT_APPROVED_CA);


    /***************************************************************************
     * CRL Reason
     ***************************************************************************/

    if ((crl_reason_name_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((crl_reason_value_to_name = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstant(constant)                      \
if (_AddIntConstantWithLookup(m, #constant, constant, \
    "crlEntry", crl_reason_name_to_value, crl_reason_value_to_name) < 0) return MOD_ERROR_VAL;

    ExportConstant(crlEntryReasonUnspecified);
    ExportConstant(crlEntryReasonKeyCompromise);
    ExportConstant(crlEntryReasonCaCompromise);
    ExportConstant(crlEntryReasonAffiliationChanged);
    ExportConstant(crlEntryReasonSuperseded);
    ExportConstant(crlEntryReasonCessationOfOperation);
    ExportConstant(crlEntryReasoncertificatedHold);
    ExportConstant(crlEntryReasonRemoveFromCRL);
    ExportConstant(crlEntryReasonPrivilegeWithdrawn);
    ExportConstant(crlEntryReasonAaCompromise);

#undef ExportConstant

    /***************************************************************************
     * General Name Types
     ***************************************************************************/

    if ((general_name_name_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((general_name_value_to_name = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstant(constant)                      \
if (_AddIntConstantWithLookup(m, #constant, constant, \
    "cert", general_name_name_to_value, general_name_value_to_name) < 0) return MOD_ERROR_VAL;

    ExportConstant(certOtherName);
    ExportConstant(certRFC822Name);
    ExportConstant(certDNSName);
    ExportConstant(certX400Address);
    ExportConstant(certDirectoryName);
    ExportConstant(certEDIPartyName);
    ExportConstant(certURI);
    ExportConstant(certIPAddress);
    ExportConstant(certRegisterID);

#undef ExportConstant

    /***************************************************************************
     * Mechanism Types
     ***************************************************************************/

    if ((ckm_name_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((ckm_value_to_name = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstant(constant)                      \
if (_AddIntConstantWithLookup(m, #constant, constant, \
    "CKM_", ckm_name_to_value, ckm_value_to_name) < 0) return MOD_ERROR_VAL;

    ExportConstant(CKM_RSA_PKCS_KEY_PAIR_GEN);
    ExportConstant(CKM_RSA_PKCS);
    ExportConstant(CKM_RSA_9796);
    ExportConstant(CKM_RSA_X_509);

    /* CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS
     * are new for v2.0.  They are mechanisms which hash and sign */
    ExportConstant(CKM_MD2_RSA_PKCS);
    ExportConstant(CKM_MD5_RSA_PKCS);
    ExportConstant(CKM_SHA1_RSA_PKCS);

    /* CKM_RIPEMD128_RSA_PKCS, CKM_RIPEMD160_RSA_PKCS, and
     * CKM_RSA_PKCS_OAEP are new for v2.10 */
    ExportConstant(CKM_RIPEMD128_RSA_PKCS);
    ExportConstant(CKM_RIPEMD160_RSA_PKCS);
    ExportConstant(CKM_RSA_PKCS_OAEP);

    /* CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31, CKM_SHA1_RSA_X9_31,
     * CKM_RSA_PKCS_PSS, and CKM_SHA1_RSA_PKCS_PSS are new for v2.11 */
    ExportConstant(CKM_RSA_X9_31_KEY_PAIR_GEN);
    ExportConstant(CKM_RSA_X9_31);
    ExportConstant(CKM_SHA1_RSA_X9_31);
    ExportConstant(CKM_RSA_PKCS_PSS);
    ExportConstant(CKM_SHA1_RSA_PKCS_PSS);

    ExportConstant(CKM_DSA_KEY_PAIR_GEN);
    ExportConstant(CKM_DSA);
    ExportConstant(CKM_DSA_SHA1);
    ExportConstant(CKM_DH_PKCS_KEY_PAIR_GEN);
    ExportConstant(CKM_DH_PKCS_DERIVE);

    /* CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE,
     * CKM_X9_42_DH_HYBRID_DERIVE, and CKM_X9_42_MQV_DERIVE are new for
     * v2.11 */
    ExportConstant(CKM_X9_42_DH_KEY_PAIR_GEN);
    ExportConstant(CKM_X9_42_DH_DERIVE);
    ExportConstant(CKM_X9_42_DH_HYBRID_DERIVE);
    ExportConstant(CKM_X9_42_MQV_DERIVE);

    /* CKM_SHA256/384/512 are new for v2.20 */
    ExportConstant(CKM_SHA256_RSA_PKCS);
    ExportConstant(CKM_SHA384_RSA_PKCS);
    ExportConstant(CKM_SHA512_RSA_PKCS);
    ExportConstant(CKM_SHA256_RSA_PKCS_PSS);
    ExportConstant(CKM_SHA384_RSA_PKCS_PSS);
    ExportConstant(CKM_SHA512_RSA_PKCS_PSS);

    /* CKM_SHA224 new for v2.20 amendment 3 */
    ExportConstant(CKM_SHA224_RSA_PKCS);
    ExportConstant(CKM_SHA224_RSA_PKCS_PSS);

    ExportConstant(CKM_RC2_KEY_GEN);
    ExportConstant(CKM_RC2_ECB);
    ExportConstant(CKM_RC2_CBC);
    ExportConstant(CKM_RC2_MAC);

    /* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
    ExportConstant(CKM_RC2_MAC_GENERAL);
    ExportConstant(CKM_RC2_CBC_PAD);

    ExportConstant(CKM_RC4_KEY_GEN);
    ExportConstant(CKM_RC4);
    ExportConstant(CKM_DES_KEY_GEN);
    ExportConstant(CKM_DES_ECB);
    ExportConstant(CKM_DES_CBC);
    ExportConstant(CKM_DES_MAC);

    /* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
    ExportConstant(CKM_DES_MAC_GENERAL);
    ExportConstant(CKM_DES_CBC_PAD);

    ExportConstant(CKM_DES2_KEY_GEN);
    ExportConstant(CKM_DES3_KEY_GEN);
    ExportConstant(CKM_DES3_ECB);
    ExportConstant(CKM_DES3_CBC);
    ExportConstant(CKM_DES3_MAC);

    /* CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
     * CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
     * CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0 */
    ExportConstant(CKM_DES3_MAC_GENERAL);
    ExportConstant(CKM_DES3_CBC_PAD);
    ExportConstant(CKM_CDMF_KEY_GEN);
    ExportConstant(CKM_CDMF_ECB);
    ExportConstant(CKM_CDMF_CBC);
    ExportConstant(CKM_CDMF_MAC);
    ExportConstant(CKM_CDMF_MAC_GENERAL);
    ExportConstant(CKM_CDMF_CBC_PAD);

    /* the following four DES mechanisms are new for v2.20 */
    ExportConstant(CKM_DES_OFB64);
    ExportConstant(CKM_DES_OFB8);
    ExportConstant(CKM_DES_CFB64);
    ExportConstant(CKM_DES_CFB8);

    ExportConstant(CKM_MD2);

    /* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
    ExportConstant(CKM_MD2_HMAC);
    ExportConstant(CKM_MD2_HMAC_GENERAL);

    ExportConstant(CKM_MD5);

    /* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
    ExportConstant(CKM_MD5_HMAC);
    ExportConstant(CKM_MD5_HMAC_GENERAL);

    ExportConstant(CKM_SHA_1);

    /* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
    ExportConstant(CKM_SHA_1_HMAC);
    ExportConstant(CKM_SHA_1_HMAC_GENERAL);

    /* CKM_RIPEMD128, CKM_RIPEMD128_HMAC,
     * CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD160, CKM_RIPEMD160_HMAC,
     * and CKM_RIPEMD160_HMAC_GENERAL are new for v2.10 */
    ExportConstant(CKM_RIPEMD128);
    ExportConstant(CKM_RIPEMD128_HMAC);
    ExportConstant(CKM_RIPEMD128_HMAC_GENERAL);
    ExportConstant(CKM_RIPEMD160);
    ExportConstant(CKM_RIPEMD160_HMAC);
    ExportConstant(CKM_RIPEMD160_HMAC_GENERAL);

    /* CKM_SHA256/384/512 are new for v2.20 */
    ExportConstant(CKM_SHA256);
    ExportConstant(CKM_SHA256_HMAC);
    ExportConstant(CKM_SHA256_HMAC_GENERAL);
    ExportConstant(CKM_SHA384);
    ExportConstant(CKM_SHA384_HMAC);
    ExportConstant(CKM_SHA384_HMAC_GENERAL);
    ExportConstant(CKM_SHA512);
    ExportConstant(CKM_SHA512_HMAC);
    ExportConstant(CKM_SHA512_HMAC_GENERAL);

    /* CKM_SHA224 new for v2.20 amendment 3 */
    ExportConstant(CKM_SHA224);
    ExportConstant(CKM_SHA224_HMAC);
    ExportConstant(CKM_SHA224_HMAC_GENERAL);

    /* All of the following mechanisms are new for v2.0 */
    /* Note that CAST128 and CAST5 are the same algorithm */
    ExportConstant(CKM_CAST_KEY_GEN);
    ExportConstant(CKM_CAST_ECB);
    ExportConstant(CKM_CAST_CBC);
    ExportConstant(CKM_CAST_MAC);
    ExportConstant(CKM_CAST_MAC_GENERAL);
    ExportConstant(CKM_CAST_CBC_PAD);
    ExportConstant(CKM_CAST3_KEY_GEN);
    ExportConstant(CKM_CAST3_ECB);
    ExportConstant(CKM_CAST3_CBC);
    ExportConstant(CKM_CAST3_MAC);
    ExportConstant(CKM_CAST3_MAC_GENERAL);
    ExportConstant(CKM_CAST3_CBC_PAD);
    ExportConstant(CKM_CAST5_KEY_GEN);
    ExportConstant(CKM_CAST128_KEY_GEN);
    ExportConstant(CKM_CAST5_ECB);
    ExportConstant(CKM_CAST128_ECB);
    ExportConstant(CKM_CAST5_CBC);
    ExportConstant(CKM_CAST128_CBC);
    ExportConstant(CKM_CAST5_MAC);
    ExportConstant(CKM_CAST128_MAC);
    ExportConstant(CKM_CAST5_MAC_GENERAL);
    ExportConstant(CKM_CAST128_MAC_GENERAL);
    ExportConstant(CKM_CAST5_CBC_PAD);
    ExportConstant(CKM_CAST128_CBC_PAD);
    ExportConstant(CKM_RC5_KEY_GEN);
    ExportConstant(CKM_RC5_ECB);
    ExportConstant(CKM_RC5_CBC);
    ExportConstant(CKM_RC5_MAC);
    ExportConstant(CKM_RC5_MAC_GENERAL);
    ExportConstant(CKM_RC5_CBC_PAD);
    ExportConstant(CKM_IDEA_KEY_GEN);
    ExportConstant(CKM_IDEA_ECB);
    ExportConstant(CKM_IDEA_CBC);
    ExportConstant(CKM_IDEA_MAC);
    ExportConstant(CKM_IDEA_MAC_GENERAL);
    ExportConstant(CKM_IDEA_CBC_PAD);
    ExportConstant(CKM_GENERIC_SECRET_KEY_GEN);
    ExportConstant(CKM_CONCATENATE_BASE_AND_KEY);
    ExportConstant(CKM_CONCATENATE_BASE_AND_DATA);
    ExportConstant(CKM_CONCATENATE_DATA_AND_BASE);
    ExportConstant(CKM_XOR_BASE_AND_DATA);
    ExportConstant(CKM_EXTRACT_KEY_FROM_KEY);
    ExportConstant(CKM_SSL3_PRE_MASTER_KEY_GEN);
    ExportConstant(CKM_SSL3_MASTER_KEY_DERIVE);
    ExportConstant(CKM_SSL3_KEY_AND_MAC_DERIVE);

    /* CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM_TLS_PRE_MASTER_KEY_GEN,
     * CKM_TLS_MASTER_KEY_DERIVE, CKM_TLS_KEY_AND_MAC_DERIVE, and
     * CKM_TLS_MASTER_KEY_DERIVE_DH are new for v2.11 */
    ExportConstant(CKM_SSL3_MASTER_KEY_DERIVE_DH);
    ExportConstant(CKM_TLS_PRE_MASTER_KEY_GEN);
    ExportConstant(CKM_TLS_MASTER_KEY_DERIVE);
    ExportConstant(CKM_TLS_KEY_AND_MAC_DERIVE);
    ExportConstant(CKM_TLS_MASTER_KEY_DERIVE_DH);

    /* CKM_TLS_PRF is new for v2.20 */
    ExportConstant(CKM_TLS_PRF);

    ExportConstant(CKM_SSL3_MD5_MAC);
    ExportConstant(CKM_SSL3_SHA1_MAC);
    ExportConstant(CKM_MD5_KEY_DERIVATION);
    ExportConstant(CKM_MD2_KEY_DERIVATION);
    ExportConstant(CKM_SHA1_KEY_DERIVATION);

    /* CKM_SHA256/384/512 are new for v2.20 */
    ExportConstant(CKM_SHA256_KEY_DERIVATION);
    ExportConstant(CKM_SHA384_KEY_DERIVATION);
    ExportConstant(CKM_SHA512_KEY_DERIVATION);

    /* CKM_SHA224 new for v2.20 amendment 3 */
    ExportConstant(CKM_SHA224_KEY_DERIVATION);

    ExportConstant(CKM_PBE_MD2_DES_CBC);
    ExportConstant(CKM_PBE_MD5_DES_CBC);
    ExportConstant(CKM_PBE_MD5_CAST_CBC);
    ExportConstant(CKM_PBE_MD5_CAST3_CBC);
    ExportConstant(CKM_PBE_MD5_CAST5_CBC);
    ExportConstant(CKM_PBE_MD5_CAST128_CBC);
    ExportConstant(CKM_PBE_SHA1_CAST5_CBC);
    ExportConstant(CKM_PBE_SHA1_CAST128_CBC);
    ExportConstant(CKM_PBE_SHA1_RC4_128);
    ExportConstant(CKM_PBE_SHA1_RC4_40);
    ExportConstant(CKM_PBE_SHA1_DES3_EDE_CBC);
    ExportConstant(CKM_PBE_SHA1_DES2_EDE_CBC);
    ExportConstant(CKM_PBE_SHA1_RC2_128_CBC);
    ExportConstant(CKM_PBE_SHA1_RC2_40_CBC);

    /* CKM_PKCS5_PBKD2 is new for v2.10 */
    ExportConstant(CKM_PKCS5_PBKD2);

    ExportConstant(CKM_PBA_SHA1_WITH_SHA1_HMAC);

    /* WTLS mechanisms are new for v2.20 */
    ExportConstant(CKM_WTLS_PRE_MASTER_KEY_GEN);
    ExportConstant(CKM_WTLS_MASTER_KEY_DERIVE);
    ExportConstant(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC);
    ExportConstant(CKM_WTLS_PRF);
    ExportConstant(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE);
    ExportConstant(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE);

    ExportConstant(CKM_KEY_WRAP_LYNKS);
    ExportConstant(CKM_KEY_WRAP_SET_OAEP);

    /* CKM_CMS_SIG is new for v2.20 */
    ExportConstant(CKM_CMS_SIG);

    /* Fortezza mechanisms */
    ExportConstant(CKM_SKIPJACK_KEY_GEN);
    ExportConstant(CKM_SKIPJACK_ECB64);
    ExportConstant(CKM_SKIPJACK_CBC64);
    ExportConstant(CKM_SKIPJACK_OFB64);
    ExportConstant(CKM_SKIPJACK_CFB64);
    ExportConstant(CKM_SKIPJACK_CFB32);
    ExportConstant(CKM_SKIPJACK_CFB16);
    ExportConstant(CKM_SKIPJACK_CFB8);
    ExportConstant(CKM_SKIPJACK_WRAP);
    ExportConstant(CKM_SKIPJACK_PRIVATE_WRAP);
    ExportConstant(CKM_SKIPJACK_RELAYX);
    ExportConstant(CKM_KEA_KEY_PAIR_GEN);
    ExportConstant(CKM_KEA_KEY_DERIVE);
    ExportConstant(CKM_FORTEZZA_TIMESTAMP);
    ExportConstant(CKM_BATON_KEY_GEN);
    ExportConstant(CKM_BATON_ECB128);
    ExportConstant(CKM_BATON_ECB96);
    ExportConstant(CKM_BATON_CBC128);
    ExportConstant(CKM_BATON_COUNTER);
    ExportConstant(CKM_BATON_SHUFFLE);
    ExportConstant(CKM_BATON_WRAP);

    /* CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
     * CKM_EC_KEY_PAIR_GEN is preferred */
    ExportConstant(CKM_ECDSA_KEY_PAIR_GEN);
    ExportConstant(CKM_EC_KEY_PAIR_GEN);

    ExportConstant(CKM_ECDSA);
    ExportConstant(CKM_ECDSA_SHA1);

    /* CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_ECMQV_DERIVE
     * are new for v2.11 */
    ExportConstant(CKM_ECDH1_DERIVE);
    ExportConstant(CKM_ECDH1_COFACTOR_DERIVE);
    ExportConstant(CKM_ECMQV_DERIVE);

    ExportConstant(CKM_JUNIPER_KEY_GEN);
    ExportConstant(CKM_JUNIPER_ECB128);
    ExportConstant(CKM_JUNIPER_CBC128);
    ExportConstant(CKM_JUNIPER_COUNTER);
    ExportConstant(CKM_JUNIPER_SHUFFLE);
    ExportConstant(CKM_JUNIPER_WRAP);
    ExportConstant(CKM_FASTHASH);

    /* CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC,
     * CKM_AES_MAC_GENERAL, CKM_AES_CBC_PAD, CKM_DSA_PARAMETER_GEN,
     * CKM_DH_PKCS_PARAMETER_GEN, and CKM_X9_42_DH_PARAMETER_GEN are
     * new for v2.11 */
    ExportConstant(CKM_AES_KEY_GEN);
    ExportConstant(CKM_AES_ECB);
    ExportConstant(CKM_AES_CBC);
    ExportConstant(CKM_AES_MAC);
    ExportConstant(CKM_AES_MAC_GENERAL);
    ExportConstant(CKM_AES_CBC_PAD);

    /* BlowFish and TwoFish are new for v2.20 */
    ExportConstant(CKM_BLOWFISH_KEY_GEN);
    ExportConstant(CKM_BLOWFISH_CBC);
    ExportConstant(CKM_TWOFISH_KEY_GEN);
    ExportConstant(CKM_TWOFISH_CBC);

    /* Camellia is proposed for v2.20 Amendment 3 */
    ExportConstant(CKM_CAMELLIA_KEY_GEN);
    ExportConstant(CKM_CAMELLIA_ECB);
    ExportConstant(CKM_CAMELLIA_CBC);
    ExportConstant(CKM_CAMELLIA_MAC);
    ExportConstant(CKM_CAMELLIA_MAC_GENERAL);
    ExportConstant(CKM_CAMELLIA_CBC_PAD);
    ExportConstant(CKM_CAMELLIA_ECB_ENCRYPT_DATA);
    ExportConstant(CKM_CAMELLIA_CBC_ENCRYPT_DATA);

#if defined(CKM_SEED_KEY_GEN)
    ExportConstant(CKM_SEED_KEY_GEN);
    ExportConstant(CKM_SEED_ECB);
    ExportConstant(CKM_SEED_CBC);
    ExportConstant(CKM_SEED_MAC);
    ExportConstant(CKM_SEED_MAC_GENERAL);
    ExportConstant(CKM_SEED_CBC_PAD);
    ExportConstant(CKM_SEED_ECB_ENCRYPT_DATA);
    ExportConstant(CKM_SEED_CBC_ENCRYPT_DATA);
#endif

    /* CKM_xxx_ENCRYPT_DATA mechanisms are new for v2.20 */
    ExportConstant(CKM_DES_ECB_ENCRYPT_DATA);
    ExportConstant(CKM_DES_CBC_ENCRYPT_DATA);
    ExportConstant(CKM_DES3_ECB_ENCRYPT_DATA);
    ExportConstant(CKM_DES3_CBC_ENCRYPT_DATA);
    ExportConstant(CKM_AES_ECB_ENCRYPT_DATA);
    ExportConstant(CKM_AES_CBC_ENCRYPT_DATA);

    ExportConstant(CKM_DSA_PARAMETER_GEN);
    ExportConstant(CKM_DH_PKCS_PARAMETER_GEN);
    ExportConstant(CKM_X9_42_DH_PARAMETER_GEN);

#undef ExportConstant

    /***************************************************************************
     * Attribute Types
     ***************************************************************************/
    if ((cka_name_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((cka_value_to_name = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstant(constant)                      \
if (_AddIntConstantWithLookup(m, #constant, constant, \
    "CKA_", cka_name_to_value, cka_value_to_name) < 0) return MOD_ERROR_VAL;

    /* The following attribute types are defined: */
    ExportConstant(CKA_CLASS);
    ExportConstant(CKA_TOKEN);
    ExportConstant(CKA_PRIVATE);
    ExportConstant(CKA_LABEL);
    ExportConstant(CKA_APPLICATION);
    ExportConstant(CKA_VALUE);

    /* CKA_OBJECT_ID is new for v2.10 */
    ExportConstant(CKA_OBJECT_ID);

    ExportConstant(CKA_CERTIFICATE_TYPE);
    ExportConstant(CKA_ISSUER);
    ExportConstant(CKA_SERIAL_NUMBER);

    /* CKA_AC_ISSUER, CKA_OWNER, and CKA_ATTR_TYPES are new for v2.10 */
    ExportConstant(CKA_AC_ISSUER);
    ExportConstant(CKA_OWNER);
    ExportConstant(CKA_ATTR_TYPES);

    /* CKA_TRUSTED is new for v2.11 */
    ExportConstant(CKA_TRUSTED);

    /* CKA_CERTIFICATE_CATEGORY ...
     * CKA_CHECK_VALUE are new for v2.20 */
    ExportConstant(CKA_CERTIFICATE_CATEGORY);
    ExportConstant(CKA_JAVA_MIDP_SECURITY_DOMAIN);
    ExportConstant(CKA_URL);
    ExportConstant(CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
    ExportConstant(CKA_HASH_OF_ISSUER_PUBLIC_KEY);
    ExportConstant(CKA_CHECK_VALUE);

    ExportConstant(CKA_KEY_TYPE);
    ExportConstant(CKA_SUBJECT);
    ExportConstant(CKA_ID);
    ExportConstant(CKA_SENSITIVE);
    ExportConstant(CKA_ENCRYPT);
    ExportConstant(CKA_DECRYPT);
    ExportConstant(CKA_WRAP);
    ExportConstant(CKA_UNWRAP);
    ExportConstant(CKA_SIGN);
    ExportConstant(CKA_SIGN_RECOVER);
    ExportConstant(CKA_VERIFY);
    ExportConstant(CKA_VERIFY_RECOVER);
    ExportConstant(CKA_DERIVE);
    ExportConstant(CKA_START_DATE);
    ExportConstant(CKA_END_DATE);
    ExportConstant(CKA_MODULUS);
    ExportConstant(CKA_MODULUS_BITS);
    ExportConstant(CKA_PUBLIC_EXPONENT);
    ExportConstant(CKA_PRIVATE_EXPONENT);
    ExportConstant(CKA_PRIME_1);
    ExportConstant(CKA_PRIME_2);
    ExportConstant(CKA_EXPONENT_1);
    ExportConstant(CKA_EXPONENT_2);
    ExportConstant(CKA_COEFFICIENT);
    ExportConstant(CKA_PRIME);
    ExportConstant(CKA_SUBPRIME);
    ExportConstant(CKA_BASE);

    /* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
    ExportConstant(CKA_PRIME_BITS);
    ExportConstant(CKA_SUBPRIME_BITS);
    ExportConstant(CKA_SUB_PRIME_BITS);
    /* (To retain backwards-compatibility) */

    ExportConstant(CKA_VALUE_BITS);
    ExportConstant(CKA_VALUE_LEN);

    /* CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
     * CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE, CKA_ECDSA_PARAMS,
     * and CKA_EC_POINT are new for v2.0 */
    ExportConstant(CKA_EXTRACTABLE);
    ExportConstant(CKA_LOCAL);
    ExportConstant(CKA_NEVER_EXTRACTABLE);
    ExportConstant(CKA_ALWAYS_SENSITIVE);

    /* CKA_KEY_GEN_MECHANISM is new for v2.11 */
    ExportConstant(CKA_KEY_GEN_MECHANISM);

    ExportConstant(CKA_MODIFIABLE);

    /* CKA_ECDSA_PARAMS is deprecated in v2.11,
     * CKA_EC_PARAMS is preferred. */
    ExportConstant(CKA_ECDSA_PARAMS);
    ExportConstant(CKA_EC_PARAMS);

    ExportConstant(CKA_EC_POINT);

    /* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
     * are new for v2.10. Deprecated in v2.11 and onwards. */
    ExportConstant(CKA_SECONDARY_AUTH);
    ExportConstant(CKA_AUTH_PIN_FLAGS);

    /* CKA_ALWAYS_AUTHENTICATE ...
     * CKA_UNWRAP_TEMPLATE are new for v2.20 */
    ExportConstant(CKA_ALWAYS_AUTHENTICATE);

    ExportConstant(CKA_WRAP_WITH_TRUSTED);
    ExportConstant(CKA_WRAP_TEMPLATE);
    ExportConstant(CKA_UNWRAP_TEMPLATE);

    /* CKA_HW_FEATURE_TYPE, CKA_RESET_ON_INIT, and CKA_HAS_RESET
     * are new for v2.10 */
    ExportConstant(CKA_HW_FEATURE_TYPE);
    ExportConstant(CKA_RESET_ON_INIT);
    ExportConstant(CKA_HAS_RESET);

    /* The following attributes are new for v2.20 */
    ExportConstant(CKA_PIXEL_X);
    ExportConstant(CKA_PIXEL_Y);
    ExportConstant(CKA_RESOLUTION);
    ExportConstant(CKA_CHAR_ROWS);
    ExportConstant(CKA_CHAR_COLUMNS);
    ExportConstant(CKA_COLOR);
    ExportConstant(CKA_BITS_PER_PIXEL);
    ExportConstant(CKA_CHAR_SETS);
    ExportConstant(CKA_ENCODING_METHODS);
    ExportConstant(CKA_MIME_TYPES);
    ExportConstant(CKA_MECHANISM_TYPE);
    ExportConstant(CKA_REQUIRED_CMS_ATTRIBUTES);
    ExportConstant(CKA_DEFAULT_CMS_ATTRIBUTES);
    ExportConstant(CKA_SUPPORTED_CMS_ATTRIBUTES);
    ExportConstant(CKA_ALLOWED_MECHANISMS);

    ExportConstant(CKA_VENDOR_DEFINED);

#undef ExportConstant

    /***************************************************************************
     * SEC OID TAGS
     ***************************************************************************/

    if ((sec_oid_name_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((sec_oid_value_to_name = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstant(constant)                      \
if (_AddIntConstantWithLookup(m, #constant, constant, \
    "SEC_OID_", sec_oid_name_to_value, sec_oid_value_to_name) < 0) return MOD_ERROR_VAL;

    ExportConstant(SEC_OID_UNKNOWN);
    ExportConstant(SEC_OID_MD2);
    ExportConstant(SEC_OID_MD4);
    ExportConstant(SEC_OID_MD5);
    ExportConstant(SEC_OID_SHA1);
    ExportConstant(SEC_OID_RC2_CBC);
    ExportConstant(SEC_OID_RC4);
    ExportConstant(SEC_OID_DES_EDE3_CBC);
    ExportConstant(SEC_OID_RC5_CBC_PAD);
    ExportConstant(SEC_OID_DES_ECB);
    ExportConstant(SEC_OID_DES_CBC);
    ExportConstant(SEC_OID_DES_OFB);
    ExportConstant(SEC_OID_DES_CFB);
    ExportConstant(SEC_OID_DES_MAC);
    ExportConstant(SEC_OID_DES_EDE);
    ExportConstant(SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE);
    ExportConstant(SEC_OID_PKCS1_RSA_ENCRYPTION);
    ExportConstant(SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION);
    ExportConstant(SEC_OID_PKCS1_MD4_WITH_RSA_ENCRYPTION);
    ExportConstant(SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION);
    ExportConstant(SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION);
    ExportConstant(SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC);
    ExportConstant(SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC);
    ExportConstant(SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC);
    ExportConstant(SEC_OID_PKCS7);
    ExportConstant(SEC_OID_PKCS7_DATA);
    ExportConstant(SEC_OID_PKCS7_SIGNED_DATA);
    ExportConstant(SEC_OID_PKCS7_ENVELOPED_DATA);
    ExportConstant(SEC_OID_PKCS7_SIGNED_ENVELOPED_DATA);
    ExportConstant(SEC_OID_PKCS7_DIGESTED_DATA);
    ExportConstant(SEC_OID_PKCS7_ENCRYPTED_DATA);
    ExportConstant(SEC_OID_PKCS9_EMAIL_ADDRESS);
    ExportConstant(SEC_OID_PKCS9_UNSTRUCTURED_NAME);
    ExportConstant(SEC_OID_PKCS9_CONTENT_TYPE);
    ExportConstant(SEC_OID_PKCS9_MESSAGE_DIGEST);
    ExportConstant(SEC_OID_PKCS9_SIGNING_TIME);
    ExportConstant(SEC_OID_PKCS9_COUNTER_SIGNATURE);
    ExportConstant(SEC_OID_PKCS9_CHALLENGE_PASSWORD);
    ExportConstant(SEC_OID_PKCS9_UNSTRUCTURED_ADDRESS);
    ExportConstant(SEC_OID_PKCS9_EXTENDED_CERTIFICATE_ATTRIBUTES);
    ExportConstant(SEC_OID_PKCS9_SMIME_CAPABILITIES);
    ExportConstant(SEC_OID_AVA_COMMON_NAME);
    ExportConstant(SEC_OID_AVA_COUNTRY_NAME);
    ExportConstant(SEC_OID_AVA_LOCALITY);
    ExportConstant(SEC_OID_AVA_STATE_OR_PROVINCE);
    ExportConstant(SEC_OID_AVA_ORGANIZATION_NAME);
    ExportConstant(SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME);
    ExportConstant(SEC_OID_AVA_DN_QUALIFIER);
    ExportConstant(SEC_OID_AVA_DC);

    ExportConstant(SEC_OID_NS_TYPE_GIF);
    ExportConstant(SEC_OID_NS_TYPE_JPEG);
    ExportConstant(SEC_OID_NS_TYPE_URL);
    ExportConstant(SEC_OID_NS_TYPE_HTML);
    ExportConstant(SEC_OID_NS_TYPE_CERT_SEQUENCE);
    ExportConstant(SEC_OID_MISSI_KEA_DSS_OLD);
    ExportConstant(SEC_OID_MISSI_DSS_OLD);
    ExportConstant(SEC_OID_MISSI_KEA_DSS);
    ExportConstant(SEC_OID_MISSI_DSS);
    ExportConstant(SEC_OID_MISSI_KEA);
    ExportConstant(SEC_OID_MISSI_ALT_KEA);

    /* Netscape private certificate extensions */
    ExportConstant(SEC_OID_NS_CERT_EXT_NETSCAPE_OK);
    ExportConstant(SEC_OID_NS_CERT_EXT_ISSUER_LOGO);
    ExportConstant(SEC_OID_NS_CERT_EXT_SUBJECT_LOGO);
    ExportConstant(SEC_OID_NS_CERT_EXT_CERT_TYPE);
    ExportConstant(SEC_OID_NS_CERT_EXT_BASE_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_REVOCATION_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_CA_REVOCATION_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_CA_CRL_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_CA_CERT_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_CERT_RENEWAL_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_CA_POLICY_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_HOMEPAGE_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_ENTITY_LOGO);
    ExportConstant(SEC_OID_NS_CERT_EXT_USER_PICTURE);
    ExportConstant(SEC_OID_NS_CERT_EXT_SSL_SERVER_NAME);
    ExportConstant(SEC_OID_NS_CERT_EXT_COMMENT);
    ExportConstant(SEC_OID_NS_CERT_EXT_LOST_PASSWORD_URL);
    ExportConstant(SEC_OID_NS_CERT_EXT_CERT_RENEWAL_TIME);
    ExportConstant(SEC_OID_NS_KEY_USAGE_GOVT_APPROVED);

    /* x.509 v3 Extensions */
    ExportConstant(SEC_OID_X509_SUBJECT_DIRECTORY_ATTR);
    ExportConstant(SEC_OID_X509_SUBJECT_KEY_ID);
    ExportConstant(SEC_OID_X509_KEY_USAGE);
    ExportConstant(SEC_OID_X509_PRIVATE_KEY_USAGE_PERIOD);
    ExportConstant(SEC_OID_X509_SUBJECT_ALT_NAME);
    ExportConstant(SEC_OID_X509_ISSUER_ALT_NAME);
    ExportConstant(SEC_OID_X509_BASIC_CONSTRAINTS);
    ExportConstant(SEC_OID_X509_NAME_CONSTRAINTS);
    ExportConstant(SEC_OID_X509_CRL_DIST_POINTS);
    ExportConstant(SEC_OID_X509_CERTIFICATE_POLICIES);
    ExportConstant(SEC_OID_X509_POLICY_MAPPINGS);
    ExportConstant(SEC_OID_X509_POLICY_CONSTRAINTS);
    ExportConstant(SEC_OID_X509_AUTH_KEY_ID);
    ExportConstant(SEC_OID_X509_EXT_KEY_USAGE);
    ExportConstant(SEC_OID_X509_AUTH_INFO_ACCESS);

    ExportConstant(SEC_OID_X509_CRL_NUMBER);
    ExportConstant(SEC_OID_X509_REASON_CODE);
    ExportConstant(SEC_OID_X509_INVALID_DATE);
    /* End of x.509 v3 Extensions */

    ExportConstant(SEC_OID_X500_RSA_ENCRYPTION);

    /* alg 1485 additions */
    ExportConstant(SEC_OID_RFC1274_UID);
    ExportConstant(SEC_OID_RFC1274_MAIL);

    /* PKCS 12 additions */
    ExportConstant(SEC_OID_PKCS12);
    ExportConstant(SEC_OID_PKCS12_MODE_IDS);
    ExportConstant(SEC_OID_PKCS12_ESPVK_IDS);
    ExportConstant(SEC_OID_PKCS12_BAG_IDS);
    ExportConstant(SEC_OID_PKCS12_CERT_BAG_IDS);
    ExportConstant(SEC_OID_PKCS12_OIDS);
    ExportConstant(SEC_OID_PKCS12_PBE_IDS);
    ExportConstant(SEC_OID_PKCS12_SIGNATURE_IDS);
    ExportConstant(SEC_OID_PKCS12_ENVELOPING_IDS);
   /* SEC_OID_PKCS12_OFFLINE_TRANSPORT_MODE,
    SEC_OID_PKCS12_ONLINE_TRANSPORT_MODE, */
    ExportConstant(SEC_OID_PKCS12_PKCS8_KEY_SHROUDING);
    ExportConstant(SEC_OID_PKCS12_KEY_BAG_ID);
    ExportConstant(SEC_OID_PKCS12_CERT_AND_CRL_BAG_ID);
    ExportConstant(SEC_OID_PKCS12_SECRET_BAG_ID);
    ExportConstant(SEC_OID_PKCS12_X509_CERT_CRL_BAG);
    ExportConstant(SEC_OID_PKCS12_SDSI_CERT_BAG);
    ExportConstant(SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4);
    ExportConstant(SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4);
    ExportConstant(SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC);
    ExportConstant(SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC);
    ExportConstant(SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC);
    ExportConstant(SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_128_BIT_RC4);
    ExportConstant(SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_40_BIT_RC4);
    ExportConstant(SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_TRIPLE_DES);
    ExportConstant(SEC_OID_PKCS12_RSA_SIGNATURE_WITH_SHA1_DIGEST);
    /* end of PKCS 12 additions */

    /* DSA signatures */
    ExportConstant(SEC_OID_ANSIX9_DSA_SIGNATURE);
    ExportConstant(SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST);
    ExportConstant(SEC_OID_BOGUS_DSA_SIGNATURE_WITH_SHA1_DIGEST);

    /* Verisign OIDs */
    ExportConstant(SEC_OID_VERISIGN_USER_NOTICES);

    /* PKIX OIDs */
    ExportConstant(SEC_OID_PKIX_CPS_POINTER_QUALIFIER);
    ExportConstant(SEC_OID_PKIX_USER_NOTICE_QUALIFIER);
    ExportConstant(SEC_OID_PKIX_OCSP);
    ExportConstant(SEC_OID_PKIX_OCSP_BASIC_RESPONSE);
    ExportConstant(SEC_OID_PKIX_OCSP_NONCE);
    ExportConstant(SEC_OID_PKIX_OCSP_CRL);
    ExportConstant(SEC_OID_PKIX_OCSP_RESPONSE);
    ExportConstant(SEC_OID_PKIX_OCSP_NO_CHECK);
    ExportConstant(SEC_OID_PKIX_OCSP_ARCHIVE_CUTOFF);
    ExportConstant(SEC_OID_PKIX_OCSP_SERVICE_LOCATOR);
    ExportConstant(SEC_OID_PKIX_REGCTRL_REGTOKEN);
    ExportConstant(SEC_OID_PKIX_REGCTRL_AUTHENTICATOR);
    ExportConstant(SEC_OID_PKIX_REGCTRL_PKIPUBINFO);
    ExportConstant(SEC_OID_PKIX_REGCTRL_PKI_ARCH_OPTIONS);
    ExportConstant(SEC_OID_PKIX_REGCTRL_OLD_CERT_ID);
    ExportConstant(SEC_OID_PKIX_REGCTRL_PROTOCOL_ENC_KEY);
    ExportConstant(SEC_OID_PKIX_REGINFO_UTF8_PAIRS);
    ExportConstant(SEC_OID_PKIX_REGINFO_CERT_REQUEST);
    ExportConstant(SEC_OID_EXT_KEY_USAGE_SERVER_AUTH);
    ExportConstant(SEC_OID_EXT_KEY_USAGE_CLIENT_AUTH);
    ExportConstant(SEC_OID_EXT_KEY_USAGE_CODE_SIGN);
    ExportConstant(SEC_OID_EXT_KEY_USAGE_EMAIL_PROTECT);
    ExportConstant(SEC_OID_EXT_KEY_USAGE_TIME_STAMP);
    ExportConstant(SEC_OID_OCSP_RESPONDER);

    /* Netscape Algorithm OIDs */
    ExportConstant(SEC_OID_NETSCAPE_SMIME_KEA);

    /* Skipjack OID -- ### mwelch temporary */
    ExportConstant(SEC_OID_FORTEZZA_SKIPJACK);

    /* PKCS 12 V2 oids */
    ExportConstant(SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4);
    ExportConstant(SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4);
    ExportConstant(SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC);
    ExportConstant(SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC);
    ExportConstant(SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC);
    ExportConstant(SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC);
    ExportConstant(SEC_OID_PKCS12_SAFE_CONTENTS_ID);
    ExportConstant(SEC_OID_PKCS12_PKCS8_SHROUDED_KEY_BAG_ID);

    ExportConstant(SEC_OID_PKCS12_V1_KEY_BAG_ID);
    ExportConstant(SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID);
    ExportConstant(SEC_OID_PKCS12_V1_CERT_BAG_ID);
    ExportConstant(SEC_OID_PKCS12_V1_CRL_BAG_ID);
    ExportConstant(SEC_OID_PKCS12_V1_SECRET_BAG_ID);
    ExportConstant(SEC_OID_PKCS12_V1_SAFE_CONTENTS_BAG_ID);
    ExportConstant(SEC_OID_PKCS9_X509_CERT);
    ExportConstant(SEC_OID_PKCS9_SDSI_CERT);
    ExportConstant(SEC_OID_PKCS9_X509_CRL);
    ExportConstant(SEC_OID_PKCS9_FRIENDLY_NAME);
    ExportConstant(SEC_OID_PKCS9_LOCAL_KEY_ID);
    ExportConstant(SEC_OID_BOGUS_KEY_USAGE);

    /*Diffe Helman OIDS */
    ExportConstant(SEC_OID_X942_DIFFIE_HELMAN_KEY);

    /* Netscape other name types */
    ExportConstant(SEC_OID_NETSCAPE_NICKNAME);

    /* Cert Server OIDS */
    ExportConstant(SEC_OID_NETSCAPE_RECOVERY_REQUEST);

    /* New PSM certificate management OIDs */
    ExportConstant(SEC_OID_CERT_RENEWAL_LOCATOR);
    ExportConstant(SEC_OID_NS_CERT_EXT_SCOPE_OF_USE);

    /* CMS (RFC2630) OIDs */
    ExportConstant(SEC_OID_CMS_EPHEMERAL_STATIC_DIFFIE_HELLMAN);
    ExportConstant(SEC_OID_CMS_3DES_KEY_WRAP);
    ExportConstant(SEC_OID_CMS_RC2_KEY_WRAP);

    /* SMIME attributes */
    ExportConstant(SEC_OID_SMIME_ENCRYPTION_KEY_PREFERENCE);

    /* AES OIDs */
    ExportConstant(SEC_OID_AES_128_ECB);
    ExportConstant(SEC_OID_AES_128_CBC);
    ExportConstant(SEC_OID_AES_192_ECB);
    ExportConstant(SEC_OID_AES_192_CBC);
    ExportConstant(SEC_OID_AES_256_ECB);
    ExportConstant(SEC_OID_AES_256_CBC);

    ExportConstant(SEC_OID_SDN702_DSA_SIGNATURE);

    ExportConstant(SEC_OID_MS_SMIME_ENCRYPTION_KEY_PREFERENCE);

    ExportConstant(SEC_OID_SHA256);
    ExportConstant(SEC_OID_SHA384);
    ExportConstant(SEC_OID_SHA512);

    ExportConstant(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION);
    ExportConstant(SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION);
    ExportConstant(SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION);

    ExportConstant(SEC_OID_AES_128_KEY_WRAP);
    ExportConstant(SEC_OID_AES_192_KEY_WRAP);
    ExportConstant(SEC_OID_AES_256_KEY_WRAP);

    /* Elliptic Curve Cryptography (ECC) OIDs */
    ExportConstant(SEC_OID_ANSIX962_EC_PUBLIC_KEY);
    ExportConstant(SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE);

    ExportConstant(SEC_OID_ANSIX962_ECDSA_SIGNATURE_WITH_SHA1_DIGEST);

    /* ANSI X9.62 named elliptic curves (prime field) */
    ExportConstant(SEC_OID_ANSIX962_EC_PRIME192V1);
    ExportConstant(SEC_OID_ANSIX962_EC_PRIME192V2);
    ExportConstant(SEC_OID_ANSIX962_EC_PRIME192V3);
    ExportConstant(SEC_OID_ANSIX962_EC_PRIME239V1);
    ExportConstant(SEC_OID_ANSIX962_EC_PRIME239V2);
    ExportConstant(SEC_OID_ANSIX962_EC_PRIME239V3);
    ExportConstant(SEC_OID_ANSIX962_EC_PRIME256V1);

    /* SECG named elliptic curves (prime field) */
    ExportConstant(SEC_OID_SECG_EC_SECP112R1);
    ExportConstant(SEC_OID_SECG_EC_SECP112R2);
    ExportConstant(SEC_OID_SECG_EC_SECP128R1);
    ExportConstant(SEC_OID_SECG_EC_SECP128R2);
    ExportConstant(SEC_OID_SECG_EC_SECP160K1);
    ExportConstant(SEC_OID_SECG_EC_SECP160R1);
    ExportConstant(SEC_OID_SECG_EC_SECP160R2);
    ExportConstant(SEC_OID_SECG_EC_SECP192K1);
    /* SEC_OID_SECG_EC_SECP192R1 is SEC_OID_ANSIX962_EC_PRIME192V1 */
    ExportConstant(SEC_OID_SECG_EC_SECP224K1);
    ExportConstant(SEC_OID_SECG_EC_SECP224R1);
    ExportConstant(SEC_OID_SECG_EC_SECP256K1);
    /* SEC_OID_SECG_EC_SECP256R1 is SEC_OID_ANSIX962_EC_PRIME256V1 */
    ExportConstant(SEC_OID_SECG_EC_SECP384R1);
    ExportConstant(SEC_OID_SECG_EC_SECP521R1);

    /* ANSI X9.62 named elliptic curves (characteristic two field) */
    ExportConstant(SEC_OID_ANSIX962_EC_C2PNB163V1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2PNB163V2);
    ExportConstant(SEC_OID_ANSIX962_EC_C2PNB163V3);
    ExportConstant(SEC_OID_ANSIX962_EC_C2PNB176V1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2TNB191V1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2TNB191V2);
    ExportConstant(SEC_OID_ANSIX962_EC_C2TNB191V3);
    ExportConstant(SEC_OID_ANSIX962_EC_C2ONB191V4);
    ExportConstant(SEC_OID_ANSIX962_EC_C2ONB191V5);
    ExportConstant(SEC_OID_ANSIX962_EC_C2PNB208W1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2TNB239V1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2TNB239V2);
    ExportConstant(SEC_OID_ANSIX962_EC_C2TNB239V3);
    ExportConstant(SEC_OID_ANSIX962_EC_C2ONB239V4);
    ExportConstant(SEC_OID_ANSIX962_EC_C2ONB239V5);
    ExportConstant(SEC_OID_ANSIX962_EC_C2PNB272W1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2PNB304W1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2TNB359V1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2PNB368W1);
    ExportConstant(SEC_OID_ANSIX962_EC_C2TNB431R1);

    /* SECG named elliptic curves (characteristic two field) */
    ExportConstant(SEC_OID_SECG_EC_SECT113R1);
    ExportConstant(SEC_OID_SECG_EC_SECT113R2);
    ExportConstant(SEC_OID_SECG_EC_SECT131R1);
    ExportConstant(SEC_OID_SECG_EC_SECT131R2);
    ExportConstant(SEC_OID_SECG_EC_SECT163K1);
    ExportConstant(SEC_OID_SECG_EC_SECT163R1);
    ExportConstant(SEC_OID_SECG_EC_SECT163R2);
    ExportConstant(SEC_OID_SECG_EC_SECT193R1);
    ExportConstant(SEC_OID_SECG_EC_SECT193R2);
    ExportConstant(SEC_OID_SECG_EC_SECT233K1);
    ExportConstant(SEC_OID_SECG_EC_SECT233R1);
    ExportConstant(SEC_OID_SECG_EC_SECT239K1);
    ExportConstant(SEC_OID_SECG_EC_SECT283K1);
    ExportConstant(SEC_OID_SECG_EC_SECT283R1);
    ExportConstant(SEC_OID_SECG_EC_SECT409K1);
    ExportConstant(SEC_OID_SECG_EC_SECT409R1);
    ExportConstant(SEC_OID_SECG_EC_SECT571K1);
    ExportConstant(SEC_OID_SECG_EC_SECT571R1);

    ExportConstant(SEC_OID_NETSCAPE_AOLSCREENNAME);

    ExportConstant(SEC_OID_AVA_SURNAME);
    ExportConstant(SEC_OID_AVA_SERIAL_NUMBER);
    ExportConstant(SEC_OID_AVA_STREET_ADDRESS);
    ExportConstant(SEC_OID_AVA_TITLE);
    ExportConstant(SEC_OID_AVA_POSTAL_ADDRESS);
    ExportConstant(SEC_OID_AVA_POSTAL_CODE);
    ExportConstant(SEC_OID_AVA_POST_OFFICE_BOX);
    ExportConstant(SEC_OID_AVA_GIVEN_NAME);
    ExportConstant(SEC_OID_AVA_INITIALS);
    ExportConstant(SEC_OID_AVA_GENERATION_QUALIFIER);
    ExportConstant(SEC_OID_AVA_HOUSE_IDENTIFIER);
    ExportConstant(SEC_OID_AVA_PSEUDONYM);

    /* More OIDs */
    ExportConstant(SEC_OID_PKIX_CA_ISSUERS);
    ExportConstant(SEC_OID_PKCS9_EXTENSION_REQUEST);

    /* new EC Signature oids */
    ExportConstant(SEC_OID_ANSIX962_ECDSA_SIGNATURE_RECOMMENDED_DIGEST);
    ExportConstant(SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST);
    ExportConstant(SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE);
    ExportConstant(SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE);
    ExportConstant(SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE);
    ExportConstant(SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE);

    /* More id-ce and id-pe OIDs from RFC 3280 */
    ExportConstant(SEC_OID_X509_HOLD_INSTRUCTION_CODE);
    ExportConstant(SEC_OID_X509_DELTA_CRL_INDICATOR);
    ExportConstant(SEC_OID_X509_ISSUING_DISTRIBUTION_POINT);
    ExportConstant(SEC_OID_X509_CERT_ISSUER);
    ExportConstant(SEC_OID_X509_FRESHEST_CRL);
    ExportConstant(SEC_OID_X509_INHIBIT_ANY_POLICY);
    ExportConstant(SEC_OID_X509_SUBJECT_INFO_ACCESS);

    /* Camellia OIDs (RFC3657)*/
    ExportConstant(SEC_OID_CAMELLIA_128_CBC);
    ExportConstant(SEC_OID_CAMELLIA_192_CBC);
    ExportConstant(SEC_OID_CAMELLIA_256_CBC);

    /* PKCS 5 V2 OIDS */
    ExportConstant(SEC_OID_PKCS5_PBKDF2);
    ExportConstant(SEC_OID_PKCS5_PBES2);
    ExportConstant(SEC_OID_PKCS5_PBMAC1);
    ExportConstant(SEC_OID_HMAC_SHA1);
    ExportConstant(SEC_OID_HMAC_SHA224);
    ExportConstant(SEC_OID_HMAC_SHA256);
    ExportConstant(SEC_OID_HMAC_SHA384);
    ExportConstant(SEC_OID_HMAC_SHA512);

    ExportConstant(SEC_OID_PKIX_TIMESTAMPING);
    ExportConstant(SEC_OID_PKIX_CA_REPOSITORY);

    ExportConstant(SEC_OID_ISO_SHA1_WITH_RSA_SIGNATURE);

#if defined(SEC_OID_SEED_CBC)
    ExportConstant(SEC_OID_SEED_CBC);
#endif

#if defined(SEC_OID_X509_ANY_POLICY)
    ExportConstant(SEC_OID_X509_ANY_POLICY);
#endif

    ExportConstant(SEC_OID_SECG_EC_SECP192R1);
    ExportConstant(SEC_OID_SECG_EC_SECP256R1);
    ExportConstant(SEC_OID_PKCS12_KEY_USAGE);

#undef ExportConstant

    /***************************************************************************
     * PK11Origin
     ***************************************************************************/
    AddIntConstant(PK11_OriginNULL);         /* There is not key, it's a null SymKey */
    AddIntConstant(PK11_OriginDerive);       /* Key was derived from some other key */
    AddIntConstant(PK11_OriginGenerated);    /* Key was generated (also PBE keys) */
    AddIntConstant(PK11_OriginFortezzaHack); /* Key was marked for fortezza hack */
    AddIntConstant(PK11_OriginUnwrap);       /* Key was unwrapped or decrypted */

    /***************************************************************************
     * PK11 Slot Disabled Reason
     ***************************************************************************/

    AddIntConstant(PK11_DIS_NONE);                 /* no reason */
    AddIntConstant(PK11_DIS_USER_SELECTED);        /* user disabled */
    AddIntConstant(PK11_DIS_COULD_NOT_INIT_TOKEN); /* could not initialize token */
    AddIntConstant(PK11_DIS_TOKEN_VERIFY_FAILED);  /* could not verify token */
    AddIntConstant(PK11_DIS_TOKEN_NOT_PRESENT);    /* token not present */

    /***************************************************************************
     * OCSP Failure Mode
     ***************************************************************************/

    AddIntConstant(ocspMode_FailureIsVerificationFailure);
    AddIntConstant(ocspMode_FailureIsNotAVerificationFailure);

    /***************************************************************************
     * PKCS12
     ***************************************************************************/

    if ((pkcs12_cipher_name_to_value = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }
    if ((pkcs12_cipher_value_to_name = PyDict_New()) == NULL) {
        return MOD_ERROR_VAL;
    }

#define ExportConstant(constant)                      \
if (_AddIntConstantWithLookup(m, #constant, constant, \
    "PKCS12_", pkcs12_cipher_name_to_value, pkcs12_cipher_value_to_name) < 0) return MOD_ERROR_VAL;

    ExportConstant(PKCS12_RC2_CBC_40);
    ExportConstant(PKCS12_RC2_CBC_128);
    ExportConstant(PKCS12_RC4_40);
    ExportConstant(PKCS12_RC4_128);
    ExportConstant(PKCS12_DES_56);
    ExportConstant(PKCS12_DES_EDE3_168);

    return MOD_SUCCESS_VAL(m);
}
