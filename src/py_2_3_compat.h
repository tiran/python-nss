#ifndef PY_2_3_COMPAT_H
#define PY_2_3_COMPAT_H

#if PY_VERSION_HEX <  0x02070000
// As part of the Python 2 to Python 3 conversion we need at least
// version 2.7 because 2.7 shares API's with 3.x
#error "Python version must be at least 2.7"
#endif

#define PyNone_Check(x) ((x) == Py_None)

#if PY_MAJOR_VERSION >= 3

/******************************************************************************
 *                                  Python 3                                  *
 ******************************************************************************/


#define IS_PY3K

#define MOD_ERROR_VAL NULL
#define MOD_SUCCESS_VAL(val) val
#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)

#define PyInteger_Check(obj)  PyLong_Check(obj)
#define PyBaseString_Check(obj) PyUnicode_Check(obj)

static inline PyObject *
PyBaseString_UTF8(PyObject *obj, char *name)
{
    if (obj == NULL) {
        return PyUnicode_FromString("<NULL>");
    }

    if (PyUnicode_Check(obj)) {
        return PyUnicode_AsUTF8String(obj);
    }

    if (name) {
        PyErr_Format(PyExc_TypeError, "%s must be a string, not %.200s",
                     name, Py_TYPE(obj)->tp_name);
        return NULL;
    } else {
        PyErr_Format(PyExc_TypeError, "must be a string, not %.200s",
                     Py_TYPE(obj)->tp_name);
        return NULL;
    }
}

/* Returns new reference */
static inline PyObject *
PyUnicode_from_basestring(PyObject *obj)
{
    if (PyUnicode_Check(obj)) {
        Py_INCREF(obj);
        return obj;
    }

    PyErr_Format(PyExc_TypeError, "must be string, not %.200s",
                 Py_TYPE(obj)->tp_name);

    return NULL;
}

/* Returns new reference */
static inline PyObject *
PyObject_String(PyObject *obj)
{
    return PyObject_Str(obj);
}

static inline int
UnicodeOrNoneConvert(PyObject *obj, PyObject **param)
{
    if (!obj) {
        *param = NULL;
        return 1;
    }

    if (PyNone_Check(obj)) {
        *param = NULL;
        return 1;
    }

    if (PyUnicode_Check(obj)) {
        Py_INCREF(obj);
        *param = obj;
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be a string or None, not %.200s",
                 Py_TYPE(obj)->tp_name);

    return 0;
}

#else  /* PY_MAJOR_VERSION < 3 */

/******************************************************************************
 *                                  Python 2                                  *
 ******************************************************************************/

#include "bytesobject.h"

#define MOD_ERROR_VAL
#define MOD_SUCCESS_VAL(val)
#define MOD_INIT(name) void init##name(void)

#define PyInteger_Check(obj) (PyInt_Check(obj) || PyLong_Check(obj))
#define PyBaseString_Check(obj) (PyString_Check(obj) || PyUnicode_Check(obj))

/* returns new reference or NULL on error */
static inline PyObject *
PyBaseString_UTF8(PyObject *obj, char *name)
{
    if (obj == NULL) {
        return PyUnicode_FromString("<NULL>");
    }

    if (PyString_Check(obj)) {
        Py_INCREF(obj);
        return obj;
    }

    if (PyUnicode_Check(obj)) {
        return PyUnicode_AsUTF8String(obj);
    }

    if (name) {
        PyErr_Format(PyExc_TypeError, "%s must be a string, not %.200s",
                     name, Py_TYPE(obj)->tp_name);
        return NULL;
    } else {
        PyErr_Format(PyExc_TypeError, "must be a string, not %.200s",
                     Py_TYPE(obj)->tp_name);
        return NULL;
    }
}

/* Returns new reference */
static inline PyObject *
PyUnicode_from_basestring(PyObject *obj)
{
    if (PyUnicode_Check(obj)) {
        Py_INCREF(obj);
        return obj;
    }

    if (PyString_Check(obj)) {
        return PyUnicode_FromString(PyString_AS_STRING(obj)); /* decodes utf-8 */
    }

    PyErr_Format(PyExc_TypeError, "must be string, not %.200s",
                 Py_TYPE(obj)->tp_name);

    return NULL;
}

/* Returns new reference */
static inline PyObject *
PyObject_String(PyObject *obj)
{
    return PyObject_Unicode(obj);
}

/*
 * Py2 does not have file system codecs, emulate PyUnicode_FSConverter()
 * to the best extent possible, convert the unicode to encoded UTF-8.
 * UTF-8 is not the same as file system encoding but it' the best we can
 * do. Caller must DECREF the returned arg.
 */
static inline int
PyUnicode_FSConverter(PyObject* arg, void* addr)
{
    PyObject *output = NULL;

    if (PyString_Check(arg)) {
        output = arg;
        Py_INCREF(output);
    } else if (PyUnicode_Check(arg)) {
        if ((output = PyUnicode_AsUTF8String(arg)) == NULL) {
            return 0;
        }
    } else {
        PyErr_Format(PyExc_TypeError, "must be str or unicode, not %.50s",
                     Py_TYPE(arg)->tp_name);
        return 0;
    }

    *(PyObject**)addr = output;
    return 1;
}

static inline int
UnicodeOrNoneConvert(PyObject *obj, PyObject **param)
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
        if ((*param = PyUnicode_FromString(PyString_AS_STRING(obj))) == NULL) {
            return 0;
        }
        return 1;
    }

    if (PyUnicode_Check(obj)) {
        Py_INCREF(obj);
        *param = obj;
        return 1;
    }

    PyErr_Format(PyExc_TypeError, "must be a string or None, not %.200s",
                 Py_TYPE(obj)->tp_name);

    return 0;
}


#endif  /* PY_MAJOR_VERSION */


#endif /* PY_2_3_COMPAT_H */
