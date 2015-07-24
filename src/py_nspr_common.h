/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//#define DEBUG

#define PACKAGE_NAME "nss"

typedef PyObject *(*format_lines_func)(PyObject *self, PyObject *args, PyObject *kwds);

typedef enum RepresentationKindEnum {
    AsObject,
    AsString,
    AsTypeString,
    AsTypeEnum,
    AsLabeledString,
    AsEnum,
    AsEnumName,
    AsEnumDescription,
    AsIndex,
    AsDottedDecimal,
} RepresentationKind;


#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#define NSS_THREAD_LOCAL_KEY "nss"

#define PyBoolAsPRBool(x) ((x) == Py_True ? PR_TRUE : PR_FALSE)

#define ASSIGN_REF(dst, obj)                    \
do {                                            \
    PyObject *tmp;                              \
                                                \
    tmp = (PyObject *)dst;                      \
    Py_INCREF(obj);                             \
    dst = obj;                                  \
    Py_CLEAR(tmp);                              \
} while (0)

#define ASSIGN_NEW_REF(dst, obj)                \
do {                                            \
    PyObject *tmp;                              \
                                                \
    tmp = (PyObject *)dst;                      \
    dst = obj;                                  \
    Py_CLEAR(tmp);                              \
} while (0)


/******************************************************************************/

#define OCTETS_PER_LINE_DEFAULT 16
#define HEX_SEPARATOR_DEFAULT ":"

#define FMT_OBJ_AND_APPEND(dst_fmt_tuples, label, src_obj, level, fail) \
{                                                                       \
    PyObject *fmt_tuple = NULL;                                         \
                                                                        \
    if ((fmt_tuple = line_fmt_tuple(level, label, src_obj)) == NULL) {  \
        goto fail;                                                      \
    }                                                                   \
    if (PyList_Append(dst_fmt_tuples, fmt_tuple) != 0) {                \
        Py_DECREF(fmt_tuple);                                           \
        goto fail;                                                      \
    }                                                                   \
}

#define FMT_LABEL_AND_APPEND(dst_fmt_tuples, label, level, fail)        \
{                                                                       \
    PyObject *fmt_tuple = NULL;                                         \
                                                                        \
    if ((fmt_tuple = fmt_label(level, label)) == NULL) {                \
        goto fail;                                                      \
    }                                                                   \
    if (PyList_Append(dst_fmt_tuples, fmt_tuple) != 0) {                \
        Py_DECREF(fmt_tuple);                                           \
        goto fail;                                                      \
    }                                                                   \
}

#define APPEND_LINE_TUPLES_AND_CLEAR(dst_fmt_tuples, src_fmt_tuples, fail) \
{                                                                       \
    PyObject *src_obj;                                                  \
    Py_ssize_t len, i;                                                  \
    if (src_fmt_tuples) {                                               \
        len = PyList_Size(src_fmt_tuples);                              \
        for (i = 0; i < len; i++) {                                     \
            src_obj = PyList_GetItem(src_fmt_tuples, i);                \
            PyList_Append(dst_fmt_tuples, src_obj);                     \
        }                                                               \
        Py_CLEAR(src_fmt_tuples);                                       \
    }                                                                   \
}

#define APPEND_LINES_AND_CLEAR(dst_fmt_tuples, src_lines, level, fail)  \
{                                                                       \
    PyObject *src_obj;                                                  \
    Py_ssize_t len, i;                                                  \
    if (src_lines) {                                                    \
        len = PySequence_Size(src_lines);                               \
        for (i = 0; i < len; i++) {                                     \
            src_obj = PySequence_GetItem(src_lines, i);                 \
            FMT_OBJ_AND_APPEND(dst_fmt_tuples, NULL, src_obj, level, fail); \
            Py_DECREF(src_obj);                                         \
        }                                                               \
        Py_CLEAR(src_lines);                                            \
    }                                                                   \
}

#define CALL_FORMAT_LINES_AND_APPEND(dst_fmt_tuples, obj, level, fail)  \
{                                                                       \
    PyObject *obj_line_fmt_tuples;                                      \
                                                                        \
    if ((obj_line_fmt_tuples =                                          \
         PyObject_CallMethod(obj, "format_lines",                       \
                             "(i)", level)) == NULL) {                  \
        goto fail;                                                      \
    }                                                                   \
                                                                        \
    APPEND_LINE_TUPLES_AND_CLEAR(dst_fmt_tuples, obj_line_fmt_tuples, fail); \
}


#define APPEND_OBJ_TO_HEX_LINES_AND_CLEAR(dst_fmt_tuples, obj, level, fail) \
{                                                                       \
    PyObject *obj_lines;                                                \
                                                                        \
    if ((obj_lines = obj_to_hex(obj, OCTETS_PER_LINE_DEFAULT,           \
                                HEX_SEPARATOR_DEFAULT)) == NULL) {      \
        goto fail;                                                      \
    }                                                                   \
    Py_CLEAR(obj);                                                      \
    APPEND_LINES_AND_CLEAR(dst_fmt_tuples, obj_lines, level, fail);     \
}

#define FMT_SEC_INT_OBJ_APPEND_AND_CLEAR(dst_fmt_tuples, label, obj, level, fail) \
{                                                                       \
    PyObject *obj_lines = NULL;                                         \
    SecItem *item = (SecItem *)obj;                                     \
                                                                        \
    FMT_LABEL_AND_APPEND(dst_fmt_tuples, label, level, fail);           \
    if ((obj_lines = secitem_integer_format_lines(&item->item, level+1)) == NULL) { \
        goto fail;                                                      \
    }                                                                   \
    Py_CLEAR(obj);                                                      \
    APPEND_LINE_TUPLES_AND_CLEAR(dst_fmt_tuples, obj_lines, fail);      \
}

/******************************************************************************/

// Gettext
#ifndef _
#define _(s) s
#endif

#if (PY_VERSION_HEX < 0x02050000)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#define PyInt_FromSsize_t PyInt_FromLong
#define PyNumber_AsSsize_t(ob, exc) PyInt_AsLong(ob)
#define PyIndex_Check(ob) PyInt_Check(ob)
typedef Py_ssize_t (*readbufferproc)(PyObject *, Py_ssize_t, void **);
typedef Py_ssize_t (*writebufferproc)(PyObject *, Py_ssize_t, void **);
typedef Py_ssize_t (*segcountproc)(PyObject *, Py_ssize_t *);
typedef Py_ssize_t (*charbufferproc)(PyObject *, Py_ssize_t, char **);
typedef Py_ssize_t (*lenfunc)(PyObject *);
typedef PyObject *(*ssizeargfunc)(PyObject *, Py_ssize_t);
typedef PyObject *(*ssizessizeargfunc)(PyObject *, Py_ssize_t, Py_ssize_t);
#endif

#if (PY_VERSION_HEX < 0x02060000)
#define Py_TYPE(ob) (((PyObject*)(ob))->ob_type)
#define PyVarObject_HEAD_INIT(type, size) \
	PyObject_HEAD_INIT(type) size,
#define PyImport_ImportModuleNoBlock PyImport_ImportModule
#define PyLong_FromSsize_t PyInt_FromLong
#define Py_TPFLAGS_HAVE_NEWBUFFER 0
#endif

#define PyNone_Check(x) ((x) == Py_None)

#define CALL_BASE(type, func, ...) (type)->tp_base->tp_##func(__VA_ARGS__)

#define TYPE_READY(type)                                                \
{                                                                       \
    if (PyType_Ready(&type) < 0)                                        \
        return MOD_ERROR_VAL;                                           \
    Py_INCREF(&type);                                                   \
    PyModule_AddObject(m, rindex(type.tp_name, '.')+1, (PyObject *)&type); \
}

#define AddIntConstant(c)                                               \
{                                                                       \
    PyObject *dict;                                                     \
                                                                        \
                                                                        \
    if ((dict = PyModule_GetDict(m)) == NULL) {                         \
        PyErr_Format(PyExc_SystemError, "module '%s' has no __dict__",  \
                     PyModule_GetName(m));                              \
        return MOD_ERROR_VAL;                                           \
    }                                                                   \
    if (PyDict_GetItemString(dict, #c)) {                               \
        PyErr_Format(PyExc_SystemError, "module '%s' already contains %s", \
                         PyModule_GetName(m), #c);                      \
        return MOD_ERROR_VAL;                                           \
    }                                                                   \
    if (PyModule_AddIntConstant(m, #c, c) < 0) return MOD_ERROR_VAL;    \
}

#define AddIntConstantName(name, c)                                     \
{                                                                       \
    PyObject *dict;                                                     \
                                                                        \
                                                                        \
    if ((dict = PyModule_GetDict(m)) == NULL) {                         \
        PyErr_Format(PyExc_SystemError, "module '%s' has no __dict__",  \
                     PyModule_GetName(m));                              \
        return MOD_ERROR_VAL;                                           \
    }                                                                   \
    if (PyDict_GetItemString(dict, #c)) {                               \
        PyErr_Format(PyExc_SystemError, "module '%s' already contains %s", \
                         PyModule_GetName(m), #c);                      \
        return MOD_ERROR_VAL;                                           \
    }                                                                   \
    if (PyModule_AddIntConstant(m, #name, c) < 0) return MOD_ERROR_VAL; \
}

#ifdef DEBUG

#define DumpRefCount(x)                                                 \
{                                                                       \
    PyObject *_obj = (PyObject *) (x);                                  \
    printf("<%s object at %p refcnt=%d>\n", Py_TYPE(_obj)->tp_name, _obj, _obj->ob_refcnt); \
}


#define TraceMessage(_msg)                      \
{                                               \
    printf("%s\n", _msg);                       \
}

#define TraceMethodEnter(x)                                             \
{                                                                       \
    PyObject *_obj = (PyObject *) (x);                                  \
    const char *name = NULL;                                            \
                                                                        \
    if (_obj) {                                                         \
        name = Py_TYPE(_obj)->tp_name;                                  \
    }                                                                   \
    printf("%s (Enter): <%s object at %p refcnt=%d>\n",                 \
           __FUNCTION__, name, _obj, _obj ? _obj->ob_refcnt : -9999);   \
}

#define TraceMethodLeave(x)                                             \
{                                                                       \
    PyObject *_obj = (PyObject *) (x);                                  \
    const char *name = NULL;                                            \
                                                                        \
    if (_obj) {                                                         \
        name = Py_TYPE(_obj)->tp_name;                                  \
    }                                                                   \
    printf("%s (Leave): <%s object at %p refcnt=%d>\n",                 \
           __FUNCTION__, name, _obj, _obj ? _obj->ob_refcnt : -9999);   \
}

#define TraceObjNewEnter(_tp)                                   \
{                                                               \
    PyTypeObject *tp = _tp;                                     \
    if (tp != NULL)                                             \
        printf("%s (Enter) %s\n", __FUNCTION__, tp->tp_name);   \
    else                                                        \
        printf("%s (Enter)\n", __FUNCTION__);                   \
}


#define TraceObjNewLeave(x)                                             \
{                                                                       \
    PyObject *_obj = (PyObject *) (x);                                  \
    const char *name = NULL;                                            \
                                                                        \
    if (_obj) {                                                         \
        name = Py_TYPE(_obj)->tp_name;                                  \
    }                                                                   \
    printf("%s: returns <%s object at %p refcnt=%d>\n",                 \
           __FUNCTION__, name, _obj, _obj ? _obj->ob_refcnt : -9999);   \
}

#else
#define DumpRefCount(_obj)
#define TraceMessage(_msg)
#define TraceMethodEnter(_obj)
#define TraceMethodLeave(_obj)
#define TraceObjNewEnter(_tp)
#define TraceObjNewLeave(_obj)
#endif
