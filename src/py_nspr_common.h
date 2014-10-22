/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//#define DEBUG

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
        return;                                                         \
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
        return;                                                         \
    }                                                                   \
    if (PyDict_GetItemString(dict, #c)) {                               \
        PyErr_Format(PyExc_SystemError, "module '%s' already contains %s", \
                         PyModule_GetName(m), #c);                      \
        return;                                                         \
    }                                                                   \
    if (PyModule_AddIntConstant(m, #c, c) < 0) return;                  \
}

#define AddIntConstantName(name, c)                                     \
{                                                                       \
    PyObject *dict;                                                     \
                                                                        \
                                                                        \
    if ((dict = PyModule_GetDict(m)) == NULL) {                         \
        PyErr_Format(PyExc_SystemError, "module '%s' has no __dict__",  \
                     PyModule_GetName(m));                              \
        return;                                                         \
    }                                                                   \
    if (PyDict_GetItemString(dict, #c)) {                               \
        PyErr_Format(PyExc_SystemError, "module '%s' already contains %s", \
                         PyModule_GetName(m), #c);                      \
        return;                                                         \
    }                                                                   \
    if (PyModule_AddIntConstant(m, #name, c) < 0) return;               \
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
