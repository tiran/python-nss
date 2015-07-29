#ifndef PY_2_3_COMPAT_H
#define PY_2_3_COMPAT_H

#if PY_MAJOR_VERSION >= 3

#define IS_PY3K

#define MOD_ERROR_VAL NULL
#define MOD_SUCCESS_VAL(val) val
#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)

#define PyInteger_Check(v)  PyLong_Check(v)

#else  /* PY_MAJOR_VERSION < 3 */

#define MOD_ERROR_VAL
#define MOD_SUCCESS_VAL(val)
#define MOD_INIT(name) void init##name(void)

#define PyInteger_Check(v)  (PyInt_Check(v) || PyLong_Check(v))

#endif  /* PY_MAJOR_VERSION */


#endif /* PY_2_3_COMPAT_H */
