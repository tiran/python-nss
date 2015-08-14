#include "frameobject.h"

/*
 * One would think there would be a CPython function to print a
 * traceback but apparently that's not possible. For starters
 * traceback information is only available after an exception
 * occurs. The function PyTraceBack_Here() which collects the
 * traceback data is called by the interpreter loop as each frame
 * unwinds off the stack. Thus there is no single place to call it
 * from within a CPython function. The traceback.py Python module
 * implements getting a stacktrace (extract_stack()) by forcing an
 * exception and walking the traceback list obtained via
 * sys.exc_info(). Once again not something we can do from within a
 * CPython function. The stackframe list is not the same as a
 * traceback list, they're actually different objects (although a
 * traceback object does have a pointer to it's matching frame
 * object). Because frame objects are not the same as traceback objects
 * we can't use the existing mechanism (PyTraceBack_Print()) to dump
 * the stack. The best we can do is walk the stack frames ourself and
 * output the information most easily available to us.
 */

/*
 * See _Py_DisplaySourceLine() in Python/traceback.c as example of
 * how to print the source code for the line
 */

static void
print_traceback(void)
{
    PyFrameObject *frame = PyEval_GetFrame();
    int depth = 6;

    printf("Traceback (most recent frame first)\n");
    while (frame && depth) {
        PyObject *msg_unicode = NULL;
        PyObject *msg_utf8 = NULL;

        msg_unicode = PyUnicode_FromFormat("  File \"%S\", line %d, in %S\n",
                                           frame->f_code->co_filename,
                                           frame->f_lineno,
                                           frame->f_code->co_name);
        msg_utf8 = PyUnicode_AsUTF8String(msg_unicode);
        printf("%s", PyBytes_AS_STRING(msg_utf8));
        Py_DECREF(msg_unicode);
        Py_DECREF(msg_utf8);

        frame = frame->f_back;
        depth--;
    }
}
