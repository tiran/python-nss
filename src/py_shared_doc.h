#ifndef PY_SHARED_DOC_H
#define PY_SHARED_DOC_H

PyDoc_STRVAR(generic_format_doc,
"format(level=0, indent='    ') -> string)\n\
\n\
:Parameters:\n\
    level : integer\n\
        Initial indentation level, all subsequent indents are relative\n\
        to this starting level.\n\
    indent : string\n\
        string replicated once for each indent level then prepended to output line\n\
\n\
This is equivalent to:\n\
indented_format(obj.format_lines()) on an object providing a format_lines() method.\n\
");

PyDoc_STRVAR(generic_format_lines_doc,
"format_lines(level=0) -> [(level, string),...]\n\
\n\
:Parameters:\n\
    level : integer\n\
        Initial indentation level, all subsequent indents are relative\n\
        to this starting level.\n\
\n\
Formats the object into a sequence of lines with indent level\n\
information.  The return value is a list where each list item is a\n\
tuple.  The first item in the tuple is an integer\n\
representing the indentation level for that line. Any remaining items\n\
in the tuple are strings to be output on that line.\n\
\n\
The output of this function can be formatted into a single string by\n\
calling `nss.nss.indented_format()`, e.g.:\n\
\n\
    print indented_format(obj.format_lines())\n\
\n\
The reason this function returns a tuple as opposed to an single\n\
indented string is to support other text formatting systems such as\n\
GUI's with indentation controls.  See `nss.nss.indented_format()` for a\n\
complete explanation.\n\
");

#endif // PY_SHARED_DOC_H
