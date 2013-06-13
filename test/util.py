import sys
import os
from distutils.util import get_platform

def get_build_dir():
    '''
    Walk from the current directory up until a directory is found
    which contains a regular file called "setup.py" and a directory
    called "build". If found return the fully qualified path to
    the build directory's platform specific directory, this is where
    the architecture specific build produced by setup.py is located.

    There is no API in distutils to return the platform specific
    directory so we use as much as distutils exposes, the rest was
    determined by looking at the source code for distutils.

    If the build directory cannont be found in the tree None is returned.
    '''
    cwd = os.getcwd()
    path_components = cwd.split('/')
    while (len(path_components)):
        path = os.path.join('/', *path_components)
        setup_path = os.path.join(path, 'setup.py')
        build_path = os.path.join(path, 'build')
        # Does this directory contain the file "setup.py" and the directory "build"?
        if os.path.exists(setup_path) and os.path.exists(build_path) and \
           os.path.isfile(setup_path) and os.path.isdir(build_path):
            # Found, return the path contentated with the architecture
            # specific build directory
            platform_specifier = "lib.%s-%s" % (get_platform(), sys.version[0:3])
            return os.path.join(build_path, platform_specifier)

        # Not found, ascend to parent directory and try again
        path_components.pop()

    # Failed to find the build directory
    return None

def insert_build_dir_into_path():
    sys.path.insert(0,get_build_dir())
