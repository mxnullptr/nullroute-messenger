#!/usr/bin/env python3
import os
import re


TO_REMOVE         = [ 'build', 'external', 'src/version.hpp' ]
TO_REMOVE_PATTERN = [ '.*cmake.*', 'makefile', '.*\\.a$', '.*\\.so', '.*\\.o', '.*\\.cbp', '.*\\.log' ]
EXCEPTIONS        = [ 'CMakeLists.txt', 'thirdparty' ]

CWD = os.getcwd()

# -------------------------------------------------------------------------------------------------------------------- #
# -------------------------------------------------------------------------------------------------------------------- #

def should_be_removed(path):
    path = os.path.basename(path)

    for pattern in TO_REMOVE_PATTERN:
        if re.match(pattern, path, re.IGNORECASE):
            for exception in EXCEPTIONS:
                if exception == path:
                    return False
            return True
    return False

# -------------------------------------------------------------------------------------------------------------------- #

def remove(path):
    os.system('rm -rf %s' % path)

# -------------------------------------------------------------------------------------------------------------------- #

for item in TO_REMOVE:
    path = os.path.join(CWD, item)
    remove(path)

# -------------------------------------------------------------------------------------------------------------------- #

def main():
    for root, dirs, files in os.walk(CWD):
        for dname in dirs:
            path = os.path.join(root, dname)
            if should_be_removed(path):
                remove(path)
        for fname in files:
            path = os.path.join(root, fname)
            if should_be_removed(path):
                remove(path)

# -------------------------------------------------------------------------------------------------------------------- #

if __name__ == '__main__':
    main()