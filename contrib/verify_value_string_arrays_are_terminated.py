#!/usr/bin/env python3
# vim: expandtab tabstop=2 shiftwidth=2 nocin

'''
Usage:
  verify_value_string_arrays_are_terminated.py PATH [PATH [...]]

e.g.
libosmocore/contrib/verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")
'''

import re
import sys
import codecs

value_string_array_re = re.compile(
  r'((\bstruct\s+value_string\b[^{;]*?)\s*=[^{;]*{[^;]*}\s*;)',
  re.MULTILINE | re.DOTALL)

members = r'(\.(value|str)\s*=\s*)?'
terminator_re = re.compile('{\s*' + members + '(0|NULL)\s*,'
                           '\s*' + members + '(0|NULL)\s*}')
errors_found = 0

for f in sys.argv[1:]:
  arrays = value_string_array_re.findall(codecs.open(f, "r", "utf-8").read())
  for array_def, name in arrays:
    if not terminator_re.search(array_def):
      print('ERROR: file contains unterminated value_string %r: %r'
            % (name, f))
      errors_found += 1

sys.exit(errors_found)
