#!/usr/bin/env python3
#
# read supplied protobuf file and apply various changes, sending the result
# to stdout:
# 1. replace maps

import re
import sys

for line in open(sys.argv[1]).readlines():

    # translate map:
    #
    # map<key_type, value_type> map_field = N;
    #
    # to:
    #
    # message MapFieldEntry {
    #   key_type key = 1;
    #   value_type value = 2;
    # }
    # repeated MapFieldEntry map_field = N;
    match = re.match(r'(\s*)map<(\w+)\s*,\s*(\w+)>\s+(\w+)\s*=\s*('
                     r'\d+)\s*;\s*', line)
    if match:
        indent = match.group(1)
        key_type = match.group(2)
        value_type = match.group(3)
        map_field = match.group(4)
        map_fields_caps = [f.capitalize() for f in map_field.split('_')]
        map_field_entry = ''.join(map_fields_caps) + 'Entry'
        n = match.group(5)
        text = []
        text.append('message %s {' % map_field_entry)
        text.append('  %s key = 1;' % key_type)
        text.append('  %s value = 2;' % value_type)
        text.append('}')
        text.append('repeated %s %s = %s;' % (map_field_entry, map_field, n))
        text = ['%s%s\n' % (indent, t) for t in text]
        line = ''.join(text)

    # output potentially modified line
    sys.stdout.write(line)
