#!/usr/bin/env python3

'''Using mad regexes, automatically make sure that all structs with sub-byte
integers have matching big-endian definitions. The idea is to save a lot of
manual effort, and to automatically verify that there are no errors.
This script most certainly has numerous holes and shortcomings, but actually,
if you hit problems with it, rather adjust your coding style so that this
script can deal with it...'''

import re
import sys
import codecs
import os.path

re_struct_start = re.compile(r'^struct\s*[a-zA-Z_][a-zA-Z_0-9]*\s*{\s*$')
re_struct_end = re.compile(r'^}[^;]*;\s*$')

re_substruct_start = re.compile(r'^\s+struct\s*{\s*$')
re_substruct_end = re.compile(r'^\s+}\s*([^;]*\s)[a-zA-Z_][a-zA-Z_0-9]*\s*;\s*$')
re_unnamed_substruct_end = re.compile(r'^\s+}\s*;\s*$')

re_int_def = re.compile(r'(^\s*((const|unsigned|signed|char|int|long|int[0-9]+_t|uint[0-9]_t)\s+)+\s*)([^;]*;)',
                        re.DOTALL | re.MULTILINE)
re_int_members = re.compile(r'([a-zA-Z_][a-zA-Z_0-9]*|[a-zA-Z_][a-zA-Z_0-9]*\s*:\s*[0-9]+)\s*[,;]\s*', re.DOTALL | re.MULTILINE)

re_little_endian_ifdef = re.compile(r'#\s*(if|elif)\s+OSMO_IS_LITTLE_ENDIAN\s*(==\s*1\s*|)');
re_big_endian_ifdef = re.compile(r'#\s*(if|elif)\s+OSMO_IS_BIG_ENDIAN\s*');
re_else = re.compile(r'#\s*else\s*');
re_endif = re.compile(r'#\s*endif\s*');

re_c_comment = re.compile(r'(/\*[^*]+\*/|//.?$)')

def remove_c_comments(code_str):
    return ''.join(re_c_comment.split(code_str)[::2])

def section_struct_body(struct_body_lines):
    '''divide a top-level-struct body into sections of
    ['arbitrary string', ['body;\n', 'lines;\n'], 'arbitrary string', ...]
    Aim: handle each sub-struct on its own, and if there already are ifdefs for
    little and big endian, keep just the little endian bit and derive big
    endian from it.
    An arbitrary string is anything other than struct member definitions, like
    a 'struct {', '} sub_name;', ...
    "body lines" are lines that define struct members (possibly with comments).
    Return: list of alternate arbitrary strings and variable definitions.
    '''

    # these globals are needed so that end_def() can change them from inside
    # the function. Not very nice style, but easiest implementation.
    global struct_body_parts
    global arbitrary_part
    global def_part

    struct_body_parts = []
    arbitrary_part = []
    def_part = []

    def end_def():
        '''if there is any content, flush out recorded parts (def_part,
        arbitrary_part) and start a new part. In short, cut a section
        boundary.'''
        global struct_body_parts
        global arbitrary_part
        global def_part

        if def_part:
            struct_body_parts.append(arbitrary_part)
            arbitrary_part = []
            struct_body_parts.append(def_part)
            def_part = []

    j = 0
    while j < len(struct_body_lines):
        line = struct_body_lines[j]

        if (re_substruct_start.fullmatch(line)
            or re_substruct_end.fullmatch(line)
            or re_unnamed_substruct_end.fullmatch(line)):
            end_def()
            arbitrary_part.append(line)
            j += 1
            continue

        if re_big_endian_ifdef.fullmatch(line):
            end_def()
            # discard big endian section
            j += 1
            while j < len(struct_body_lines):
                line = struct_body_lines[j]
                if re_endif.fullmatch(line):
                    end_def()
                    j += 1
                    break;
                if re_little_endian_ifdef.fullmatch(line):
                    end_def()
                    # keep that start of little endian section, not j++
                    break;
                if re_else.fullmatch(line):
                    # there's an '#else' after big-endian. Shim a little-endian header in just for the loop.
                    struct_body_lines[j] = '#if OSMO_IS_LITTLE_ENDIAN\n'
                    break;
                j += 1
            continue

        if re_little_endian_ifdef.fullmatch(line):
            end_def()
            j += 1
            while j < len(struct_body_lines):
                line = struct_body_lines[j]
                if re_endif.fullmatch(line):
                    end_def()
                    j += 1
                    break;
                if re_big_endian_ifdef.fullmatch(line):
                    end_def()
                    # keep that start of big endian section, not j++
                    break;
                if re_else.fullmatch(line):
                    # there's an '#else' after little-endian. Shim a big-endian header in just for the loop.
                    struct_body_lines[j] = '#if OSMO_IS_BIG_ENDIAN\n'
                    break;
                def_part.append(line)
                j += 1

            continue

        def_part.append(line)
        j += 1

    # flush the last section remaining that didn't see an explicit end
    end_def()
    # end_def() only flushes arbitrary_part if there was a def_part, so:
    if arbitrary_part:
        struct_body_parts.append(arbitrary_part)

    return struct_body_parts

def struct_body_to_big_endian(body_str):
    '''Input: a multi-line string containing the body of a struct, i.e. without
    sub-structs and without #if OSMO_IS_BIG_ENDIAN. like

      '\tconst char *foo;\n\tuint8_t moo:3, goo:2;\n\tuint8_t loo:3;\n\tvoid *baz;\n'

    Return None to indicate that there is no little/big endian split
    required, or return a multi-line string of the big-endian version of this
    same struct body, where sub-byte ints are reversed at byte boundaries, and
    all others are copied 1:1. If there are no sub-byte integers, return None,
    to indicate that there is no little/big endian split required.'''

    # kick comments out of the code analysis. They will end up being stripped
    # from big-endian only.
    body_str = remove_c_comments(body_str)

    def_strs = body_str.split(';')
    def_strs = ('%s;' % def_str for def_str in def_strs if def_str.strip())

    # classify defs as containing sub-byte members or not
    # defs = [ (true, 'uint8_t ', ('foo:3', 'bar:5')),
    #          (false, 'int baz;'),...]
    defs = []
    any_sub_byte_ints = False
    for one_def in def_strs:

        # does it have sub-string integers?
        int_def = re_int_def.fullmatch(one_def)
        if not int_def:
            # not even a number, same for big and little endian
            defs.append((False, one_def))
            continue

        int_type = int_def.group(1)
        members_str = int_def.groups()[-1]
        has_sub_byte_ints = False

        members = []
        for int_member in re_int_members.finditer(members_str):
            member = int_member.group(1)
            members.append(member)
            if ':' in member:
                has_sub_byte_ints = True

        if not has_sub_byte_ints:
            defs.append((False, one_def))
        else:
            defs.append((True, one_def, int_type, members))
            any_sub_byte_ints = True

    if not any_sub_byte_ints:
        return None

    # now the interesting part, go over the defs, and reverse the sub-byte ints
    # at byte boundaries.

    i = 0
    got_bits = 0
    byte_type = None
    members_within_a_byte = []
    big_endian_defs = []

    big_defs = []
    for classified_def in defs:
        has_sub_byte_ints = classified_def[0]

        # now the big endian part
        if has_sub_byte_ints:
            _, one_def, int_type, members = classified_def

            if byte_type and byte_type.strip() != int_type.strip():
                raise Exception('mismatching type continuation after incomplete byte: %r %r to %r'
                                % (byte_type, members_within_a_byte, int_type))
            byte_type = int_type

            for member in members:
                member_name, bits_str = member.split(':')
                member_name = member_name.strip()
                bits = int(bits_str)
                member = '%s:%d' % (member_name, bits)
                members_within_a_byte.append(member)
                got_bits += bits

                if got_bits == 8:
                    # reverse these.
                    big_endian_defs.append('%s%s;' % (byte_type, ', '.join(reversed(members_within_a_byte))))
                    members_within_a_byte = []
                    byte_type = None
                    got_bits = 0

                elif got_bits > 8:
                    raise Exception('sub-byte int breaks clean byte bounds: %s -- %d + %d = %d bits'
                                    % (member, got_bits - bits, bits, got_bits))

        elif not has_sub_byte_ints:
            if got_bits:
                raise Exception('sub-byte members do not add up to clean byte bounds: %r' % members_within_a_byte)

            big_endian_defs.append(classified_def[1])

    # strip empty lines
    lines = [l for l in (''.join(big_endian_defs).split('\n')) if l.strip()]
    # clean lines' whitespace errors we might have taken in with the type names
    for i in range(len(lines)):
        line = lines[i]
        while len(line) and line[-1] in ' \t':
            line = line[:-1]
        lines[i] = line
    return '\n'.join(lines)

def handle_struct_body(body_str):

    big_endian_body_str = struct_body_to_big_endian(body_str)

    if big_endian_body_str:
        new_lines = ['#if OSMO_IS_LITTLE_ENDIAN\n']
        new_lines.append(body_str)
        new_lines.append('#elif OSMO_IS_BIG_ENDIAN\n'
                         '/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */\n')
        new_lines.append(big_endian_body_str)
        new_lines.append('\n#endif\n')
        return ''.join(new_lines)
    else:
        return body_str

def _check_file(f):
    if not (f.endswith('.h') or f.endswith('.c') or f.endswith('.cpp')):
        return

    # section the file into
    # [ ["no struct def"], ["struct {...};"], ["no struct def"], ... ]
    sections = []
    in_struct = False
    buf = []
    for line in codecs.open(f, "r", "utf-8").readlines():

        if not in_struct and re_struct_start.fullmatch(line):
            # flush whatever might still be in buf from before
            sections.append(buf)
            # start an in_struct section
            buf = [line]
            in_struct = True
        elif in_struct and re_struct_end.fullmatch(line):
            # add this end to the in_struct section and then start a non-struct section
            buf.append(line)
            sections.append(buf)
            in_struct = False
            buf = []
        else:
            buf.append(line)
    # flush any leftovers in buf
    if buf:
        sections.append(buf)

    # examine each struct, i.e. every second item in 'sections'
    for i in range(len(sections)):
        if not (i & 1):
            continue

        struct = sections[i]

        # If the struct isn't packed, we need not bother.
        # The practical use of this: in some structs we have booleans in the
        # form of
        #     integer flag:1;
        # and these don't add up to bytes, and cause errors. So let's skip all
        # non-packed structs, then all of those are out of the picture.
        if not 'packed' in struct[-1]:
            continue

        try:

            # assume the 'struct foo {' is on the first line, the closing brace
            # '} __attribute...;' on the last, and the rest are individual
            # definitions split by ';'.
            struct_body_lines = struct[1:-1]
            struct_body_parts = section_struct_body(struct_body_lines)

            new_struct_body_parts = []
            for j in range(len(struct_body_parts)):
                part = ''.join(struct_body_parts[j])
                if not (j & 1):
                    new_struct_body_parts.append(part)
                else:
                    new_struct_body_parts.append(handle_struct_body(part))

            new_struct = [struct[0], ''.join(new_struct_body_parts), struct[-1]]
            sections[i] = new_struct
        except Exception as e:
            raise Exception('ERROR in struct %r' % struct[0])

    # phew. result.
    result = ''.join((''.join(s) for s in sections))

    # see if osmocom/core/endian.h is needed and included.
    if (not f.endswith('endian.h')
        and 'OSMO_IS_LITTLE_ENDIAN' in result
        and '#include <osmocom/core/endian.h>' not in result):
        # add the include after the last 'osmocom/core' include
        last_include_start = result.rfind('#include <osmocom/core/')
        if last_include_start < 0:
            last_include_start = result.rfind('#include <osmocom/')
        if last_include_start < 0:
            last_include_start = result.rfind('#include')

        if last_include_start < 0:
            raise Exception('do not know where to include osmocom/core/endian.h in %r' % f)

        insert_at = result.find('\n', last_include_start)

        result = result[:insert_at] + '\n#include <osmocom/core/endian.h>' + result[insert_at:]

    with codecs.open(f, "w", "utf-8") as fd:
        fd.write(result)

def check_file(f):
        try:
            _check_file(f)
        except Exception as e:
            raise Exception('ERROR IN FILE %r' % f)

args = sys.argv[1:]
if not args:
    args = ['.']

for f in args:
    if os.path.isdir(f):
        for parent_path, subdirs, files in os.walk(f, None, None):
            for ff in files:
                check_file(os.path.join(parent_path, ff))
    else:
        check_file(f)

# vim: tabstop=4 shiftwidth=4 expandtab
