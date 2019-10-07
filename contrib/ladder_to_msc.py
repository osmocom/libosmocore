#!/usr/bin/env python3
doc=r'''
We write a lot of ladder diagrams to explain CNI procedures.
However, the .msc format has a lot of overhead for a human author:

  foo[label="Foo"], bar[label="Bar"];
  foo -> bar [label="Baz msg"];
  foo <= bar [label="Moo",attrib="value",attrib2="value2"];
  foo -> bar [label="Multi\nLine\nDescription"];

This defines a .ladder format that is easier to type and can be directly translated into .msc.

  foo = Foo
  bar = Bar

  foo > bar  Baz msg
  foo << bar  Moo
    {attrib=value, attrib2=value2}

  foo > bar
    Multi
    Line
    Description


  a > b    simple arrow
  a -> b   filled arrow
  a => b   double-lined arrow
  a --> b   dashed-line arrow
  a ~> b   half arrow-head
  a ->< b  arrow with X arrowhead
  a > *    broadcast arrow with multiple heads

'''

import argparse
import sys
import re
import tempfile
import os

def error(*msg):
	sys.stderr.write('%s\n' % (''.join(msg)))
	exit(1)

def quote(msg, quote='"'):
	return '"%s"' % (msg.replace('"', r'\"'))

class Entity:
	def __init__(self):
		self.name = None
		self.descr = None
		self.attrs = {}
	
class Arrow:
	def __init__(self):
		self.left = None
		self.arrow = None
		self.right = None
		self.descr = None
		self.attrs = {}

class Output:
	def __init__(self, write_to):
		self._write_to = write_to
		self.collected_entities = []
		self.empty_lines_after_entities = 0

	def write(self, line):
		self._write_to.write(line)

	def txlate_entity_name(self, name):
		if name == 'msc':
			return '__msc'
		return name

	def start(self):
		self.write('msc {\n');
	def end(self):
		self.write('}\n');

	def writeln(self, line):
		self.write('  %s;\n' % line)

	def root_attrs(self, attrs):
		self.writeln(','.join('%s=%s' % (k,quote(v)) for k,v in attrs.items()))

	def entity(self, e):
		self.collected_entities.append(e)

	def entities(self):
		line = []
		for e in self.collected_entities:
			attr_strs = []
			if e.descr:
				attr_strs.append('label=%s' % quote(e.descr))
			for k,v in e.attrs.items():
				attr_strs.append('%s=%s' % (k, quote(v)))

			if attr_strs:
				line.append('%s[%s]' % (self.txlate_entity_name(e.name), ','.join(attr_strs)))
			else:
				line.append(self.txlate_entity_name(e.name))
		self.writeln('%s' % (','.join(line)))
		self.collected_entities = []
		if self.empty_lines_after_entities:
			self.write('\n' * self.empty_lines_after_entities);
		self.empty_lines_after_entities = 0

	def left_arrow_right(self, arrow):
		if self.collected_entities:
			self.entities()

		line = [self.txlate_entity_name(arrow.left), arrow.arrow, self.txlate_entity_name(arrow.right)]
		attrs = []
		if arrow.descr:
			attrs.append('label=%s' % quote(arrow.descr))
		for k,v in arrow.attrs.items():
			attrs.append('%s=%s' % (k, quote(v)))
		if attrs:
			line.append('[%s]' % (','.join(attrs)))
		self.writeln(' '.join(line))

	def separator(self, sep_str, descr, attrs):
		if self.collected_entities:
			self.entities()

		a = []
		if descr.strip():
			a.append('label=%s' % quote(descr))
		for k,v in attrs.items():
			a.append('%s=%s' % (k, quote(v)))
		if not a:
			self.writeln(sep_str)
		else:
			self.writeln('%s [%s]' % (sep_str, ','.join(a)))

	def empty_line(self, count):
		if self.collected_entities:
			self.empty_lines_after_entities += count
			return
		self.write('\n' * count);

class Parse:
	RE_ENTITY = re.compile(r'^([a-zA-Z0-9_]+)[ \t]*(|=[ \t]*([a-zA-Z].+))$')
	RE_LEFT_ARROW_RIGHT = re.compile(r'^([^ \t<=>()[\]-]+)([ \t]*([<=>[\]():\\/|~-]+)[ \t]*|[ \t]+([a-z]+)[ \t]+)([a-zA-Z0-9_-]+|\*|\.)([ \t]*|[ \t]+(.*)|\\n(.*))$')
	RE_SEPARATOR = re.compile(r'^(\.\.\.|\|\|\||---)[ \t]*(.*)$')
	RE_INDENT = re.compile(r'^([ \t]+).*')
	RE_ATTR = re.compile(r'[{,]([a-zA-Z0-9_-]+)[ \t]*=[ \t]*([^,}]+)')
	RE_ATTRS_STR = re.compile(r'(.*?)[ \t]*({[^}]+=[^}]+})[ \t]*$')
	ARROWS = {
		'>' : '=>>',
		'->' : '=>',
		'-->' : '>>',
		'~>' : '->',
		'=>' : ':>',
		'-><' : '-x',

		'<' : '<<=',
		'<-' : '<=',
		'<--' : '<<',
		'<~' : '<-',
		'<=' : '<:',
		'><-' : 'x-',

		'<>' : 'abox',
		'()' : 'rbox',
		'[]' : 'note',
		}

	def __init__(self, output):
		self.line_block = []
		self.line_block_started_at = 1
		self.output = output
		self.linenr = 0

	def error(self, *msg):
		error('line %d: ' % self.line_block_started_at, *msg)

	def start(self):
		self.output.start()
	def end(self):
		self.output.end()

	def add_line(self, line):
		self.linenr += 1
		if line.endswith('\n'):
			line = line[:-1]
		if line.endswith('\r'):
			line = line[:-1]

		if line.strip().startswith('#'):
			self.output.writeln(line)
			return

		if len(line) > 0 and not Parse.RE_INDENT.match(line):
			self.flush_block()
		self.line_block.append(line)

	def flush_block(self):
		block = self.line_block
		self.line_block = []

		# strip trailing empty lines
		empties = 0
		while len(block) and not block[-1].strip():
			block = block[:-1]
			empties += 1

		self.interpret(block)
		if empties:
			self.output.empty_line(empties)

		self.line_block_started_at = self.linenr

	def interpret(self, block):
		# ignore empty blocks
		if not block:
			return

		if block[0].startswith('{'):
			self.root_attrs(block)
			return

		m = Parse.RE_ENTITY.match(block[0])
		if m:
			self.entity(block)
			return

		m = Parse.RE_SEPARATOR.match(block[0])
		if m:
			self.separator(block)
			return

		self.left_arrow_right(block)

	def remove_indent(self, block):
		if len(block) == 1:
			return block
		first_nonempty_line = None
		for l in block[1:]:
			if not l:
				continue
			first_nonempty_line = l
			break
		if first_nonempty_line is None:
			return block
		m = Parse.RE_INDENT.match(first_nonempty_line)
		indent = m.group(1)
		content = [block[0]]
		for line in block[1:]:
			if not line.strip():
				content.append('')
				continue
			if not line.startswith(indent):
				self.error('Inconsistent indenting: expected %r, got %r' % (indent, line))
			content.append(line[len(indent):])
		return content

	def root_attrs(self, block):
		block = self.remove_indent(block)
		attrs_str = ','.join(block)
		attrs = {}
		for m in Parse.RE_ATTR.finditer(attrs_str):
			key = m.group(1)
			val = m.group(2)
			attrs[key] = val
		self.output.root_attrs(attrs)

	def entity(self, block):
		line = '\\n'.join(self.remove_indent(block))
		m = Parse.RE_ENTITY.match(line)
		if not m:
			self.error('Failure to parse entity like "foo = Description", got %r' % block[0])
		e = Entity()
		e.name = m.group(1)
		if len(m.groups()) > 2:
			e.descr = m.group(3)
		self.output.entity(e)

	def separator(self, block):
		attrs_str, block = self.remove_attrs_str(block)
		line = '\\n'.join(self.remove_indent(block))
		m = Parse.RE_SEPARATOR.match(line)
		if not m:
			self.error('Failure to parse separator like "... Description", got %r' % block[0])
		sep_str = m.group(1)
		descr = m.group(2)
		attrs = {}
		for m in Parse.RE_ATTR.finditer(attrs_str):
			key = m.group(1)
			val = m.group(2)
			attrs[key] = val
		self.output.separator(sep_str, descr, attrs)

	def translate_arrow(self, arrow_str):
		if arrow_str in Parse.ARROWS:
			return Parse.ARROWS.get(arrow_str)
		if arrow_str in Parse.ARROWS.values():
			return arrow_str
		self.error('Unknown arrow string: %r' % arrow_str)

	def remove_attrs_str(self, block):
		last_line = block[-1]
		m = Parse.RE_ATTRS_STR.match(last_line)
		if not m:
			return '', block

		before = m.group(1)
		attrs_str = m.group(2)

		if before:
			block[-1] = before
		else:
			block = block[:-1]
		return attrs_str, block

	def left_arrow_right(self, block):
		attrs_str, block = self.remove_attrs_str(block)
		line = '\\n'.join(self.remove_indent(block))

		m = Parse.RE_LEFT_ARROW_RIGHT.match(line)
		if not m:
			self.error('Expected a line like "foo > bar  Comment", but got:\n%r' % block[0])
		a = Arrow()
		a.left = m.group(1)
		a.arrow = self.translate_arrow(m.group(3) or m.group(4))
		a.right = m.group(5)
		if a.right == '.':
			a.right = a.left
		a.descr = m.group(7) or m.group(8)

		attrs = {}
		for m in Parse.RE_ATTR.finditer(attrs_str):
			key = m.group(1)
			val = m.group(2)
			attrs[key] = val
		a.attrs = attrs

		if a.descr and a.descr.count('^') == 1 and not 'id' in [k.lower() for k in a.attrs.keys()]:
			normal, superscript = a.descr.split('^')
			if normal.strip():
				a.descr = normal
				a.attrs['ID'] = superscript

		self.output.left_arrow_right(a)



def translate(inf, outf, cmdline):
	output = Output(outf)
	parse = Parse(output)

	parse.start()

	while inf.readable():
		line = inf.readline()
		if not line:
			break;
		parse.add_line(line)
	parse.flush_block()
	parse.end()

def open_output(inf, cmdline):
	if cmdline.output_file == '-':
		translate(inf, sys.stdout, cmdline)
	else:
		with tempfile.NamedTemporaryFile(dir=os.path.dirname(cmdline.output_file), mode='w', encoding='utf-8') as tmp_out:
			translate(inf, tmp_out, cmdline)
			if os.path.exists(cmdline.output_file):
				os.unlink(cmdline.output_file)
			os.link(tmp_out.name, cmdline.output_file)
	
def open_input(cmdline):
	if cmdline.input_file == '-':
		open_output(sys.stdin, cmdline)
	else:
		with open(cmdline.input_file, 'r') as f:
			open_output(f, cmdline)

def main(cmdline):
	open_input(cmdline)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=doc)
	parser.add_argument('-i', '--input-file', dest='input_file', default="-",
			help='Read from this file, or stdin if "-"')
	parser.add_argument('-o', '--output-file', dest='output_file', default="-",
			help='Write to this file, or stdout if "-"')

	cmdline = parser.parse_args()

	main(cmdline)

# vim: shiftwidth=8 noexpandtab tabstop=8 autoindent
