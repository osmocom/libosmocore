#!/usr/bin/env python

__doc__ = '''
fsm-to-dot: convert FSM definitons to graph images

Usage:
  ./fsm-to-dot.py ~/openbsc/openbsc/src/libvlr/*.c
  for f in *.dot ; do dot -Tpng "$f" > "$f.png"; done
  # dot comes from 'apt-get install graphviz'

Looks for osmo_fsm finite state machine definitions and madly parses .c files
to draw graphs of them. This uses wild regexes that rely on coding style etc..
No proper C parsing is done here (pycparser sucked, unfortunately).
'''

import sys, re, os

if '-h' in sys.argv or '--help' in sys.argv:
  print(__doc__)
  exit(0)

def err(msg):
  sys.stderr.write(msg + '\n')

class listdict(object):
  def __getattr__(ld, name):
    if name == 'add':
      return ld.__getattribute__(name)
    return ld.__dict__.__getattribute__(name)

  def _have(ld, name):
    l = ld.__dict__.get(name)
    if not l:
      l = []
      ld.__dict__[name] = l
    return l

  def add(ld, name, item):
    l = ld._have(name)
    l.append(item)
    return ld

  def add_dict(ld, d):
    for k,v in d.items():
      ld.add(k, v)

  def __setitem__(ld, name, val):
    return ld.__dict__.__setitem__(name, val)

  def __getitem__(ld, name):
    return ld.__dict__.__getitem__(name)

  def __str__(ld):
    return ld.__dict__.__str__()

  def __repr__(ld):
    return ld.__dict__.__repr__()

  def update(ld, other_ld):
    for name, items in other_ld.items():
      ld.extend(name, items)
    return ld

  def extend(ld, name, vals):
    l = ld._have(name)
    l.extend(vals)
    return ld

re_state_start = re.compile(r'\[([A-Z_][A-Z_0-9]*)\]')
re_event_alternatives = [
    re.compile(r'\(1 *<< *([A-Z_][A-Z_0-9]*)\)'),
    re.compile(r'S\(([A-Z_][A-Z_0-9]*)\)'),
  ]
re_action = re.compile(r'.action *= *([a-z_][a-z_0-9]*)')

re_insane_dot_name_chars = re.compile('[^a-zA-Z_]')

def state_starts(line):
  m = re_state_start.search(line)
  if m:
    return m.group(1)
  return None

def in_event_starts(line):
  return line.find('in_event_mask') >= 0

def out_state_starts(line):
  return line.find('out_state_mask') >= 0

def states_or_events(line):
  results = []
  for one_re in re_event_alternatives:
    results.extend(one_re.findall(line))
  return results

def parse_action(line):
  a = re_action.findall(line)
  if a:
    return a[0]
  return None

def _common_prefix(a, b):
  for l in reversed(range(1,len(a))):
    aa = a[:l+1]
    if b.startswith(aa):
      return aa
  return ''

def common_prefix(strs):
  if not strs:
    return ''
  p = None
  for s in strs:
    if p is None:
      p = s
      continue
    p = _common_prefix(p, s)
    if not p:
      return ''
  return p

KIND_STATE = 'KIND_STATE'
KIND_FUNC = 'KIND_FUNC'
KIND_FSM = 'KIND_FSM'
BOX_SHAPES = {
  KIND_STATE : None,
  KIND_FUNC : 'box',
  KIND_FSM : 'box3d',
}

class Event:
  def __init__(event, name):
    event.name = name
    event.short_name = name

  def __cmp__(event, other):
    return cmp(event.name, other.name)

class Edge:
  def __init__(edge, to_state, event_name=None, style=None, action=None, color=None, arrow_head=None):
    edge.to_state = to_state
    edge.style = style
    edge.color = color
    edge.arrow_head = arrow_head
    edge.events = []
    edge.actions = []
    edge.add_event_name(event_name)
    edge.add_action(action)

  def add_event_name(edge, event_name):
    if not event_name:
      return
    edge.add_event(Event(event_name))

  def add_event(edge, event):
    if not event:
      return
    if event in edge.events:
      return
    edge.events.append(event)

  def add_events(edge, events):
    for event in events:
      edge.add_event(event)

  def add_action(edge, action):
    if not action or action in edge.actions:
      return
    edge.actions.append(action)

  def add_actions(edge, actions):
    for action in actions:
      edge.add_action(action)

  def event_names(edge):
    return sorted([event.name for event in edge.events])

  def event_labels(edge):
    return sorted([event.short_name for event in edge.events])

  def action_labels(edge):
    return sorted([action + '()' for action in edge.actions])

  def has_event_name(edge, event_name):
    return event_name in edge.event_names()

class State:
  name = None
  short_name = None
  action = None
  label = None
  in_event_names = None
  out_state_names = None
  out_edges = None
  kind = None
  color = None

  def __init__(state):
    state.in_event_names = []
    state.out_state_names = []
    state.out_edges = []
    state.kind = KIND_STATE

  def add_out_edge(state, edge):
    for out_edge in state.out_edges:
      if out_edge.to_state is edge.to_state:
        if out_edge.style == edge.style:
          out_edge.add_events(edge.events)
          out_edge.add_actions(edge.actions)
          return
      elif out_edge.to_state.get_label() == edge.to_state.get_label():
        # sanity: there already is an edge to a state that a) is not identical to the target state of the
        # newly added edge but b) has the same label.
        raise Exception('Two distinct states exist with identical label: %r: states %r and %r.'
                        % (out_edge.to_state.get_label(), out_edge.to_state, edge.to_state))
    state.out_edges.append(edge)

  def get_label(state):
    if state.label:
      return state.label
    l = [state.short_name]
    if state.action:
      if state.short_name == state.action:
        l = []
      l.append(state.action + '()')
    return r'\n'.join(l)

  def event_names(state):
    event_names = []
    for out_edge in state.out_edges:
      event_names.extend(out_edge.event_names())
    return event_names

  def shape_str(state):
    shape = BOX_SHAPES.get(state.kind, None)
    if not shape:
      return ''
    return ',shape=%s' % shape

  def color_str(state):
    if state.color is None:
      return ''
    return ',color="%s"' % state.color

  def __repr__(state):
    return 'State(name=%r,short_name=%r,out=%d)' % (state.name, state.short_name, len(state.out_edges))

class Fsm:
  def __init__(fsm, struct_name, string_name, states_struct_name, from_file=None):
    fsm.states = []
    fsm.struct_name = struct_name
    fsm.string_name = string_name
    fsm.states_struct_name = states_struct_name
    fsm.from_file = from_file
    fsm.action_funcs = set()
    fsm.event_names = set()
    fsm.dot_name = fsm.all_names_sanitized()

  def __repr__(fsm):
    return str(fsm)

  def __str__(fsm):
    return 'Fsm(%r,%r)' % (fsm.struct_name, fsm.from_file)

  def parse_states(fsm, src, c_file):
    state = None
    started = None

    IN_EVENTS = 'events'
    OUT_STATES = 'states'

    lines = src.splitlines()

    for line in lines:
      state_name = state_starts(line)
      if state_name:
        state = fsm.find_state_by_name(state_name)
        if state is not None:
          if c_file is fsm.from_file:
            print('ERROR: fsm %r has multiple definitions of state %r' % (fsm, state_name))
          else:
            print('ERROR: it appears two FSMs with identical name %r exist in %r and %r'
                  % (fsm.struct_name, fsm.from_file, c_file))
          state = None
          continue
        state = State()
        fsm.states.append(state)
        started = None
        state.name = state_name

      if in_event_starts(line):
        started = IN_EVENTS
      if out_state_starts(line):
        started = OUT_STATES

      if not state or not started:
        continue

      tokens = states_or_events(line)
      if started == IN_EVENTS:
        state.in_event_names.extend(tokens)
      elif started == OUT_STATES:
        state.out_state_names.extend(tokens)
      else:
        err('ignoring: %r' % tokens)

      a = parse_action(line)
      if a:
        state.action = a


    for state in fsm.states:
      if state.action:
        fsm.action_funcs.add(state.action)
      if state.in_event_names:
        fsm.event_names.update(state.in_event_names)

    fsm.make_states_short_names()
    fsm.ref_out_states()

  def make_states_short_names(fsm):
    p = common_prefix([s.name for s in fsm.states])
    for s in fsm.states:
      s.short_name = s.name[len(p):]
    return p

  def make_events_short_names(fsm):
    p = common_prefix(fsm.event_names)
    for state in fsm.states:
      for edge in state.out_edges:
        for event in edge.events:
          event.short_name = event.name[len(p):]

  def ref_out_states(fsm):
    for state in fsm.states:
      for out_state_name in state.out_state_names:
        out_state = fsm.find_state_by_name(out_state_name, False)
        if out_state is None:
          print('ERROR: fsm %r has a transition to state not part of the FSM: %r'
                % (fsm, out_state_name))
          out_state = fsm.have_state(out_state_name, KIND_STATE, color='red')
        state.add_out_edge(Edge(out_state))

  def find_state_by_name(fsm, name, strict=False):
    for state in fsm.states:
      if state.name == name:
        return state
    if strict:
      raise Exception("State not found: %r" % name);
    return None

  def find_state_by_action(fsm, action):
    for state in fsm.states:
      if state.action == action:
        return state
    return None

  def add_special_state(fsm, additional_states, name, in_state=None,
                        out_state=None, event_name=None, kind=KIND_FUNC,
                        state_action=None, label=None, edge_action=None,
                        style='dotted', arrow_head=None):
    additional_state = None
    for s in additional_states:
      if s.short_name == name:
        additional_state = s
        break;

    if not additional_state:
      for s in fsm.states:
        if s.short_name == name:
          additional_state = s
          break;

    if kind == KIND_FUNC and not state_action:
      state_action = name

    if not additional_state:
      additional_state = State()
      additional_state.short_name = name
      additional_state.action = state_action
      additional_state.kind = kind
      additional_state.label = label
      additional_states.append(additional_state)

    if out_state:
      additional_state.out_state_names.append(out_state.name)
      additional_state.add_out_edge(Edge(out_state, event_name, style=style,
                                         action=edge_action, arrow_head=arrow_head))

    if in_state:
      in_state.out_state_names.append(additional_state.name)
      in_state.add_out_edge(Edge(additional_state, event_name, style=style,
                                 action=edge_action, arrow_head=arrow_head))


  def find_event_edges(fsm, c_files):
    # enrich state transitions between the states with event labels
    func_to_state_transitions = listdict()
    for c_file in c_files:
      func_to_state_transitions.update( c_file.find_state_transitions(fsm.event_names) )

    # edges between explicit states
    for state in fsm.states:
      transitions = func_to_state_transitions.get(state.action)
      if not transitions:
        continue

      for to_state_name, event_name in transitions:
        if not event_name:
          continue
        found = False
        for out_edge in state.out_edges:
          if out_edge.to_state.name == to_state_name:
            out_edge.add_event_name(event_name)
            found = True
        if not found:
          sys.stderr.write(
            "ERROR: %s() triggers a transition to %s, but this is not allowed by the FSM definition\n"
            % (state.action, to_state_name))
          state.add_out_edge(Edge(fsm.find_state_by_name(to_state_name, True), event_name,
                                  color='red'))

    additional_states = []


    # functions that aren't state actions but still effect state transitions
    for func_name, transitions in func_to_state_transitions.items():
      if func_name in fsm.action_funcs:
        continue
      for to_state_name, event_name in transitions:
        to_state = fsm.find_state_by_name(to_state_name)
        if not to_state:
          continue
        fsm.add_special_state(additional_states, func_name, None, to_state, event_name)


    event_sources = c_files.find_event_sources(fsm.event_names)

    for state in fsm.states:

      for in_event_name in state.in_event_names:
        funcs_for_in_event = event_sources.get(in_event_name)
        if not funcs_for_in_event:
          continue

        found = False
        for out_edge in state.out_edges:
          if out_edge.has_event_name(in_event_name):
            out_edge.action = r'\n'.join([(f + '()') for f in funcs_for_in_event
                                          if f != state.action])

        # if any functions that don't belong to a state trigger events, add
        # them to the graph as well
        additional_funcs = [f for f in funcs_for_in_event if f not in fsm.action_funcs]
        for af in additional_funcs:
          fsm.add_special_state(additional_states, af, None, state, in_event_name,
                                arrow_head='halfopen')

    fsm.states.extend(additional_states)

    # do any existing action functions by chance call other action functions?
    for state in fsm.states:
      if not state.action:
        continue
      callers = c_files.find_callers(state.action)
      if not callers:
        continue
      for other_state in fsm.states:
        if other_state.action in callers:
          other_state.add_out_edge(Edge(state, None, 'dotted'))

  def add_fsm_alloc(fsm, c_files):

    allocating_funcs = []
    for c_file in c_files:
      allocating_funcs.extend(c_file.fsm_allocators.get(fsm.struct_name, []))

    starting_state = None
    if fsm.states:
      # assume the first state starts
      starting_state = fsm.states[0]

    additional_states = []
    for func_name in allocating_funcs:
      fsm.add_special_state(additional_states, func_name, None, starting_state)

    fsm.states.extend(additional_states)

  def add_cross_fsm_links(fsm, fsms, c_files, fsm_meta):
    for state in fsm.states:
      if not state.action:
        continue
      if state.kind == KIND_FSM:
        continue
      callers = c_files.find_callers(state.action)

      if state.kind == KIND_FUNC:
        callers.append(state.action)

      if not callers:
        continue

      for caller in callers:
        for calling_fsm in fsms:
          if calling_fsm is fsm:
            continue
          calling_state = calling_fsm.find_state_by_action(caller)
          if not calling_state:
            continue
          if calling_state.kind == KIND_FSM:
            continue

          label = None
          if state.kind == KIND_STATE:
            label=fsm.struct_name + ': ' + state.short_name
          edge_action = caller
          if calling_state.action == edge_action:
            edge_action = None
          calling_fsm.add_special_state(calling_fsm.states, fsm.dot_name,
            calling_state, kind=KIND_FSM, edge_action=edge_action, label=' '.join(fsm.all_names()))

          label = None
          if calling_state.kind == KIND_STATE:
            label=calling_fsm.struct_name + ': ' + calling_state.short_name
          edge_action = caller
          if state.action == edge_action:
            edge_action = None
          fsm.add_special_state(fsm.states, calling_fsm.dot_name, None,
            state, kind=KIND_FSM, edge_action=edge_action,
            label=label)

          # meta overview
          meta_called_fsm = fsm_meta.have_state(fsm.dot_name, KIND_FSM)
          meta_calling_fsm = fsm_meta.have_state(calling_fsm.dot_name, KIND_FSM)
          meta_calling_fsm.add_out_edge(Edge(meta_called_fsm))


  def have_state(fsm, name, kind=KIND_STATE, color=None):
    state = fsm.find_state_by_name(name)
    if not state:
      state = State()
      state.name = name
      state.short_name = name
      state.kind = kind
      state.color = color
      fsm.states.append(state)
    return state

  def to_dot(fsm):
    out = ['digraph G {', 'rankdir=LR;']

    for state in fsm.states:
      out.append('%s [label="%s"%s%s]' % (state.short_name, state.get_label(),
                  state.shape_str(), state.color_str()))

    for state in fsm.states:
      for out_edge in state.out_edges:
        attrs = []
        labels = []
        if out_edge.events:
          labels.extend(out_edge.event_labels())
        if out_edge.actions:
          labels.extend(out_edge.action_labels())
        if labels:
          label = r'\n'.join(labels)
        else:
          label = '-'
        attrs.append('label="%s"' % label)
        if out_edge.style:
          attrs.append('style=%s'% out_edge.style)
        if out_edge.color:
          attrs.append('color=%s'% out_edge.color)
        if out_edge.arrow_head:
          attrs.append('arrowhead=%s'% out_edge.arrow_head)
        attrs_str = ''
        if attrs:
          attrs_str = ' [%s]' % (','.join(attrs))
        out.append('%s->%s%s' % (state.short_name, out_edge.to_state.short_name, attrs_str))

    out.append('}\n')

    return '\n'.join(out)

  def all_names(fsm):
    n = []
    if fsm.from_file:
      n.append(os.path.basename(fsm.from_file.path))
    if fsm.struct_name:
      n.append(fsm.struct_name)
    if fsm.string_name:
      n.append(fsm.string_name)
    return n

  def all_names_sanitized(fsm, sep='_'):
    n = sep.join(fsm.all_names())
    n = re_insane_dot_name_chars.sub('_', n)
    return n

  def write_dot_file(fsm):
    dot_path = '%s.dot' % ('_'.join(fsm.all_names()))
    f = open(dot_path, 'w')
    f.write(fsm.to_dot())
    f.close()
    print(dot_path)


re_fsm = re.compile(r'struct osmo_fsm ([a-z_][a-z_0-9]*) =')
re_fsm_string_name = re.compile(r'\bname = "([^"]*)"')
re_fsm_states_struct_name = re.compile(r'\bstates = ([a-z_][a-z_0-9]*)\W*,')
re_fsm_states = re.compile(r'struct osmo_fsm_state ([a-z_][a-z_0-9]*)\[\] =')
re_func = re.compile(r'(\b[a-z_][a-z_0-9]*\b)\([^)]*\)\W*^{', re.MULTILINE)
re_state_trigger = re.compile(r'osmo_fsm_inst_state_chg\([^,]+,\W*([A-Z_][A-Z_0-9]*)\W*,', re.M)
re_fsm_alloc = re.compile(r'osmo_fsm_inst_alloc[_child]*\(\W*&([a-z_][a-z_0-9]*),', re.M)
re_fsm_event_dispatch = re.compile(r'osmo_fsm_inst_dispatch\(\W*[^,]+,\W*([A-Z_][A-Z_0-9]*)\W*,', re.M)
re_comment_multiline = re.compile(r'/\*.*?\*/', re.M | re.S)
re_comment_single_line = re.compile(r'//.*$', re.M | re.S)
re_break = re.compile(r'^\W*\bbreak;', re.M)

class CFile():
  def __init__(c_file, path):
    c_file.path = path
    c_file.src = open(path).read()
    c_file.funcs = {}
    c_file.fsm_allocators = listdict()

  def __repr__(c_file):
    return str(c_file)

  def __str__(c_file):
    return 'CFile(%r)' % c_file.path

  def extract_block(c_file, brace_open, brace_close, start):
    pos = 0
    try:
      src = c_file.src
      block_start = src.find(brace_open, start)

      pos = block_start
      level = 1
      while level > 0:
        pos += 1
        if src[pos] == brace_open:
          level += 1
        elif src[pos] == brace_close:
          level -= 1

      return src[block_start+1:pos]
    except:
      print("Error while trying to extract a code block from %r char pos %d" % (c_file.path, pos))
      print("Block start at char pos %d" % block_start)
      try:
        print(src[block_start - 20 : block_start + 20])
        print('...')
        print(src[pos - 20 : pos + 20])
      except:
        pass
      return ''


  def find_fsms(c_file):
    fsms = []
    for m in re_fsm.finditer(c_file.src):
      struct_name = m.group(1)
      struct_def = c_file.extract_block('{', '}', m.start())
      string_name = (re_fsm_string_name.findall(struct_def) or [None])[0]
      states_struct_name = re_fsm_states_struct_name.findall(struct_def)[0]
      fsm = Fsm(struct_name, string_name, states_struct_name, c_file)
      fsms.append(fsm)
    return fsms

  def find_fsm_states(c_file, fsms):
    for m in re_fsm_states.finditer(c_file.src):
      states_struct_name = m.group(1)
      for fsm in fsms:
        if states_struct_name == fsm.states_struct_name:
          fsm.parse_states(c_file.extract_block('{', '}', m.start()), c_file)

  def parse_functions(c_file):
    funcs = {}
    for m in re_func.finditer(c_file.src):
      name = m.group(1)
      func_src = c_file.extract_block('{', '}', m.start())
      func_src = ''.join(re_comment_multiline.split(func_src))
      func_src = ''.join(re_comment_single_line.split(func_src))
      funcs[name] = func_src
    c_file.funcs = funcs
    c_file.find_fsm_allocators()

  def find_callers(c_file, func_name):
    func_call = func_name + '('
    callers = []
    for func_name, src in c_file.funcs.items():
      if src.find(func_call) >= 0:
        callers.append(func_name)
    return callers

  def find_fsm_allocators(c_file):
    c_file.fsm_allocators = listdict()
    for func_name, src in c_file.funcs.items():
      for m in re_fsm_alloc.finditer(src):
        fsm_struct_name = m.group(1)
        c_file.fsm_allocators.add(fsm_struct_name, func_name)

  def find_state_transitions(c_file, event_names):
    TO_STATE = 'TO_STATE'
    IF_EVENT = 'IF_EVENT'
    CASE_EVENT = 'CASE_EVENT'
    BREAK = 'BREAK'
    func_to_state_transitions = listdict()

    for func_name, src in c_file.funcs.items():
      found_tokens = []

      for m in re_state_trigger.finditer(src):
        to_state = m.group(1)
        found_tokens.append((m.start(), TO_STATE, to_state))

      for event in event_names:
        re_event = re.compile(r'\bif\w*\(.*\b(' + event + r')\b')
        for m in re_event.finditer(src):
          event = m.group(1)
          found_tokens.append((m.start(), IF_EVENT, event))

        re_event = re.compile(r'^\W*case\W\W*\b(' + event + r'):', re.M)
        for m in re_event.finditer(src):
          event = m.group(1)
          found_tokens.append((m.start(), CASE_EVENT, event))

      for m in re_break.finditer(src):
        found_tokens.append((m.start(), BREAK, 'break'))

      found_tokens = sorted(found_tokens)

      last_events = []
      saw_break = True
      for start, kind, name in found_tokens:
        if kind == IF_EVENT:
          last_events = [name]
          saw_break = True
        elif kind == CASE_EVENT:
          if saw_break:
            last_events = []
            saw_break = False
          last_events.append(name)
        elif kind == BREAK:
          saw_break = True
        elif kind == TO_STATE:
          for event in (last_events or [None]):
            func_to_state_transitions.add(func_name, (name, event))

    return func_to_state_transitions


  def find_event_sources(c_file, event_names):
    c_file.event_sources = listdict()
    for func_name, src in c_file.funcs.items():
      for m in re_fsm_event_dispatch.finditer(src):
        event_name = m.group(1)
        c_file.event_sources.add(event_name, func_name)

class CFiles(list):

  def find_callers(c_files, func_name):
    callers = []
    for c_file in c_files:
      callers.extend(c_file.find_callers(func_name))
    return callers

  def find_func_to_state_transitions(c_files):
    func_to_state_transitions = listdict()
    for c_file in c_files:
      func_to_state_transitions.update( c_file.find_state_transitions(fsm.event_names) )
    return func_to_state_transitions

  def find_event_sources(c_files, event_names):
    event_sources = listdict()
    for c_file in c_files:
      for event, sources in c_file.event_sources.items():
        if event in event_names:
          event_sources.extend(event, sources)
    return event_sources

c_files = CFiles()
paths_seen = set()
for path in sys.argv[1:]:
  if path in paths_seen:
    continue
  paths_seen.add(path)
  c_file = CFile(path)
  c_files.append(c_file)

for c_file in c_files:
  c_file.parse_functions()

fsms = []
for c_file in c_files:
  fsms.extend(c_file.find_fsms())

for fsm1 in fsms:
  for fsm2 in fsms:
    if fsm1 is fsm2:
      continue
    if fsm1.states_struct_name == fsm2.states_struct_name:
      print('ERROR: two distinct FSMs share the same states-struct name: %r and %r both use %r'
            % (fsm1, fsm2, fsm1.states_struct_name))

for c_file in c_files:
  c_file.find_fsm_states(fsms)
  c_file.find_event_sources(fsms)

for fsm in fsms:
  fsm.find_event_edges(c_files)
  fsm.add_fsm_alloc(c_files)

fsm_meta = Fsm("meta", None, "meta")
for fsm in fsms:
  fsm.add_cross_fsm_links(fsms, c_files, fsm_meta)

for fsm in fsms:
  fsm.make_events_short_names()

for fsm in fsms:
  fsm.write_dot_file()

fsm_meta.write_dot_file()


# vim: tabstop=2 shiftwidth=2 expandtab
