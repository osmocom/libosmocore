osmocore_HEADERS = \
	application.h \
	backtrace.h \
	base64.h \
	bit16gen.h \
	bit32gen.h \
	bit64gen.h \
	bits.h \
	bitvec.h \
	bitcomp.h \
	byteswap.h \
	conv.h \
	counter.h \
	crc16.h \
	crc16gen.h \
	crc32gen.h \
	crc64gen.h \
	crc8gen.h \
	crcgen.h \
	endian.h \
	defs.h \
	exec.h \
	fsm.h \
	gsmtap.h \
	gsmtap_util.h \
	hash.h \
	hashtable.h \
	isdnhdlc.h \
	it_q.h \
	linuxlist.h \
	linuxrbtree.h \
	log2.h \
	logging.h \
	loggingrb.h \
	stats.h \
	macaddr.h \
	msgb.h \
	netdev.h \
	netns.h \
	panic.h \
	prbs.h \
	prim.h \
	process.h \
	rate_ctr.h \
	stat_item.h \
	stats_tcp.h \
	select.h \
	sercomm.h \
	signal.h \
	socket.h \
	statistics.h \
	strrb.h \
	talloc.h \
	tdef.h \
	thread.h \
	timer.h \
	timer_compat.h \
	tun.h \
	utils.h \
	write_queue.h \
	sockaddr_str.h \
	time_cc.h \
	use_count.h \
	$(NULL)

if ENABLE_PLUGIN
osmocore_HEADERS += plugin.h
endif

if ENABLE_MSGFILE
osmocore_HEADERS += msgfile.h
endif

if ENABLE_SERIAL
osmocore_HEADERS += serial.h
endif

if ENABLE_LIBMNL
osmocore_HEADERS += mnl.h
endif

osmocoredir = $(includedir)/osmocom/core

noinst_HEADERS = \
	logging_internal.h \
	$(NULL)

bit%gen.h: bitXXgen.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed -e's/XX/$*/g' $< > $@

crc%gen.h: crcXXgen.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed -e's/XX/$*/g' $< > $@
