SUBDIRS = protocol

BUILT_SOURCES = gsm0503.h

osmogsm_HEADERS = \
	a5.h \
	abis_nm.h \
	apn.h \
	bts_features.h \
	cbsp.h \
	comp128.h \
	comp128v23.h \
	bitvec_gsm.h \
	gan.h \
	gsm0341.h \
	gsm0411_smc.h \
	gsm0411_smr.h \
	gsm0411_utils.h \
	gsm0480.h \
	gsm0502.h \
	gsm0503.h \
	bsslap.h \
	bssmap_le.h \
	gad.h \
	gsm0808.h \
	gsm0808_lcs.h \
	gsm29205.h \
	gsm0808_utils.h \
	gsm23003.h \
	gsm23236.h \
	gsm29118.h \
	gsm48.h \
	gsm48_arfcn_range_encode.h \
	gsm48_ie.h \
	gsm48_rest_octets.h \
	gsm_utils.h \
	gsup.h \
	gsup_sms.h \
	i460_mux.h \
	ipa.h \
	iuup.h \
	lapd_core.h \
	lapdm.h \
	meas_rep.h \
	mncc.h \
	prim.h \
	l1sap.h \
	oap.h \
	oap_client.h \
	rsl.h \
	rxlev_stat.h \
	sysinfo.h \
	tlv.h \
	$(NULL)

osmogsmdir = $(includedir)/osmocom/gsm

noinst_HEADERS = \
	kasumi.h \
	gea.h \
	$(NULL)

gsm0503.h: $(top_srcdir)/utils/conv_gen.py $(top_srcdir)/utils/conv_codes_gsm.py
	$(AM_V_GEN)python3 $(top_srcdir)/utils/conv_gen.py gen_header gsm \
		--target-path $(builddir)/

CLEANFILES = gsm0503.h
