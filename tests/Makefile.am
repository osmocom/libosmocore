AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_builddir)
AM_CFLAGS = -Wall $(TALLOC_CFLAGS) $(PTHREAD_CFLAGS)
AM_LDFLAGS = -no-install
LDADD = $(top_builddir)/src/core/libosmocore.la $(TALLOC_LIBS) $(PTHREAD_LIBS)

if ENABLE_SERCOM_STUB
noinst_LIBRARIES = libsercomstub.a
LDADD += $(top_builddir)/tests/libsercomstub.a
endif

check_PROGRAMS = timer/timer_test sms/sms_test ussd/ussd_test		\
                 bits/bitrev_test a5/a5_test		                \
                 conv/conv_test auth/milenage_test lapd/lapd_test	\
                 gsm0808/gsm0808_test gsm0408/gsm0408_test		\
		 gprs/gprs_test	kasumi/kasumi_test gea/gea_test		\
		 logging/logging_test codec/codec_test			\
		 loggingrb/loggingrb_test strrb/strrb_test              \
		 comp128/comp128_test                         		\
		 bitvec/bitvec_test msgb/msgb_test bits/bitcomp_test	\
		 bits/bitfield_test					\
		 tlv/tlv_test gsup/gsup_test oap/oap_test		\
		 write_queue/wqueue_test socket/socket_test		\
		 coding/coding_test conv/conv_gsm0503_test		\
		 abis/abis_test endian/endian_test sercomm/sercomm_test	\
		 prbs/prbs_test gsm23003/gsm23003_test 			\
		 gsm23236/gsm23236_test                                 \
		 codec/codec_ecu_fr_test timer/clk_override_test	\
		 oap/oap_client_test gsm29205/gsm29205_test		\
		 logging/logging_vty_test				\
		 vty/vty_transcript_test				\
		 tdef/tdef_test tdef/tdef_vty_config_root_test		\
		 tdef/tdef_vty_config_subnode_test			\
		 tdef/tdef_vty_dynamic_test				\
		 sockaddr_str/sockaddr_str_test				\
		 use_count/use_count_test				\
		 context/context_test					\
                 gsm0502/gsm0502_test					\
                 dtx/dtx_gsm0503_test					\
                 i460_mux/i460_mux_test					\
		 bitgen/bitgen_test					\
		 gad/gad_test						\
		 bsslap/bsslap_test					\
		 bssmap_le/bssmap_le_test				\
		 it_q/it_q_test						\
		 time_cc/time_cc_test					\
		 gsm48/rest_octets_test					\
		 base64/base64_test					\
		 iuup/iuup_test						\
		 smscb/smscb_test                                       \
		 smscb/gsm0341_test                                     \
		 smscb/cbsp_test                                        \
		 $(NULL)

if ENABLE_MSGFILE
check_PROGRAMS += msgfile/msgfile_test
endif

if ENABLE_PCSC
check_PROGRAMS += sim/sim_test
endif

if ENABLE_UTILITIES
check_PROGRAMS += utils/utils_test
endif

if ENABLE_VTY
check_PROGRAMS += vty/vty_test
endif

if ENABLE_CTRL
check_PROGRAMS += \
	ctrl/ctrl_test \
	fsm/fsm_test \
	fsm/fsm_dealloc_test \
	$(NULL)
endif

if !EMBEDDED
check_PROGRAMS += \
	stats/stats_test \
	stats/stats_vty_test \
	exec/exec_test
endif

if ENABLE_GB
check_PROGRAMS += gb/bssgp_fc_test gb/gprs_bssgp_test gb/gprs_bssgp_rim_test gb/gprs_ns_test gb/gprs_ns2_test fr/fr_test
endif

base64_base64_test_SOURCES = base64/base64_test.c

utils_utils_test_SOURCES = utils/utils_test.c
utils_utils_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

stats_stats_test_SOURCES = stats/stats_test.c
stats_stats_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la
stats_stats_test_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/core

stats_stats_vty_test_SOURCES = stats/stats_vty_test.c
stats_stats_vty_test_LDADD = $(LDADD) $(top_builddir)/src/vty/libosmovty.la

a5_a5_test_SOURCES = a5/a5_test.c
a5_a5_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libgsmint.la

kasumi_kasumi_test_SOURCES = kasumi/kasumi_test.c
kasumi_kasumi_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libgsmint.la

comp128_comp128_test_SOURCES = comp128/comp128_test.c
comp128_comp128_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

auth_milenage_test_SOURCES = auth/milenage_test.c
auth_milenage_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

abis_abis_test_SOURCES = abis/abis_test.c
abis_abis_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

ctrl_ctrl_test_SOURCES = ctrl/ctrl_test.c
ctrl_ctrl_test_LDADD = $(LDADD) \
	$(top_builddir)/src/ctrl/libosmoctrl.la \
	$(top_builddir)/src/gsm/libosmogsm.la \
	$(top_builddir)/src/vty/libosmovty.la

gea_gea_test_SOURCES = gea/gea_test.c
gea_gea_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

bits_bitrev_test_SOURCES = bits/bitrev_test.c

bitvec_bitvec_test_SOURCES = bitvec/bitvec_test.c

bits_bitcomp_test_SOURCES = bits/bitcomp_test.c

bits_bitfield_test_SOURCES = bits/bitfield_test.c

conv_conv_test_SOURCES = conv/conv_test.c conv/conv.c
conv_conv_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libgsmint.la

gsm0502_gsm0502_test_SOURCES = gsm0502/gsm0502_test.c
gsm0502_gsm0502_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

dtx_dtx_gsm0503_test_SOURCES = dtx/dtx_gsm0503_test.c
dtx_dtx_gsm0503_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la \
			     $(top_builddir)/src/coding/libosmocoding.la

conv_conv_gsm0503_test_SOURCES = conv/conv_gsm0503_test.c conv/conv.c conv/gsm0503_test_vectors.c
conv_conv_gsm0503_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libgsmint.la
conv_conv_gsm0503_test_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/tests/conv

gsm0808_gsm0808_test_SOURCES = gsm0808/gsm0808_test.c
gsm0808_gsm0808_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

gsm29205_gsm29205_test_SOURCES = gsm29205/gsm29205_test.c
gsm29205_gsm29205_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

gsm0408_gsm0408_test_SOURCES = gsm0408/gsm0408_test.c
gsm0408_gsm0408_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

gsm48_rest_octets_test_SOURCES = gsm48/rest_octets_test.c
gsm48_rest_octets_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

gprs_gprs_test_SOURCES = gprs/gprs_test.c
gprs_gprs_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

lapd_lapd_test_SOURCES = lapd/lapd_test.c
lapd_lapd_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la $(top_builddir)/src/isdn/libosmoisdn.la

msgb_msgb_test_SOURCES = msgb/msgb_test.c

msgfile_msgfile_test_SOURCES = msgfile/msgfile_test.c

smscb_smscb_test_SOURCES = smscb/smscb_test.c
smscb_smscb_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

smscb_gsm0341_test_SOURCES = smscb/gsm0341_test.c
smscb_gsm0341_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

smscb_cbsp_test_SOURCES = smscb/cbsp_test.c
smscb_cbsp_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

sms_sms_test_SOURCES = sms/sms_test.c
sms_sms_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

timer_timer_test_SOURCES = timer/timer_test.c

timer_clk_override_test_SOURCES = timer/clk_override_test.c

ussd_ussd_test_SOURCES = ussd/ussd_test.c
ussd_ussd_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

gb_bssgp_fc_test_SOURCES = gb/bssgp_fc_test.c
gb_bssgp_fc_test_LDADD = $(LDADD) $(top_builddir)/src/gb/libosmogb.la \
			 $(top_builddir)/src/vty/libosmovty.la \
			 $(top_builddir)/src/gsm/libosmogsm.la

gb_gprs_bssgp_test_SOURCES = gb/gprs_bssgp_test.c
gb_gprs_bssgp_test_LDADD = $(LDADD) $(top_builddir)/src/gb/libosmogb.la $(LIBRARY_DLSYM) \
			   $(top_builddir)/src/vty/libosmovty.la \
			   $(top_builddir)/src/gsm/libosmogsm.la \
			   $(top_builddir)/src/gb/libosmogb.la

gb_gprs_bssgp_rim_test_SOURCES = gb/gprs_bssgp_rim_test.c
gb_gprs_bssgp_rim_test_LDADD = $(LDADD) $(top_builddir)/src/gb/libosmogb.la $(LIBRARY_DLSYM) \
			       $(top_builddir)/src/gb/libosmogb.la

gb_gprs_ns_test_SOURCES = gb/gprs_ns_test.c
gb_gprs_ns_test_LDADD = $(LDADD) $(top_builddir)/src/gb/libosmogb.la $(LIBRARY_DLSYM) \
			$(top_builddir)/src/vty/libosmovty.la \
			$(top_builddir)/src/gsm/libosmogsm.la

gb_gprs_ns2_test_SOURCES = gb/gprs_ns2_test.c
gb_gprs_ns2_test_LDADD = $(LDADD) $(LIBRARY_DLSYM) \
			$(top_builddir)/src/vty/libosmovty.la \
			$(top_builddir)/src/gsm/libosmogsm.la \
			$(top_builddir)/src/core/libosmocore.la \
			$(top_builddir)/src/gb/libosmogb-test.la

logging_logging_test_SOURCES = logging/logging_test.c

logging_logging_vty_test_SOURCES = logging/logging_vty_test.c
logging_logging_vty_test_LDADD = $(LDADD) $(top_builddir)/src/vty/libosmovty.la

vty_vty_transcript_test_SOURCES = vty/vty_transcript_test.c
vty_vty_transcript_test_LDADD = $(LDADD) $(top_builddir)/src/vty/libosmovty.la

fr_fr_test_SOURCES = fr/fr_test.c
fr_fr_test_LDADD = $(LDADD) $(top_builddir)/src/gb/libosmogb.la $(LIBRARY_DLSYM) \
		   $(top_builddir)/src/vty/libosmovty.la \
		   $(top_builddir)/src/gsm/libosmogsm.la

codec_codec_test_SOURCES = codec/codec_test.c
codec_codec_test_LDADD = $(LDADD) $(top_builddir)/src/codec/libosmocodec.la

codec_codec_ecu_fr_test_SOURCES = codec/codec_ecu_fr_test.c
codec_codec_ecu_fr_test_LDADD = $(LDADD) $(top_builddir)/src/codec/libosmocodec.la

loggingrb_loggingrb_test_SOURCES = loggingrb/loggingrb_test.c
loggingrb_loggingrb_test_LDADD = $(LDADD)

strrb_strrb_test_SOURCES = strrb/strrb_test.c

vty_vty_test_SOURCES = vty/vty_test.c
vty_vty_test_LDADD = $(LDADD) $(top_builddir)/src/vty/libosmovty.la

sim_sim_test_SOURCES = sim/sim_test.c
sim_sim_test_LDADD = $(LDADD) $(top_builddir)/src/sim/libosmosim.la \
		     $(top_builddir)/src/gsm/libosmogsm.la

tlv_tlv_test_SOURCES = tlv/tlv_test.c
tlv_tlv_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

gsup_gsup_test_SOURCES = gsup/gsup_test.c
gsup_gsup_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

oap_oap_test_SOURCES = oap/oap_test.c
oap_oap_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

oap_oap_client_test_SOURCES = oap/oap_client_test.c
oap_oap_client_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

fsm_fsm_test_SOURCES = fsm/fsm_test.c
fsm_fsm_test_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/ctrl/libosmoctrl.la \
	$(top_builddir)/src/gsm/libosmogsm.la \
	$(top_builddir)/src/vty/libosmovty.la

fsm_fsm_dealloc_test_SOURCES = fsm/fsm_dealloc_test.c
fsm_fsm_dealloc_test_LDADD = $(LDADD)

write_queue_wqueue_test_SOURCES = write_queue/wqueue_test.c

socket_socket_test_SOURCES = socket/socket_test.c

coding_coding_test_SOURCES = coding/coding_test.c
coding_coding_test_LDADD = $(LDADD) \
  $(top_builddir)/src/gsm/libosmogsm.la \
  $(top_builddir)/src/codec/libosmocodec.la \
  $(top_builddir)/src/coding/libosmocoding.la

endian_endian_test_SOURCES = endian/endian_test.c

sercomm_sercomm_test_SOURCES = sercomm/sercomm_test.c

prbs_prbs_test_SOURCES = prbs/prbs_test.c

gsm23003_gsm23003_test_SOURCES = gsm23003/gsm23003_test.c
gsm23003_gsm23003_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

gsm23236_gsm23236_test_SOURCES = gsm23236/gsm23236_test.c
gsm23236_gsm23236_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

tdef_tdef_test_SOURCES = tdef/tdef_test.c
tdef_tdef_test_LDADD = $(LDADD)

tdef_tdef_vty_config_root_test_SOURCES = tdef/tdef_vty_config_root_test.c
tdef_tdef_vty_config_root_test_LDADD = $(LDADD) $(top_builddir)/src/vty/libosmovty.la

tdef_tdef_vty_config_subnode_test_SOURCES = tdef/tdef_vty_config_subnode_test.c
tdef_tdef_vty_config_subnode_test_LDADD = $(LDADD) $(top_builddir)/src/vty/libosmovty.la

tdef_tdef_vty_dynamic_test_SOURCES = tdef/tdef_vty_dynamic_test.c
tdef_tdef_vty_dynamic_test_LDADD = $(LDADD) $(top_builddir)/src/vty/libosmovty.la

sockaddr_str_sockaddr_str_test_SOURCES = sockaddr_str/sockaddr_str_test.c
sockaddr_str_sockaddr_str_test_LDADD = $(LDADD)

use_count_use_count_test_SOURCES = use_count/use_count_test.c
use_count_use_count_test_LDADD = $(LDADD)

context_context_test_SOURCES = context/context_test.c
context_context_test_LDADD = $(LDADD)

exec_exec_test_SOURCES = exec/exec_test.c
exec_exec_test_LDADD = $(LDADD)

i460_mux_i460_mux_test_SOURCES = i460_mux/i460_mux_test.c
i460_mux_i460_mux_test_LDADD = $(LDADD) $(top_builddir)/src/isdn/libosmoisdn.la

bitgen_bitgen_test_SOURCES = bitgen/bitgen_test.c
bitgen_bitgen_test_LDADD = $(LDADD)

gad_gad_test_SOURCES = gad/gad_test.c
gad_gad_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

bsslap_bsslap_test_SOURCES = bsslap/bsslap_test.c
bsslap_bsslap_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

bssmap_le_bssmap_le_test_SOURCES = bssmap_le/bssmap_le_test.c
bssmap_le_bssmap_le_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

it_q_it_q_test_SOURCES = it_q/it_q_test.c
it_q_it_q_test_LDADD = $(LDADD)

time_cc_time_cc_test_SOURCES = time_cc/time_cc_test.c
time_cc_time_cc_test_LDADD = $(LDADD)

iuup_iuup_test_SOURCES = iuup/iuup_test.c
iuup_iuup_test_LDADD = $(LDADD) $(top_builddir)/src/gsm/libosmogsm.la

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = testsuite.at $(srcdir)/package.m4 $(TESTSUITE)		\
             timer/timer_test.ok sms/sms_test.ok ussd/ussd_test.ok	\
             bits/bitrev_test.ok a5/a5_test.ok				\
             conv/conv_test.ok auth/milenage_test.ok ctrl/ctrl_test.ok	\
             lapd/lapd_test.ok						\
             gsm0408/gsm0408_test.ok gsm0408/gsm0408_test.err		\
             gsm0808/gsm0808_test.ok gb/bssgp_fc_tests.err		\
             gb/bssgp_fc_tests.ok gb/bssgp_fc_tests.sh			\
             gb/gprs_bssgp_test.ok gb/gprs_ns_test.ok gea/gea_test.ok	\
	     gb/gprs_bssgp_rim_test.ok					\
             gb/gprs_ns2_vty.vty gb/osmoappdesc.py gb/osmo-ns-dummy.cfg \
             gb/gprs_ns2_test.ok					\
             gprs/gprs_test.ok kasumi/kasumi_test.ok			\
             msgfile/msgfile_test.ok msgfile/msgconfig.cfg		\
             logging/logging_test.ok logging/logging_test.err		\
             logging/logging_vty_test.vty				\
             fr/fr_test.ok loggingrb/logging_test.ok			\
             loggingrb/logging_test.err	strrb/strrb_test.ok		\
             codec/codec_test.ok \
             codec/codec_ecu_fr_test.ok \
	     vty/vty_test.ok vty/vty_test.err \
	     vty/fail_not_de-indented.cfg \
	     vty/fail_tabs_and_spaces.cfg \
	     vty/fail_too_much_indent.cfg \
	     vty/fail_cmd_ret_warning.cfg \
	     vty/ok.cfg \
	     vty/ok_empty_parent.cfg \
	     vty/ok_ignore_blank.cfg \
	     vty/ok_ignore_comment.cfg \
	     vty/ok_indented_root.cfg \
	     vty/ok_more_spaces.cfg \
	     vty/ok_tabs_and_spaces.cfg \
	     vty/ok_tabs.cfg \
	     vty/ok_deprecated_logging.cfg \
	     comp128/comp128_test.ok bits/bitfield_test.ok		\
	     utils/utils_test.ok utils/utils_test.err 			\
	     stats/stats_test.ok stats/stats_test.err			\
	     stats/stats_vty_test.vty					\
	     bitvec/bitvec_test.ok msgb/msgb_test.ok bits/bitcomp_test.ok \
	     sim/sim_test.ok tlv/tlv_test.ok abis/abis_test.ok		\
	     gsup/gsup_test.ok gsup/gsup_test.err			\
	     oap/oap_test.ok fsm/fsm_test.ok fsm/fsm_test.err		\
	     fsm/fsm_dealloc_test.err					\
	     write_queue/wqueue_test.ok socket/socket_test.ok		\
	     socket/socket_test.err coding/coding_test.ok		\
	     osmo-auc-gen/osmo-auc-gen_test.sh				\
	     osmo-auc-gen/osmo-auc-gen_test.ok				\
	     osmo-auc-gen/osmo-auc-gen_test.err				\
	     conv/conv_gsm0503_test.ok endian/endian_test.ok 		\
	     sercomm/sercomm_test.ok prbs/prbs_test.ok			\
	     gsm29205/gsm29205_test.ok gsm23003/gsm23003_test.ok        \
	     gsm23236/gsm23236_test.ok                                  \
	     timer/clk_override_test.ok					\
	     oap/oap_client_test.ok oap/oap_client_test.err		\
	     vty/vty_transcript_test.vty				\
	     tdef/tdef_test.ok \
	     tdef/tdef_test_range_64bit.ok \
	     tdef/tdef_vty_config_root_test.vty	\
	     tdef/tdef_vty_config_subnode_test.vty \
	     tdef/tdef_vty_dynamic_test.vty \
	     sockaddr_str/sockaddr_str_test.ok \
	     use_count/use_count_test.ok use_count/use_count_test.err \
	     context/context_test.ok \
	     gsm0502/gsm0502_test.ok \
	     dtx/dtx_gsm0503_test.ok \
	     exec/exec_test.ok exec/exec_test.err \
	     i460_mux/i460_mux_test.ok \
	     bitgen/bitgen_test.ok \
	     gad/gad_test.ok \
	     bsslap/bsslap_test.ok \
	     bssmap_le/bssmap_le_test.ok \
	     it_q/it_q_test.ok \
	     time_cc/time_cc_test.ok \
	     gsm48/rest_octets_test.ok \
	     base64/base64_test.ok \
	     iuup/iuup_test.ok \
	     smscb/smscb_test.ok \
	     smscb/gsm0341_test.ok \
	     smscb/cbsp_test.ok \
	     $(NULL)

if ENABLE_LIBSCTP
if ENABLE_SCTP_TESTS
EXTRA_DIST += socket/socket_sctp_test.ok socket/socket_sctp_test.err
check_PROGRAMS += socket/socket_sctp_test
socket_socket_sctp_test_SOURCES = socket/socket_sctp_test.c
endif
endif

DISTCLEANFILES = atconfig atlocal conv/gsm0503_test_vectors.c
BUILT_SOURCES = conv/gsm0503_test_vectors.c
noinst_HEADERS = conv/conv.h

TESTSUITE = $(srcdir)/testsuite

update_exp: $(check_PROGRAMS)
	a5/a5_test \
		>$(srcdir)/a5/a5_test.ok
	abis/abis_test \
		>$(srcdir)/abis/abis_test.ok
if ENABLE_CTRL
	ctrl/ctrl_test \
		>$(srcdir)/ctrl/ctrl_test.ok
endif
	kasumi/kasumi_test \
		>$(srcdir)/kasumi/kasumi_test.ok
	bits/bitrev_test \
		>$(srcdir)/bits/bitrev_test.ok
	bitvec/bitvec_test \
		>$(srcdir)/bitvec/bitvec_test.ok
	bits/bitcomp_test \
		>$(srcdir)/bits/bitcomp_test.ok
	bits/bitfield_test \
		>$(srcdir)/bits/bitfield_test.ok
	conv/conv_test \
		>$(srcdir)/conv/conv_test.ok
	conv/conv_gsm0503_test \
		>$(srcdir)/conv/conv_gsm0503_test.ok
	coding/coding_test \
		>$(srcdir)/coding/coding_test.ok
	msgb/msgb_test \
		>$(srcdir)/msgb/msgb_test.ok
	gea/gea_test \
		>$(srcdir)/gea/gea_test.ok
if ENABLE_MSGFILE
	cp $(srcdir)/msgfile/msgconfig.cfg .
	msgfile/msgfile_test \
		>$(srcdir)/msgfile/msgfile_test.ok
endif
	sms/sms_test \
		>$(srcdir)/sms/sms_test.ok
	smscb/smscb_test \
		>$(srcdir)/smscb/smscb_test.ok
	smscb/gsm0341_test \
		>$(srcdir)/smscb/gsm0341_test.ok
	smscb/cbsp_test \
		>$(srcdir)/smscb/cbsp_test.ok
	ussd/ussd_test \
		>$(srcdir)/ussd/ussd_test.ok
	auth/milenage_test \
		>$(srcdir)/auth/milenage_test.ok
	comp128/comp128_test \
		>$(srcdir)/comp128/comp128_test.ok
	lapd/lapd_test \
		>$(srcdir)/lapd/lapd_test.ok
	gsm0502/gsm0502_test \
		>$(srcdir)/gsm0502/gsm0502_test.ok
	dtx/dtx_gsm0503_test \
		>$(srcdir)/dtx/dtx_gsm0503_test.ok
	gsm0808/gsm0808_test \
		>$(srcdir)/gsm0808/gsm0808_test.ok
	gsm29205/gsm29205_test \
		>$(srcdir)/gsm29205/gsm29205_test.ok
	gsm0408/gsm0408_test \
		2>$(srcdir)/gsm0408/gsm0408_test.err \
		1>$(srcdir)/gsm0408/gsm0408_test.ok
	gsm48/rest_octets_test \
		>$(srcdir)/gsm48/rest_octets_test.ok
	gprs/gprs_test \
		>$(srcdir)/gprs/gprs_test.ok
	logging/logging_test \
		>$(srcdir)/logging/logging_test.ok \
		2>$(srcdir)/logging/logging_test.err
	codec/codec_test \
		>$(srcdir)/codec/codec_test.ok
	codec/codec_ecu_fr_test \
		>$(srcdir)/codec/codec_ecu_fr_test.ok
if ENABLE_GB
	fr/fr_test \
		>$(srcdir)/fr/fr_test.ok
endif
	loggingrb/loggingrb_test \
		>$(srcdir)/loggingrb/logging_test.ok \
		2>$(srcdir)/loggingrb/logging_test.err
	strrb/strrb_test \
		>$(srcdir)/strrb/strrb_test.ok
if ENABLE_VTY
	cp $(srcdir)/vty/*.cfg .
	vty/vty_test \
		>$(srcdir)/vty/vty_test.ok \
		2>$(srcdir)/vty/vty_test.err
endif
if ENABLE_GB
	gb/gprs_bssgp_test \
		>$(srcdir)/gb/gprs_bssgp_test.ok
	gb/gprs_bssgp_rim_test \
		>$(srcdir)/gb/gprs_bssgp_rim_test.ok
	gb/gprs_ns_test \
		>$(srcdir)/gb/gprs_ns_test.ok
	gb/gprs_ns2_test \
		>$(srcdir)/gb/gprs_ns2_test.ok
endif
if ENABLE_UTILITIES
	utils/utils_test \
		>$(srcdir)/utils/utils_test.ok
endif
if !EMBEDDED
	stats/stats_test \
		>$(srcdir)/stats/stats_test.ok \
		2>$(srcdir)/stats/stats_test.err
endif
	write_queue/wqueue_test \
		>$(srcdir)/write_queue/wqueue_test.ok
if ENABLE_GB
	$(srcdir)/gb/bssgp_fc_tests.sh gb \
		>$(srcdir)/gb/bssgp_fc_tests.ok \
		2>$(srcdir)/gb/bssgp_fc_tests.err
endif
if ENABLE_PCSC
	sim/sim_test \
		>$(srcdir)/sim/sim_test.ok
endif
	timer/timer_test \
		>$(srcdir)/timer/timer_test.ok
	timer/clk_override_test \
		>$(srcdir)/timer/clk_override_test.ok
	tlv/tlv_test \
		>$(srcdir)/tlv/tlv_test.ok
	gsup/gsup_test \
		>$(srcdir)/gsup/gsup_test.ok \
		2>$(srcdir)/gsup/gsup_test.err
if ENABLE_CTRL
	fsm/fsm_test \
		>$(srcdir)/fsm/fsm_test.ok \
		2>$(srcdir)/fsm/fsm_test.err
	fsm/fsm_dealloc_test \
		2>$(srcdir)/fsm/fsm_dealloc_test.err
endif
	oap/oap_test \
		>$(srcdir)/oap/oap_test.ok
	oap/oap_client_test \
		>$(srcdir)/oap/oap_client_test.ok \
		2>$(srcdir)/oap/oap_client_test.err
	socket/socket_test \
		>$(srcdir)/socket/socket_test.ok \
		2>$(srcdir)/socket/socket_test.err
	socket/socket_sctp_test \
		>$(srcdir)/socket/socket_sctp_test.ok \
		2>$(srcdir)/socket/socket_sctp_test.err
	$(srcdir)/osmo-auc-gen/osmo-auc-gen_test.sh ../utils/osmo-auc-gen \
		>$(srcdir)/osmo-auc-gen/osmo-auc-gen_test.ok \
		2>$(srcdir)/osmo-auc-gen/osmo-auc-gen_test.err
	endian/endian_test \
		>$(srcdir)/endian/endian_test.ok
	sercomm/sercomm_test \
		>$(srcdir)/sercomm/sercomm_test.ok
	prbs/prbs_test \
		>$(srcdir)/prbs/prbs_test.ok
	gsm23003/gsm23003_test \
		>$(srcdir)/gsm23003/gsm23003_test.ok
	gsm23236/gsm23236_test \
		>$(srcdir)/gsm23236/gsm23236_test.ok
	tdef/tdef_test \
		>$(srcdir)/tdef/tdef_test.ok
	sockaddr_str/sockaddr_str_test \
		>$(srcdir)/sockaddr_str/sockaddr_str_test.ok
	use_count/use_count_test \
		>$(srcdir)/use_count/use_count_test.ok \
		2>$(srcdir)/use_count/use_count_test.err
	context/context_test \
		>$(srcdir)/context/context_test.ok
if !EMBEDDED
	exec/exec_test \
		>$(srcdir)/exec/exec_test.ok \
		2>$(srcdir)/exec/exec_test.err
endif
	i460_mux/i460_mux_test \
		>$(srcdir)/i460_mux/i460_mux_test.ok
	bitgen/bitgen_test \
		>$(srcdir)/bitgen/bitgen_test.ok
	gad/gad_test \
		>$(srcdir)/gad/gad_test.ok
	bsslap/bsslap_test \
		>$(srcdir)/bsslap/bsslap_test.ok
	bssmap_le/bssmap_le_test \
		>$(srcdir)/bssmap_le/bssmap_le_test.ok
	it_q/it_q_test \
		>$(srcdir)/it_q/it_q_test.ok
	time_cc/time_cc_test \
		>$(srcdir)/time_cc/time_cc_test.ok
	iuup/iuup_test \
		>$(srcdir)/iuup/iuup_test.ok

check-local: atconfig $(TESTSUITE)
	[ -e /proc/cpuinfo ] && cat /proc/cpuinfo
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) ext-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

conv/gsm0503_test_vectors.c: $(top_srcdir)/utils/conv_gen.py $(top_srcdir)/utils/conv_codes_gsm.py
	$(AM_V_GEN)python3 $(top_srcdir)/utils/conv_gen.py gen_vectors gsm \
		--target-path $(builddir)/conv

if ENABLE_EXT_TESTS
ext-tests:
# don't run vty and ctrl tests concurrently so that the ports don't conflict
	$(MAKE) vty-test
	$(MAKE) ctrl-test
else
ext-tests:
	echo "Not running python-based external tests (determined at configure-time)"
endif

# To update the VTY script from current application behavior,
# pass -u to osmo_verify_transcript_vty.py by doing:
#   make vty-test U=-u

vty-test-ns2:
	$(MAKE) -C $(top_builddir)/utils osmo-ns-dummy
	osmo_verify_transcript_vty.py -v \
		-p 42042 \
		-r "$(top_builddir)/utils/osmo-ns-dummy -p 42042" \
		$(U) $(srcdir)/gb/gprs_ns2*.vty
	osmotestvty.py -p $(abs_top_srcdir)/tests/gb -w $(abs_top_builddir)/tests/gb -v
	osmotestconfig.py -p $(abs_top_srcdir)/tests/gb -w $(abs_top_builddir)/tests/gb -v

vty-test-logging:
	osmo_verify_transcript_vty.py -v \
		-p 42042 \
		-r "$(top_builddir)/tests/logging/logging_vty_test" \
		$(U) $(srcdir)/logging/*.vty

vty-test-vty:
	osmo_verify_transcript_vty.py -v \
		-p 42042 \
		-r "$(top_builddir)/tests/vty/vty_transcript_test" \
		$(U) $(srcdir)/vty/*.vty

vty-test-tdef:
	osmo_verify_transcript_vty.py -v \
		-p 42042 \
		-r "$(top_builddir)/tests/tdef/tdef_vty_config_root_test" \
		$(U) $(srcdir)/tdef/tdef_vty_config_root_test.vty
	osmo_verify_transcript_vty.py -v \
		-p 42042 \
		-r "$(top_builddir)/tests/tdef/tdef_vty_config_subnode_test" \
		$(U) $(srcdir)/tdef/tdef_vty_config_subnode_test.vty
	osmo_verify_transcript_vty.py -v \
		-p 42042 \
		-r "$(top_builddir)/tests/tdef/tdef_vty_dynamic_test" \
		$(U) $(srcdir)/tdef/tdef_vty_dynamic_test.vty

vty-test-stats:
	osmo_verify_transcript_vty.py -v \
		-p 42042 \
		-r "$(top_builddir)/tests/stats/stats_vty_test" \
		$(U) $(srcdir)/stats/*.vty

# don't run vty tests concurrently so that the ports don't conflict
vty-test:
	$(MAKE) vty-test-logging
	$(MAKE) vty-test-vty
	$(MAKE) vty-test-tdef
	$(MAKE) vty-test-ns2
	$(MAKE) vty-test-stats

ctrl-test:
	echo "No CTRL tests exist currently"
