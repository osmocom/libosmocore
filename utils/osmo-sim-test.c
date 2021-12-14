/* libosmosim test application - currently simply dumps a USIM */
/* (C) 2012-2020 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/sim/sim.h>
#include <osmocom/gsm/tlv.h>


/* FIXME: this needs to be moved to card_fs_uicc.c */

static uint8_t g_class = 0x00; /* UICC/USIM */
static const char *g_output_dir;

/* 11.1.1 */
static struct msgb *_select_file(struct osim_chan_hdl *st, uint8_t p1, uint8_t p2,
			const uint8_t *data, uint8_t data_len)
{
	struct msgb *msg;
	uint8_t *dst;

	msg = osim_new_apdumsg(g_class, 0xA4, p1, p2, data_len, 256);
	dst = msgb_put(msg, data_len);
	memcpy(dst, data, data_len);

	osim_transceive_apdu(st, msg);

	return msg;
}

/* 11.1.1 */
static struct msgb *select_adf(struct osim_chan_hdl *st, const uint8_t *adf, uint8_t adf_len)
{
	return _select_file(st, 0x04, 0x04, adf,adf_len);
}

/* 11.1.1 */
static struct msgb *select_file(struct osim_chan_hdl *st, uint16_t fid)
{
	uint16_t cfid = htons(fid);
	uint8_t p2 = 0x04;

	/* Classic SIM cards don't support 0x04 (Return FCP) */
	if (g_class == 0xA0)
		p2 = 0x00;

	return _select_file(st, 0x00, p2, (uint8_t *)&cfid, 2);
}

#if 0
/* 11.1.9 */
static int verify_pin(struct osim_chan_hdl *st, uint8_t pin_nr, char *pin)
{
	struct msgb *msg;
	char *pindst;

	if (strlen(pin) > 8)
		return -EINVAL;

	msg = osim_new_apdumsg(g_class, 0x20, 0x00, pin_nr, 8, 0);
	pindst = (char *) msgb_put(msg, 8);
	memset(pindst, 0xFF, 8);
	/* Do not copy the terminating \0 */
	memcpy(pindst, pin, strlen(pin));

	return osim_transceive_apdu(st, msg);
}
#endif

/* 11.1.5 */
static struct msgb *read_record_nr(struct osim_chan_hdl *st, uint8_t rec_nr, uint16_t rec_size)
{
	struct msgb *msg;

	msg = osim_new_apdumsg(g_class, 0xB2, rec_nr, 0x04, 0, rec_size);

	osim_transceive_apdu(st, msg);

	return msg;
}

/* 11.1.3 */
static struct msgb *read_binary(struct osim_chan_hdl *st, uint16_t offset, uint16_t len)
{
	struct msgb *msg;

	if (offset > 0x7fff || len > 256)
		return NULL;

	msg = osim_new_apdumsg(g_class, 0xB0, offset >> 8, offset & 0xff, 0, len & 0xff);

	osim_transceive_apdu(st, msg);

	return msg;
}

static int dump_fcp_template(struct tlv_parsed *tp)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tp->lv); i++) {
		if (TLVP_PRESENT(tp, i))
			printf("Tag 0x%02x (%s): %s\n", i,
				get_value_string(ts102221_fcp_vals, i),
				osmo_hexdump(TLVP_VAL(tp, i), TLVP_LEN(tp, i)));
	}

	return 0;
}

static int dump_fcp_template_msg(struct msgb *msg)
{
	struct tlv_parsed tp;
	int rc;

	rc = tlv_parse(&tp, &ts102221_fcp_tlv_def, msgb_apdu_de(msg)+2, msgb_apdu_le(msg)-2, 0, 0);
	if (rc < 0)
		return rc;

	return dump_fcp_template(&tp);
}

struct osim_fcp_fd_decoded {
	enum osim_file_type type;
	enum osim_ef_type ef_type;
	uint16_t rec_len;
	uint8_t num_rec;
};

static const enum osim_file_type iso2ftype[8] = {
	[0] = TYPE_EF,
	[1] = TYPE_EF_INT,
	[7] = TYPE_DF,
};

static const enum osim_ef_type iso2eftype[8] = {
	[1] = EF_TYPE_TRANSP,
	[2] = EF_TYPE_RECORD_FIXED,
	[6] = EF_TYPE_RECORD_CYCLIC,
};

static int osim_fcp_fd_decode(struct osim_fcp_fd_decoded *ofd, const uint8_t *fcp, int fcp_len)
{
	memset(ofd, 0, sizeof(*ofd));

	if (fcp_len != 2 && fcp_len != 5)
		return -EINVAL;

	ofd->type = iso2ftype[(fcp[0] >> 3) & 7];
	if (ofd->type != TYPE_DF)
		ofd->ef_type = iso2eftype[fcp[0] & 7];

	if (fcp[1] != 0x21)
		return -EINVAL;

	if (fcp_len >= 5) {
		ofd->rec_len = ntohs(*(uint16_t *)(fcp+2));
		ofd->num_rec = fcp[4];
	}

	return 0;
}

/* TS 51.011 Section 9.3 Type of File */
static const enum osim_file_type sim2ftype[8] = {
	[1] = TYPE_MF,
	[2] = TYPE_DF,
	[4] = TYPE_EF,
};

/* TS 51.011 Section 9.3 Structure of File */
static const enum osim_ef_type sim2eftype[8] = {
	[0] = EF_TYPE_TRANSP,
	[1] = EF_TYPE_RECORD_FIXED,
	[3] = EF_TYPE_RECORD_CYCLIC,
};

/* TS 51.011 Section 9.2.1 */
static int osim_fcp_fd_decode_sim(struct osim_fcp_fd_decoded *ofd, const uint8_t *fcp, int fcp_len)
{
	memset(ofd, 0, sizeof(*ofd));

	if (fcp_len < 14)
		return -EINVAL;

	ofd->type = sim2ftype[fcp[6] & 7];
	switch (ofd->type) {
	case TYPE_EF:
		ofd->ef_type = sim2eftype[fcp[13] & 7];
		if (fcp_len < 13 + fcp[12])
			return -EINVAL;
		switch (ofd->ef_type) {
		case EF_TYPE_RECORD_FIXED:
		case EF_TYPE_RECORD_CYCLIC:
			if (fcp_len < 15)
				return -EINVAL;
			ofd->rec_len = fcp[14];
			ofd->num_rec = ntohs(*(uint16_t *)(fcp+2)) / ofd->rec_len;
			break;
		default:
			break;
		}
		break;
	case TYPE_MF:
	case TYPE_DF:
		if (fcp_len < 22)
			return -EINVAL;
		break;
	default:
		break;
	}

	return 0;
}

/*! scan an UICC for all installed apps; allocate osim_card_app_hdl for each of them */
static int osim_uicc_scan_apps(struct osim_chan_hdl *st)
{
	struct tlv_parsed tp;
	struct osim_fcp_fd_decoded ofd;
	struct msgb *msg;
	uint8_t *cur;
	int rc, i;

	/* we don't know where we currently might be; go back to MF */
	msg = select_file(st, 0x3f00);
	if (!msg)
		return -EIO;
	if (msgb_apdu_sw(msg) != 0x9000)
		return -msgb_apdu_sw(msg);

	/* select EF.DIR */
	msg = select_file(st, 0x2f00);
	if (!msg)
		return -EIO;
	/* return status word in case of error */
	if (msgb_apdu_sw(msg) != 0x9000)
		return -msgb_apdu_sw(msg);

	/* various FCP related sanity checks */
	rc = tlv_parse(&tp, &ts102221_fcp_tlv_def, msgb_apdu_de(msg)+2, msgb_apdu_le(msg)-2, 0, 0);
	if (rc < 0) {
		fprintf(stderr, "Error decoding EF.DIR FCP TLV\n");
		msgb_free(msg);
		return -EINVAL;
	}

	dump_fcp_template(&tp);

	if (!TLVP_PRESENT(&tp, UICC_FCP_T_FILE_DESC) ||
	    TLVP_LEN(&tp, UICC_FCP_T_FILE_DESC) < 5) {
		fprintf(stderr, "No EF.DIR FCP file description\n");
		msgb_free(msg);
		return -EINVAL;
	}

	rc = osim_fcp_fd_decode(&ofd, TLVP_VAL(&tp, UICC_FCP_T_FILE_DESC),
				TLVP_LEN(&tp, UICC_FCP_T_FILE_DESC));
	if (rc < 0) {
		fprintf(stderr, "Error decoding EF.DIR FCP file description\n");
		msgb_free(msg);
		return -EINVAL;
	}

	if (ofd.type != TYPE_EF || ofd.ef_type != EF_TYPE_RECORD_FIXED) {
		fprintf(stderr, "EF.DIR is not a fixed record EF!?!\n");
		msgb_free(msg);
		return -EINVAL;
	}

	msgb_free(msg);

	printf("ofd rec_len = %u, num_rec = %u\n", ofd.rec_len, ofd.num_rec);

	for (i = 0; i < ofd.num_rec; i++) {
		const uint8_t *aid;
		uint8_t aid_len;
		msg = read_record_nr(st, i+1, ofd.rec_len);
		if (!msg) {
			fprintf(stderr, "Error reading Record %u of EF.DIR, skipping\n", i+1);
			continue;
		}

		/* Entries look like this:
		 * 61194f10 a0000000871002ffffffff8907090000 5005 5553696d31 ffffffffffffffffffffff */

		cur = msgb_apdu_de(msg);
		if (msgb_apdu_le(msg) < 5) {
			fprintf(stderr, "Record length %u too short for EF.DIR, skipping\n", msgb_apdu_le(msg));
			msgb_free(msg);
			continue;
		}

		if (cur[0] != 0x61 || cur[1] < 0x03 || cur[1] > 0x7f ||
		    cur[2] != 0x4F || cur[3] < 0x01 || cur[3] > 0x10) {
			fprintf(stderr, "Unexpected/unknown record in EF.DIR: %s, skipping\n",
				osmo_hexdump_nospc(msgb_apdu_de(msg), msgb_apdu_le(msg)));
			msgb_free(msg);
			continue;
		}
		aid_len = cur[3];
		aid = cur+4;

		/* FIXME: parse / pass label*/
		printf("Detected AID %s\n", osmo_hexdump_nospc(aid, aid_len));
		osim_card_hdl_add_app(st->card, aid, aid_len, NULL);
	}

	return i;
}


extern struct osim_card_profile *osim_cprof_sim(void *ctx);
extern struct osim_card_profile *osim_cprof_uicc(void *ctx, bool have_df_gsm);

static int dump_file(struct osim_chan_hdl *chan, const char *short_name, uint16_t fid)
{
	struct tlv_parsed tp;
	struct osim_fcp_fd_decoded ffdd;
	struct msgb *msg, *rmsg;
	int rc, i, offset;
	FILE *f_data = NULL;

	/* Select the file */
	msg = select_file(chan, fid);
	if (!msg) {
		fprintf(stderr, "Unable to select file\n");
		return -EIO;
	}
	if (msgb_apdu_sw(msg) != 0x9000) {
		fprintf(stderr, "status 0x%04x selecting file\n", msgb_apdu_sw(msg));
		goto out;
	}

	if (g_class != 0xA0) {
		rc = tlv_parse(&tp, &ts102221_fcp_tlv_def, msgb_apdu_de(msg)+2, msgb_apdu_le(msg)-2, 0, 0);
		if (rc < 0) {
			fprintf(stderr, "Unable to parse FCP: %s\n", msgb_hexdump(msg));
			goto out;
		}

		if (!TLVP_PRESENT(&tp, UICC_FCP_T_FILE_DESC) ||
		    TLVP_LEN(&tp, UICC_FCP_T_FILE_DESC) < 2) {
			fprintf(stderr, "No file descriptor present ?!?\n");
			goto out;
		}

		rc = osim_fcp_fd_decode(&ffdd, TLVP_VAL(&tp, UICC_FCP_T_FILE_DESC),
					TLVP_LEN(&tp, UICC_FCP_T_FILE_DESC));
	} else {
		rc = osim_fcp_fd_decode_sim(&ffdd, msgb_apdu_de(msg), msgb_apdu_le(msg));
	}

	if (rc < 0) {
		fprintf(stderr, "Unable to decode File Descriptor\n");
		goto out;
	}

	if (ffdd.type != TYPE_EF) {
		fprintf(stderr, "File Type != EF\n");
		goto out;
	}

	if (g_output_dir) {
		f_data = fopen(short_name, "w");
		if (!f_data) {
			fprintf(stderr, "Couldn't create '%s': %s\n", short_name, strerror(errno));
			goto out;
		}
	}

	printf("EF type: %u\n", ffdd.ef_type);

	switch (ffdd.ef_type) {
	case EF_TYPE_RECORD_FIXED:
		for (i = 0; i < ffdd.num_rec; i++) {
			const char *hex;
			rmsg = read_record_nr(chan, i+1, ffdd.rec_len);
			if (!rmsg) {
				if (f_data)
					fclose(f_data);
				return -EIO;
			}
			printf("SW: %s\n", osim_print_sw(chan, msgb_apdu_sw(msg)));

			hex = osmo_hexdump_nospc(msgb_apdu_de(rmsg), msgb_apdu_le(rmsg));
			printf("Rec %03u: %s\n", i+1, hex);
			if (f_data)
				fprintf(f_data, "%s\n", hex);
		}
		break;
	case EF_TYPE_TRANSP:
		if (g_class != 0xA0) {
			if (!TLVP_PRESENT(&tp, UICC_FCP_T_FILE_SIZE))
				goto out;
			i = ntohs(*(uint16_t *)TLVP_VAL(&tp, UICC_FCP_T_FILE_SIZE));
			printf("File size: %d bytes\n", i);
		} else {
			fprintf(stderr, "Can not determine file size, invalid EF-type!\n");
			goto out;
		}
		for (offset = 0; offset < i-1; ) {
			uint16_t remain_len = i - offset;
			uint16_t read_len = OSMO_MIN(remain_len, 256);
			const char *hex;
			rmsg = read_binary(chan, offset, read_len);
			if (!rmsg) {
				if (f_data)
					fclose(f_data);
				return -EIO;
			}
			offset += read_len;
			hex = osmo_hexdump_nospc(msgb_apdu_de(rmsg), msgb_apdu_le(rmsg));
			printf("Content: %s\n", hex);
			if (f_data)
				fprintf(f_data, "%s", hex);
		}
		break;
	default:
		goto out;
	}

out:
	if (f_data)
		fclose(f_data);
	msgb_free(msg);
	return -EINVAL;

}

static void print_help(void)
{
	printf(	"osmo-sim-test Usage:\n"
		" -h  --help		This message\n"
		" -n  --reader-num NR	Open reader number NR\n"
		" -o  --output-dir DIR	To-be-created output directory for filesystem dump\n"
	      );
}

static int readernum = 0;

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		const struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "reader-num", 1, 0, 'n' },
			{ "output-dir", 1, 0, 'o' },
			{0,0,0,0}
		};

		c = getopt_long(argc, argv, "hn:o:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'n':
			readernum = atoi(optarg);
			break;
		case 'o':
			g_output_dir = optarg;
			break;
		default:
			exit(2);
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
	}
}


static void mkdir_and_chdir(const char *name, mode_t mode)
{
	int rc;
	rc = mkdir(name, mode);
	if (rc < 0) {
		fprintf(stderr, "Cannot create '%s': %s\n", name, strerror(errno));
		exit(24);
	}
	rc = chdir(name);
	if (rc < 0) {
		fprintf(stderr, "Cannot change to just-created '%s': %s\n", name, strerror(errno));
		exit(24);
	}
}


static void iterate_fs(struct osim_chan_hdl *chan)
{
	const struct osim_file_desc *prev_cwd;
	struct osim_file_desc *ofd;

	/* iterate over all files in current working directory */
	llist_for_each_entry(ofd, &chan->cwd->child_list, list) {
		struct msgb *m;
		char prev_dir[PATH_MAX];

		printf("\n\n================ %s (%s) ==================\n",
			ofd->short_name, ofd->long_name);

		m = select_file(chan, ofd->fid);
		if (msgb_apdu_sw(m) != 0x9000) {
			msgb_free(m);
			continue;
		}
		dump_fcp_template_msg(m);
		msgb_free(m);

		/* If this is a DF, recurse into it */
		switch (ofd->type) {
		case TYPE_DF:
			/* the select above has just changed into this directory */
			prev_cwd = chan->cwd;
			chan->cwd = ofd;
			if (g_output_dir) {
				if (!getcwd(prev_dir, sizeof(prev_dir))) {
					fprintf(stderr, "Cannot determine cwd: %s\n", strerror(errno));
					exit(23);
					continue;
				}
				mkdir_and_chdir(ofd->short_name, 0750);
			}
			iterate_fs(chan);
			/* "pop" the directory from the stack */
			chan->cwd = prev_cwd;
			if (g_output_dir)
				OSMO_ASSERT(chdir("..") == 0);
			break;
		default:
			dump_file(chan, ofd->short_name, ofd->fid);
			break;
		}
	}
}

static void iterate_apps(struct osim_chan_hdl *chan)
{
	struct osim_card_app_hdl *cah;

	llist_for_each_entry(cah, &chan->card->apps, list) {
		const struct osim_card_app_profile *cap = cah->prof;
		struct msgb *msg;

		if (!cap) {
			fprintf(stderr, "Unknown AID %s; skipping\n",
				osmo_hexdump_nospc(cah->aid, cah->aid_len));
			continue;
		}

		msg = select_adf(chan, cah->aid, cah->aid_len);
		if (!msg) {
			fprintf(stderr, "Error selectiong ADF for AID %s; skipping\n",
				osmo_hexdump_nospc(cah->aid, cah->aid_len));
			continue;
		}
		printf("SW: %s\n", osim_print_sw(chan, msgb_apdu_sw(msg)));
		chan->cur_app = cah;
		chan->cwd = cap->adf;

		if (g_output_dir)
			mkdir_and_chdir(cap->adf->short_name, 0750);

		iterate_fs(chan);

		if (g_output_dir)
			OSMO_ASSERT(chdir("..") == 0);
	}
}


int main(int argc, char **argv)
{
	struct osim_reader_hdl *reader;
	struct osim_card_hdl *card;
	struct osim_chan_hdl *chan;
	int rc;

	handle_options(argc, argv);

	osim_init(NULL);

	if (g_output_dir) {
		int rc;
		rc = mkdir(g_output_dir, 0750);
		if (rc < 0) {
			fprintf(stderr, "Cannot create directory '%s': %s\n", g_output_dir,
				strerror(errno));
			exit(5);
		}
		rc = chdir(g_output_dir);
		if (rc < 0) {
			fprintf(stderr, "Cannot change to just-created directory '%s': %s\n",
				g_output_dir, strerror(errno));
			exit(5);
		}
	}

	reader = osim_reader_open(OSIM_READER_DRV_PCSC, readernum, "", NULL);
	if (!reader)
		exit(1);
	card = osim_card_open(reader, OSIM_PROTO_T0);
	if (!card)
		exit(2);
	chan = llist_entry(card->channels.next, struct osim_chan_hdl, list);
	if (!chan)
		exit(3);

	//verify_pin(chan, 1, "1653");

	rc = osim_uicc_scan_apps(chan);
	if (rc >= 0) {
		chan->card->prof = osim_cprof_uicc(chan->card, true);
		chan->cwd = chan->card->prof->mf;
	} else if (rc == -0x6e00) {
		/* CLA not supported: must be classic SIM, not USIM */
		g_class = 0xA0;
		chan->card->prof = osim_cprof_sim(chan->card);
		chan->cwd = chan->card->prof->mf;
	} else if (rc < 0) {
		exit(4);
	}

	/* first iterate over normal file system */
	iterate_fs(chan);

	/* then itereate over all apps and their file system */
	iterate_apps(chan);

	exit(0);
}
