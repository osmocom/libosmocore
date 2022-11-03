#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include <osmocom/core/bitvec.h>
#include <osmocom/core/utils.h>

#include <osmocom/codec/codec.h>
#include <osmocom/codec/ecu.h>
#include <osmocom/codec/gsm610_bits.h>

/* Set with sample full-rate voice frames and some intentional dropouts */
static const char *fr_frames_hex[] = {
	"d9aa93ae63de00471a91b95b8660471392b4a2daa037628f391c624039258dc723",
	"d8eb83699a66c036ec89b7246e6034dc8d48948620589b7256e3a6603b2371b8da",
	"d967abaa1cbe4035238da6ace4c036d46ec69ba600391c4eb8a2b040591c6a3924",
	"d8e8a42662c240472469b91bd2e0452291b6dba600495b8e38dcb020491a71c91b",
	"da2aac1ddbb00036e46e26dcec6039138db923822047137248e3560048e38dc8e3",
	"d929ab2a9b5240395b6dc72ba020469c8d551c5440349c9148e36a4036a372471b",
	"d9eb93215bb8a0271c69c724682036db71c71a94a0372491b72bee4044eb71b923",
	"d9ab9aa19abc40391b6e5ae2ee40471b91c6dbe820492291b8e4b84036e47238db",
	"d96b9be9db782044e371b55cb200389491c69b8ea034e271c8d3808038ec6db8e3",
	"d9aa9365e3f060375c6db6ebc4c02764b1c51b78a0571c91a723de6049248dc8dd",
	"BAD",
	"d9ea9c219ce60046e38d3724e0c034e56e36eb7e0038d471b8dcb260491b8dbb23",
	"d9e89be9d9e0a0391b6dd6a4624029247138e3a2a04713922524de0036db69d91c",
	"d9699422a2b6a048dd90c91c6a802b6259395c8880575b4a58e4ac20269d7248d4",
	"d967ac5b1baae0371c71b8ab9c804a9e8e58a55a8038626ec8dcb640395c7244dc",
	"d9e8a3e262e68027638db52b88a038634e471a7ec049136e3b1bc8402923adcad2",
	"d8eab36e1bbe0046e34d491b608035137658d3524044e48e375cdac0472b9238d4",
	"d9689ba5e3d260491b516adb5e4027256e27227ee0351c8e549a5c60492471971b",
	"BAD",
	"BAD",
	"d8e6a2e1d3d2605b1376c8d35280392451391cbc80392a71b6db8aa049238dc8ab",
	"d9a87ba1a3982048eb8a471cac00472b4e391bbc40292489b71cc200495b8d3ae3",
	"d9278b2a1ba4c0475b8dc722d6e0491b5228da70204ae36dc71d94a056a29236e3",
	"d9ec9be2129520392335598c50c04b5bad3d4ba680789b69df5a5aa0469cd1b4da",
	"d8ea932623e660669b8e4a9dd8a03aa32a76e466e028d396cc9bbe4047256dc8e5",
	"d96a94215aa0403aab713f22e8e024e68db91ab6a027abd1a55b6e804aec9146e4",
	"d867ac21e270a0350d6ac91a724037247246d2a6c0396c89d6dc562049244e48d5",
	"d8a9b460d3b48026a4ad471b7c20452491b69bbc803ae48db722ee00292491a8db",
	"d928a3e1d3b24036e37244abf02047634d371b74c047637148a29ac03b234e38e3",
	"d9ab9b21d2e0c0471c693aec54e044dbae46dc7c20391badb724ee8038e469bb15",
	"d9a99361a276403b1a6ad6dcd40026e489c8e3bc40371c4dc564e2c036e28eb963",
	"BAD",
	"BAD",
	"BAD",
	"BAD",
	"BAD",
	"BAD",
	"d92c8b6d5aee4034ebb22724862047145634a5c0a038e371b8e4a880485c89dd25",
	"d8e78b29e3c6c038dba9d91beca04723ad491cda80471471b6ec7ae03b1396b91b",
	"d8a78b25e37a0022dd8a46dc68a0351bad391bde2046e56dd8dc96c038e396d89b",
	"d8a88c255ab6e038e38e48dbde8038ad8dc8db8ec0376372b564b44038e49234dc",
	"d9708ce6a39ce049646646a2c1a0272496b29a66c037db562863ace0795b55b2e3",
	"d8ee9bea5ae4003ae371b713eae05adc91995a5ea064dcc9571e786026ed51c52c",
	"d9299421d2944036ed69b8e572a048e36d551cd480571d4ec95be680356c69c763",
	"d92aab696190c046e26e392cae0026a376a8dc662048d291b75b54c04ad3ae3b1b",
	"d8e7a469627a6038e289cb1baca0569b8db6dddec026dc8e38e5dc803722722d23",
	"d8a88c299b64c03a548a58e37420272c6dd76b92c0471c9236dbc0e0551c71c713",
	"BAD",
	"d7299c19a3be8024e58ea7a49f20a522963ad976e0a76ecd92b38500cb62aa4c94",
	"d7eb6c6262eee02b2c42e79a60a0aa55aed68a7f00ad358e10fad960e55a39396d",
	"d970858dd2ab61d91355ebc15ca1a6a7ca48a05cc0dae66f2523c2a1bad3825daa",
	"d8f0844a23ad20da50d6de025e81c37392b9039cc0c764c1bd1e94c1b699736a98",
	"d9708ce6a39ce049646646a2c1a0272496b29a66c037db562863ace0795b55b2e3",
	"d9299421d2944036ed69b8e572a048e36d551cd480571d4ec95be680356c69c763",
	"d9299421d2944036ed69b8e572a048e36d551cd480571d4ec95be680356c69c763",
	"d9299421d2944036ed69b8e572a048e36d551cd480571d4ec95be680356c69c763",
	"d2577a1cda50004924924924500049249249245000492492492450004923924924",
	NULL
};

/* Example of a good frame */
static const char *sample_frame_hex[] = {
	"d9ec9be212901f802335598c501f805bad3d4ba01f809b69df5a501f809cd1b4da",
	"d9ec9be212901d802335598c5013805bad3d4ba01f809b69df5a5019809cd1b4da",
	NULL
};

#define GSM610_XMAXC_LEN	6
static void parse_xmaxc_frame(uint8_t *frame, uint64_t xmaxc_res[4])
{
	unsigned int field_index, len;

	struct bitvec *frame_bitvec = bitvec_alloc(GSM_FR_BYTES, NULL);
	OSMO_ASSERT(frame_bitvec);
	len = bitvec_unpack(frame_bitvec, frame);
	OSMO_ASSERT(len == GSM_FR_BYTES);

	field_index = GSM610_RTP_XMAXC00;
	xmaxc_res[0] = bitvec_read_field(frame_bitvec, &field_index, GSM610_XMAXC_LEN);
	field_index = GSM610_RTP_XMAXC10;
	xmaxc_res[1] = bitvec_read_field(frame_bitvec, &field_index, GSM610_XMAXC_LEN);
	field_index = GSM610_RTP_XMAXC20;
	xmaxc_res[2] = bitvec_read_field(frame_bitvec, &field_index, GSM610_XMAXC_LEN);
	field_index = GSM610_RTP_XMAXC30;
	xmaxc_res[3] = bitvec_read_field(frame_bitvec, &field_index, GSM610_XMAXC_LEN);

	bitvec_free(frame_bitvec);
}

/**
 * Start with a good voice frame and then simulate 20 consecutive bad frames,
 * watching how the error concealment decreases the XMAXC parameters.
 */
void test_fr_concealment(void)
{
	struct osmo_ecu_fr_state state;
	uint8_t frame[GSM_FR_BYTES];
	uint64_t xmaxc[4];
	int i, rc;
	int j = 0;

	printf("=> Testing FR concealment (simple, consecutive bad frames)\n");

	while (sample_frame_hex[j] != NULL) {
		/* Parse frame from string to hex */
		osmo_hexparse(sample_frame_hex[j], frame, GSM_FR_BYTES);
		parse_xmaxc_frame(frame, xmaxc);
		printf("Start with: %s, XMAXC: [%"PRIx64", %"PRIx64", %"PRIx64", %"PRIx64"]\n",
		       sample_frame_hex[j], xmaxc[0], xmaxc[1], xmaxc[2], xmaxc[3]);

		/* Reset the ECU with the proposed known good frame */
		osmo_ecu_fr_reset(&state, frame);

		/* Now pretend that we do not receive any good frames anymore */
		for (i = 0; i < 20; i++) {

			rc = osmo_ecu_fr_conceal(&state, frame);
			OSMO_ASSERT(rc == 0);
			parse_xmaxc_frame(frame, xmaxc);

			printf("conceal: %02i, result: %s XMAXC: [%"PRIx64", %"PRIx64", %"PRIx64", %"PRIx64"]\n",
			       i, osmo_hexdump_nospc(frame, GSM_FR_BYTES),
			       xmaxc[0], xmaxc[1], xmaxc[2], xmaxc[3]);
		}

		/* Go to the next frame */
		j++;
	}
}

/* Same as test_fr_concealment() but using generic core */
void test_fr_concealment_core(void)
{
	struct osmo_ecu_state *state = osmo_ecu_init(NULL, OSMO_ECU_CODEC_FR);
	uint8_t frame[GSM_FR_BYTES];
	uint64_t xmaxc[4];
	int i, rc;
	int j = 0;

	printf("=> Testing FR concealment (simple, consecutive bad frames)\n");

	while (sample_frame_hex[j] != NULL) {
		/* Parse frame from string to hex */
		osmo_hexparse(sample_frame_hex[j], frame, GSM_FR_BYTES);
		parse_xmaxc_frame(frame, xmaxc);
		printf("Start with: %s, XMAXC: [%"PRIx64", %"PRIx64", %"PRIx64", %"PRIx64"]\n",
		       sample_frame_hex[j], xmaxc[0], xmaxc[1], xmaxc[2], xmaxc[3]);

		/* Reset the ECU with the proposed known good frame */
		osmo_ecu_frame_in(state, false, frame, GSM_FR_BYTES);

		/* Now pretend that we do not receive any good frames anymore */
		for (i = 0; i < 20; i++) {

			rc = osmo_ecu_frame_out(state, frame);
			OSMO_ASSERT(rc == GSM_FR_BYTES);
			parse_xmaxc_frame(frame, xmaxc);

			printf("conceal: %02i, result: %s XMAXC: [%"PRIx64", %"PRIx64", %"PRIx64", %"PRIx64"]\n",
			       i, osmo_hexdump_nospc(frame, GSM_FR_BYTES),
			       xmaxc[0], xmaxc[1], xmaxc[2], xmaxc[3]);
		}

		/* Go to the next frame */
		j++;
	}

	osmo_ecu_destroy(state);
}

/* Simulate a real life situation: voice frames with a few dropouts */
void test_fr_concealment_realistic(void)
{
	struct osmo_ecu_fr_state state;
	uint8_t frame[GSM_FR_BYTES];
	unsigned int frame_len;
	int rc, i = 0;

	printf("\n=> Testing FR concealment (realistic, various bad frames)\n");

	while (fr_frames_hex[i] != NULL) {
		/* Debug print */
		printf("Frame No. %03i:\n", i);

		/* Good or bad frame? */
		frame_len = strlen(fr_frames_hex[i]) / 2;
		if (frame_len == GSM_FR_BYTES) {
			printf(" * input:  %s\n", fr_frames_hex[i]);
			osmo_hexparse(fr_frames_hex[i], frame, GSM_FR_BYTES);
			osmo_ecu_fr_reset(&state, frame);
		} else {
			printf(" * input:  (bad)\n");
			memset(frame, 0x00, GSM_FR_BYTES);
			rc = osmo_ecu_fr_conceal(&state, frame);
			OSMO_ASSERT(rc == 0);
		}

		/* Print result */
		printf(" * output: %s\n",
			osmo_hexdump_nospc(frame, GSM_FR_BYTES));

		/* Go to the next frame */
		i++;
	}
}

/* Simulate a real life situation: voice frames with a few dropouts, using generic core */
void test_fr_concealment_realistic_core(void)
{
	struct osmo_ecu_state *state = osmo_ecu_init(NULL, OSMO_ECU_CODEC_FR);
	uint8_t frame[GSM_FR_BYTES];
	unsigned int frame_len;
	int rc, i = 0;

	printf("\n=> Testing FR concealment (realistic, using ECU abstraction)\n");

	OSMO_ASSERT(state);

	while (fr_frames_hex[i] != NULL) {
		/* Debug print */
		printf("Frame No. %03i:\n", i);

		/* Good or bad frame? */
		frame_len = strlen(fr_frames_hex[i]) / 2;
		if (frame_len == GSM_FR_BYTES) {
			printf(" * input:  %s\n", fr_frames_hex[i]);
			osmo_hexparse(fr_frames_hex[i], frame, GSM_FR_BYTES);
			osmo_ecu_frame_in(state, false, frame, GSM_FR_BYTES);
		} else {
			printf(" * input:  (bad)\n");
			memset(frame, 0x00, GSM_FR_BYTES);
			osmo_ecu_frame_in(state, true, frame, 0);
			rc = osmo_ecu_frame_out(state, frame);
			OSMO_ASSERT(rc == GSM_FR_BYTES);
		}

		/* Print result */
		printf(" * output: %s\n",
			osmo_hexdump_nospc(frame, GSM_FR_BYTES));

		/* Go to the next frame */
		i++;
	}

	osmo_ecu_destroy(state);
}


int main(int argc, char **argv)
{
	/* Perform actual tests */
	test_fr_concealment();
	test_fr_concealment_core();
	test_fr_concealment_realistic();
	test_fr_concealment_realistic_core();

	return 0;
}
