/* gsm 04.08 system information (si) encoding and decoding
 * 3gpp ts 04.08 version 7.21.0 release 1998 / etsi ts 100 940 v7.21.0 */

/*
 * (C) 2012 Holger Hans Peter Freyther
 * (C) 2012 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_arfcn_range_encode.h>

#include <osmocom/core/utils.h>

#include <errno.h>

static inline int greatest_power_of_2_lesser_or_equal_to(int index)
{
	int power_of_2 = 1;

	do {
		power_of_2 *= 2;
	} while (power_of_2 <= index);

	/* now go back one step */
	return power_of_2 / 2;
}

static inline int mod(int data, int range)
{
	int res = data % range;
	while (res < 0)
		res += range;
	return res;
}

/**
 * Determine at which index to split the ARFCNs to create an
 * equally size partition for the given range. Return -1 if
 * no such partition exists.
 */
int osmo_gsm48_range_enc_find_index(enum osmo_gsm48_range range, const int *freqs, const int size)
{
	int i, j, n;

	const int RANGE_DELTA = (range - 1) / 2;

	for (i = 0; i < size; ++i) {
		n = 0;
		for (j = 0; j < size; ++j) {
			if (mod(freqs[j] - freqs[i], range) <= RANGE_DELTA)
				n += 1;
		}

		if (n - 1 == (size - 1) / 2)
			return i;
	}

	return -1;
}

/* Worker for range_enc_arfcns(), do not call directly. */
static int _range_enc_arfcns(enum osmo_gsm48_range range,
		const int *arfcns, int size, int *out,
		const int index)
{
	int split_at;
	int i;

	/*
	 * The below is a GNU extension and we can remove it when
	 * we move to a quicksort like in-situ swap with the pivot.
	 */
	int arfcns_left[size / 2];
	int arfcns_right[size / 2];
	int l_size;
	int r_size;
	int l_origin;
	int r_origin;

	/* Now do the processing */
	split_at = osmo_gsm48_range_enc_find_index(range, arfcns, size);
	if (split_at < 0)
		return -EINVAL;

	/* we now know where to split */
	out[index] = 1 + arfcns[split_at];

	/* calculate the work that needs to be done for the leafs */
	l_origin = mod(arfcns[split_at] + ((range - 1) / 2) + 1, range);
	r_origin = mod(arfcns[split_at] + 1, range);
	for (i = 0, l_size = 0, r_size = 0; i < size; ++i) {
		if (mod(arfcns[i] - l_origin, range) < range / 2)
			arfcns_left[l_size++] = mod(arfcns[i] - l_origin, range);
		if (mod(arfcns[i] - r_origin, range) < range / 2)
			arfcns_right[r_size++] = mod(arfcns[i] - r_origin, range);
	}

	/*
	 * Now recurse and we need to make this iterative... but as the
	 * tree is balanced the stack will not be too deep.
	 */
	if (l_size)
		osmo_gsm48_range_enc_arfcns(range / 2, arfcns_left, l_size,
			out, index + greatest_power_of_2_lesser_or_equal_to(index + 1));
	if (r_size)
		osmo_gsm48_range_enc_arfcns((range - 1) / 2, arfcns_right, r_size,
			 out, index + (2 * greatest_power_of_2_lesser_or_equal_to(index + 1)));
	return 0;
}

/**
 * Range encode the ARFCN list.
 * \param range The range to use.
 * \param arfcns The list of ARFCNs
 * \param size The size of the list of ARFCNs
 * \param out Place to store the W(i) output.
 */
int osmo_gsm48_range_enc_arfcns(enum osmo_gsm48_range range,
		const int *arfcns, int size, int *out,
		const int index)
{
	if (size <= 0)
		return 0;

	if (size == 1) {
		out[index] = 1 + arfcns[0];
		return 0;
	}

	return _range_enc_arfcns(range, arfcns, size, out, index);
}

/*
 * The easiest is to use f0 == arfcns[0]. This means that under certain
 * circumstances we can encode less ARFCNs than possible with an optimal f0.
 *
 * TODO: Solve the optimisation problem and pick f0 so that the max distance
 * is the smallest. Taking into account the modulo operation. I think picking
 * size/2 will be the optimal arfcn.
 */
/**
 * This implements the range determination as described in GSM 04.08 J4. The
 * result will be a base frequency f0 and the range to use. Note that for range
 * 1024 encoding f0 always refers to ARFCN 0 even if it is not an element of
 * the arfcns list.
 *
 * \param[in] arfcns The input frequencies, they must be sorted, lowest number first
 * \param[in] size The length of the array
 * \param[out] f0 The selected F0 base frequency. It might not be inside the list
 */
int osmo_gsm48_range_enc_determine_range(const int *arfcns, const int size, int *f0)
{
	int max = 0;

	/* don't dereference arfcns[] array if size is 0 */
	if (size == 0)
		return OSMO_GSM48_ARFCN_RANGE_128;

	/*
	 * Go for the easiest. And pick arfcns[0] == f0.
	 */
	max = arfcns[size - 1] - arfcns[0];
	*f0 = arfcns[0];

	if (max < 128 && size <= 29)
		return OSMO_GSM48_ARFCN_RANGE_128;
	if (max < 256 && size <= 22)
		return OSMO_GSM48_ARFCN_RANGE_256;
	if (max < 512 && size <= 18)
		return OSMO_GSM48_ARFCN_RANGE_512;
	if (max < 1024 && size <= 17) {
		*f0 = 0;
		return OSMO_GSM48_ARFCN_RANGE_1024;
	}

	return OSMO_GSM48_ARFCN_RANGE_INVALID;
}

static void write_orig_arfcn(uint8_t *chan_list, int f0)
{
	chan_list[0] |= (f0 >> 9) & 1;
	chan_list[1] = (f0 >> 1);
	chan_list[2] = (f0 & 1) << 7;
}

static void write_all_wn(uint8_t *chan_list, int bit_offs,
			 int *w, int w_size, int w1_len)
{
	int octet_offs = 0; /* offset into chan_list */
	int wk_len = w1_len; /* encoding size in bits of w[k] */
	int k; /* 1 based */
	int level = 0; /* tree level, top level = 0 */
	int lvl_left = 1; /* nodes per tree level */

	/* W(2^i) to W(2^(i+1)-1) are on w1_len-i bits when present */

	for (k = 1; k <= w_size; k++) {
		int wk_left = wk_len;

		while (wk_left > 0) {
			int cur_bits = 8 - bit_offs;
			int cur_mask;
			int wk_slice;

			if (cur_bits > wk_left)
				cur_bits = wk_left;

			cur_mask = ((1 << cur_bits) - 1);

			/* advance */
			wk_left -= cur_bits;
			bit_offs += cur_bits;

			/* right aligned wk data for current out octet */
			wk_slice = (w[k-1] >> wk_left) & cur_mask;

			/* cur_bits now contains the number of bits
			 * that are to be copied from wk to the chan_list.
			 * wk_left is set to the number of bits that must
			 * not yet be copied.
			 * bit_offs points after the bit area that is going to
			 * be overwritten:
			 *
			 *          wk_left
			 *             |
			 *             v
			 * wk: WWWWWWWWWWW
			 *        |||||<-- wk_slice, cur_bits=5
			 *      --WWWWW-
			 *             ^
			 *             |
			 *           bit_offs
			 */

			chan_list[octet_offs] &= ~(cur_mask << (8 - bit_offs));
			chan_list[octet_offs] |= wk_slice << (8 - bit_offs);

			/* adjust output */
			if (bit_offs == 8) {
				bit_offs = 0;
				octet_offs += 1;
			}
		}

		/* adjust bit sizes */
		lvl_left -= 1;
		if (!lvl_left) {
			/* completed tree level, advance to next */
			level += 1;
			lvl_left = 1 << level;
			wk_len -= 1;
		}
	}
}

int osmo_gsm48_range_enc_128(uint8_t *chan_list, int f0, int *w)
{
	chan_list[0] = 0x8C;
	write_orig_arfcn(chan_list, f0);

	write_all_wn(&chan_list[2], 1, w, 28, 7);
	return 0;
}

int osmo_gsm48_range_enc_256(uint8_t *chan_list, int f0, int *w)
{
	chan_list[0] = 0x8A;
	write_orig_arfcn(chan_list, f0);

	write_all_wn(&chan_list[2], 1, w, 21, 8);
	return 0;
}

int osmo_gsm48_range_enc_512(uint8_t *chan_list, int f0, int *w)
{
	chan_list[0] = 0x88;
	write_orig_arfcn(chan_list, f0);

	write_all_wn(&chan_list[2], 1, w, 17, 9);
	return 0;
}

int osmo_gsm48_range_enc_1024(uint8_t *chan_list, int f0, int f0_included, int *w)
{
	chan_list[0] = 0x80 | (f0_included << 2);

	write_all_wn(&chan_list[0], 6, w, 16, 10);
	return 0;
}

int osmo_gsm48_range_enc_filter_arfcns(int *arfcns, const int size, const int f0, int *f0_included)
{
	int i, j = 0;
	*f0_included = 0;

	for (i = 0; i < size; ++i) {
		/*
		 * Appendix J.4 says the following:
		 * All frequencies except F(0), minus F(0) + 1.
		 * I assume we need to exclude it here.
		 */
		if (arfcns[i] == f0) {
			*f0_included = 1;
			continue;
		}

		arfcns[j++] = mod(arfcns[i] - (f0 + 1), 1024);
	}

	return j;
}
