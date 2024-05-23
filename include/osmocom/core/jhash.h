#pragma once
#include <osmocom/core/bit32gen.h>

/* Below is a partial copy of
 * https://raw.githubusercontent.com/torvalds/linux/3eb3c33c1d87029a3832e205eebd59cfb56ba3a4/tools/include/linux/bitops.h
 * with an osmo_ prefix applied to avoid any collisions.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline uint32_t osmo_rol32(uint32_t word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

/* Below is a partial copy of
 * https://raw.githubusercontent.com/torvalds/linux/22c033989c3eb9731ad0c497dfab4231b8e367d6/include/linux/unaligned/packed_struct.h
 * with an osmo_ prefix applied to avoid any collisions.
 */
struct osmo_unaligned_cpu32 {
	uint32_t x;
} __attribute__((__packed__));

static inline uint32_t osmo_get_unaligned_cpu32(const void *p)
{
	const struct osmo_unaligned_cpu32 *ptr = (const struct osmo_unaligned_cpu32 *)p;
	return ptr->x;
}

/* Below is a partial copy of
 * https://raw.githubusercontent.com/torvalds/linux/79e3ea5aab48c83de9410e43b52895406847eca7/tools/include/linux/jhash.h
 * with an osmo_ prefix applied to avoid any collisions.
 */
/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */

/* OSMO_JHASH_MIX -- mix 3 32-bit values reversibly. */
#define OSMO_JHASH_MIX(a, b, c)			\
{						\
	a -= c;  a ^= osmo_rol32(c, 4);  c += b;	\
	b -= a;  b ^= osmo_rol32(a, 6);  a += c;	\
	c -= b;  c ^= osmo_rol32(b, 8);  b += a;	\
	a -= c;  a ^= osmo_rol32(c, 16); c += b;	\
	b -= a;  b ^= osmo_rol32(a, 19); a += c;	\
	c -= b;  c ^= osmo_rol32(b, 4);  b += a;	\
}

/* OSMO_JHASH_FINAL - final mixing of 3 32-bit values (a,b,c) into c */
#define OSMO_JHASH_FINAL(a, b, c)			\
{						\
	c ^= b; c -= osmo_rol32(b, 14);		\
	a ^= c; a -= osmo_rol32(c, 11);		\
	b ^= a; b -= osmo_rol32(a, 25);		\
	c ^= b; c -= osmo_rol32(b, 16);		\
	a ^= c; a -= osmo_rol32(c, 4);		\
	b ^= a; b -= osmo_rol32(a, 14);		\
	c ^= b; c -= osmo_rol32(b, 24);		\
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef

/* osmo_jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline uint32_t osmo_jhash(const void *key, uint32_t length, uint32_t initval)
{
	uint32_t a, b, c;
	const uint8_t *k = key;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += osmo_get_unaligned_cpu32(k);
		b += osmo_get_unaligned_cpu32(k + 4);
		c += osmo_get_unaligned_cpu32(k + 8);
		OSMO_JHASH_MIX(a, b, c);
		length -= 12;
		k += 12;
	}
	/* Last block: affect all 32 bits of (c) */
	/* All the case statements fall through */
	switch (length) {
	case 12: c += (uint32_t)k[11]<<24;
	case 11: c += (uint32_t)k[10]<<16;
	case 10: c += (uint32_t)k[9]<<8;
	case 9:  c += k[8];
	case 8:  b += (uint32_t)k[7]<<24;
	case 7:  b += (uint32_t)k[6]<<16;
	case 6:  b += (uint32_t)k[5]<<8;
	case 5:  b += k[4];
	case 4:  a += (uint32_t)k[3]<<24;
	case 3:  a += (uint32_t)k[2]<<16;
	case 2:  a += (uint32_t)k[1]<<8;
	case 1:  a += k[0];
		 OSMO_JHASH_FINAL(a, b, c);
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

/* osmo_jhash2 - hash an array of uint32_t's
 * @k: the key which must be an array of uint32_t's
 * @length: the number of uint32_t's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline uint32_t osmo_jhash2(const uint32_t *k, uint32_t length, uint32_t initval)
{
	uint32_t a, b, c;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + (length<<2) + initval;

	/* Handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		OSMO_JHASH_MIX(a, b, c);
		length -= 3;
		k += 3;
	}

	/* Handle the last 3 uint32_t's: all the case statements fall through */
	switch (length) {
	case 3: c += k[2];
	case 2: b += k[1];
	case 1: a += k[0];
		OSMO_JHASH_FINAL(a, b, c);
	case 0:	/* Nothing left to add */
		break;
	}

	return c;
}
