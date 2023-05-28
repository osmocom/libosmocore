/* -----------------------------------------------------------------------
 * code extracted from 3GPP TS 35.231, annex E for Keccak core functions
 * https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=2402
 *-----------------------------------------------------------------------*/

/* This code may be freely used or adapted.
*/

#include "KeccakP-1600-3gpp.h"


const uint8_t Rho[25]		= {0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,
   15,21,8,18,2,61,56,14};

const uint8_t Pi[25]		= {0,6,12,18,24,3,9,10,16,22,1,7,13,19,20,4,5,11,17,
   23,2,8,14,15,21};

const uint8_t Iota[24]	= {1,146,218,112,155,33,241,89,138,136,57,42,187,203,
   217,83,82,192,26,106,241,208,33,120};

#define ROTATE64(value, n)	\
((((uint64_t)(value))<<(n)) | (((uint64_t)(value))>>(64-(n))))

/* ---------------------------------------------------------------------
   64-bit version of Keccak_f(1600)
   ---------------------------------------------------------------------
*/
void Keccak_f_64(uint64_t s[25])
{	uint64_t t[5];
	uint8_t i, j, round;

	for(round=0; round<24; ++round)
	{	/* Theta function */
		for(i=0; i<5; ++i)
			t[i] = s[i] ^ s[5+i] ^ s[10+i] ^ s[15+i] ^ s[20+i];
		for(i=0; i<5; ++i, s+=5)
		{	s[0] ^= t[4] ^ ROTATE64(t[1], 1);
			s[1] ^= t[0] ^ ROTATE64(t[2], 1);
			s[2] ^= t[1] ^ ROTATE64(t[3], 1);
			s[3] ^= t[2] ^ ROTATE64(t[4], 1);
			s[4] ^= t[3] ^ ROTATE64(t[0], 1);
		}
		s -= 25;

		/* Rho function */
		for(i=1; i<25; ++i)
			s[i] = ROTATE64(s[i], Rho[i]);

		/* Pi function */
		for(t[1] = s[i=1]; (j=Pi[i]) > 1; s[i]=s[j], i=j);
		s[i] = t[1];

		/* Chi function */
		for(i=0; i<5; ++i, s += 5)
		{	t[0] = (~s[1]) & s[2];
			t[1] = (~s[2]) & s[3];
			t[2] = (~s[3]) & s[4];
			t[3] = (~s[4]) & s[0];
			t[4] = (~s[0]) & s[1];
			for(j=0; j<5; ++j) s[j] ^= t[j];
		}
		s -= 25;

		/* Iota function */
		t[0] = Iota[round];
		*s ^= (t[0] | (t[0]<<11) | (t[0]<<26) | (t[0]<<57)) 
              & 0x800000008000808BULL; /* set & mask bits 0,1,3,7,15,31,63 */
	}
}


/* ---------------------------------------------------------------------
   8-bit version of Keccak_f(1600)
   ---------------------------------------------------------------------
*/
void Keccak_f_8(uint8_t s[200])
{	uint8_t t[40], i, j, k, round;

	for(round=0; round<24; ++round)
	{	/* Theta function */
		for(i=0; i<40; ++i)
			t[i]=s[i]^s[40+i]^s[80+i]^s[120+i]^s[160+i];
		for(i=0; i<200; i+=8)
			for(j = (i+32)%40, k=0; k<8; ++k)
				s[i+k] ^= t[j+k];
		for(i=0; i<40; t[i] = (t[i]<<1)|j, i+=8)
			for(j = t[i+7]>>7, k=7; k; --k)
				t[i+k] = (t[i+k]<<1)|(t[i+k-1]>>7);
		for(i=0; i<200; i+=8)
			for(j = (i+8)%40, k=0; k<8; ++k)
				s[i+k] ^= t[j+k];

		/* Rho function */
		for(i=8; i<200; i+=8)
		{	for(j = Rho[i>>3]>>3, k=0; k<8; ++k) 	/* j:=bytes to shift, s->t 		*/
				t[(k+j)&7] = s[i+k];
			for(j = Rho[i>>3]&7, k=7; k; --k) 	   /* j:=bits  to shift, t->s 	*/
				s[i+k] = (t[k]<<j) | (t[k-1]>>(8-j));
			s[i] = (t[0]<<j) | (t[7]>>(8-j));
		}

		/* Pi function */
		for(k=8; k<16; ++k) t[k] = s[k];		/* =memcpy(t+8, s+8, 8) 				 	*/
		for(i=1; (j=Pi[i])>1; i=j)
			for(k=0; k<8; ++k)						/* =memcpy(s+(i<<3), s+(j<<3), 8)	*/
				s[(i<<3)|k] = s[(j<<3)|k];
		for(k=0; k<8; ++k)							/* =memcpy(s+(i<<3), t+8, 8) 		 	*/
			s[(i<<3)|k] = t[k+8];

		/* Chi function */
		for(i=0; i<200; i+=40)
		{	for(j=0; j<40; ++j)
				t[j]=(~s[i+(j+8)%40]) & s[i+(j+16)%40];
			for(j=0; j<40; ++j)	s[i+j]^=t[j];
		}

		/* Iota function */
		k = Iota[round];
		s[0] ^= k & 0x8B;			/* bits 0, 1, 3, 7 */
		s[1] ^= (k<<3)&0x80;		/* bit 15 */
		s[3] ^= (k<<2)&0x80;		/* bit 31 */
		s[7] ^= (k<<1)&0x80;		/* bit 63 */

	}
}

/* ---------------------------------------------------------------------
   32-bit version of Keccak_f(1600)
   ---------------------------------------------------------------------
*/
void Keccak_f_32(uint32_t s[50])
{	uint32_t t[10];
	uint8_t i, j, round, k;

	for(round=0; round<24; ++round)
	{	/* Theta function */
		for(i=0; i<10; ++i)
			t[i] = s[i] ^ s[10+i] ^ s[20+i] ^ s[30+i] ^ s[40+i];
		for(i=0; i<5; ++i)
			for(j=8, k=2; ; j%=10, k=(k+2)%10)
			{	*s++ ^= t[j++] ^ ((t[k]<<1)|(t[k+1]>>31));
				*s++ ^= t[j++] ^ ((t[k+1]<<1)|(t[k]>>31));
				if(j==8) break;
			}
		s -= 50;

		/* Rho function */
		for(i=2; i<50; i+=2)
		{	k = Rho[i>>1] & 0x1f;
			t[0] = (s[i+1] << k) | (s[i] >> (32-k));
			t[1] = (s[i] << k) | (s[i+1] >> (32-k));
			k = Rho[i>>1] >> 5;
			s[i] = t[1-k], s[i+1] = t[k];
		}

		/* Pi function */
		for(i=2, t[0]=s[2], t[1]=s[3]; (j=(Pi[i>>1]<<1))>2; i=j)
			s[i]=s[j], s[i+1]=s[j+1];
		s[i]=t[0], s[i+1]=t[1];

		/* Chi function */
		for(i=0; i<5; ++i, s+=10)
		{	for(j=0; j<10; ++j)
				t[j] = (~s[(j+2)%10]) & s[(j+4)%10];
			for(j=0; j<10; ++j)
				s[j] ^= t[j];
		}
		s -= 50;

		/* Iota function */
		t[0] = Iota[round];
		s[0] ^= (t[0] | (t[0]<<11) | (t[0]<<26)) & 0x8000808B;
		s[1] ^= (t[0]<<25) & 0x80000000;
	}
}

