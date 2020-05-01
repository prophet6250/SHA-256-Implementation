#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#include "SHA2.h"

void
SHA2_preprocessing(uint8_t *data, const uint32_t hash_size) 
{
	uint64_t data_size = strlen(data);
	int i, j;

	memset(data + data_size, 0x80, 1);
	/* append the sizeof original string at the end of the padded string */
	data[hash_size - 7] = (uint8_t)(data_size);

	for (i = 0, j = 7; i < 8; i++, j--) {
		data[hash_size - 8 + i] = (data_size >> (8*j));
	}
}

void
SHA2_prepare_words(const uint8_t *block, uint32_t *words)
{
	int i, j;

	for (i = 0, j = 0; i < 16; i++, j += 4) {
		words[i] = ((SHL(block[j], 24)) | (SHL(block[j + 1], 16)) | 
			    (SHL(block[j + 2], 8)) | ((block[j + 3])));
	}
	for (i = 16; i < 64; i++) {
		/* progressive mod 2^32 addition to prevent int overflow */
		words[i] = ADD(RHO0(words[i - 15]), RHO1(words[i - 2]));
		words[i] = ADD(words[i], words[i - 7]);
		words[i] = ADD(words[i], words[i - 16]);
	}
}

void
SHA2_decoding(const uint32_t *hash, uint8_t *output)
{
	int i, j;
	for (i = 0, j = 0; i < 8; i++, j += 4) {
		output[j]     = (uint8_t)(hash[i] >> 24);
		output[j + 1] = (uint8_t)(hash[i] >> 16);
		output[j + 2] = (uint8_t)(hash[i] >> 8);
		output[j + 3] = (uint8_t)(hash[i]);
	}
}

/* store the final hash in output buffer */
void
SHA2_compression(uint8_t *data, uint8_t *output)
{
	uint32_t total_blks = (strlen(data) >> 6) + 1, blk_cnt = 0, data_size;

	/* first 32 bits of fractional part of square roots of first 8 primes */
	uint32_t hash[] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	/* first 32 bits of fractional part of cube roots of first 64 primes */
	uint32_t K[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	   	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
	   	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};
	uint32_t words[64];
	
	int i, j;
	uint8_t current_blk[64] = {0},
	        *buffer_blk = malloc(sizeof *buffer_blk * (total_blks << 6));

	strncpy(buffer_blk, data, strlen(data));

	/* step 1: add padding and append size in the end of message */
	SHA2_preprocessing(buffer_blk, (total_blks << 6));

	/* form block of 64 bytes */
	while (blk_cnt < total_blks) {
		memset(current_blk, 0, 64);

		/* copy the current block into the buffer first */
		for (i = (blk_cnt << 6), j = 0; j < 64; i++, j++) {
			current_blk[j] = buffer_blk[i];
		}

		uint32_t a = hash[0],
		         b = hash[1],
		         c = hash[2],
		         d = hash[3],
		         e = hash[4],
		         f = hash[5],
		         g = hash[6],
		         h = hash[7];

		memset(words, 0, 64);
		/* step 2: encode the data into 64 32-bit integers */
		SHA2_prepare_words(current_blk, words);

		/* initialize the current with current hash values */
		
		/* step 3: main hashing process */
		for (i = 0; i < 64; i++) {
			/* progressive addition mod 2^32 */
			uint32_t term1 = ADD(CH(e, f, g), SIGMA1(e));
			term1 = ADD(term1, K[i]);
			term1 = ADD(term1, words[i]);
			term1 = ADD(term1, h);

			uint32_t term2 = ADD(SIGMA0(a), MAJ(a, b, c));

			h = g;
			g = f;
			f = e;
			e = d + term1;
			d = c;
			c = b;
			b = a;
			a = term1 + term2;
		}

		hash[0] = ADD(hash[0], a);
		hash[1] = ADD(hash[1], b);
		hash[2] = ADD(hash[2], c);
		hash[3] = ADD(hash[3], d);
		hash[4] = ADD(hash[4], e);
		hash[5] = ADD(hash[5], f);
		hash[6] = ADD(hash[6], g);
		hash[7] = ADD(hash[7], h);

		blk_cnt += 1;
	}
	/* step 4: decode the words, put them into the output buffer */
	SHA2_decoding(hash, output);
}
