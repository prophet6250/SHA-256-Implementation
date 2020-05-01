#ifndef __SHA2__
#define __SHA2__

/* didn't want to include stdint.h for these basic typedefs */
typedef unsigned char          uint8_t;
typedef unsigned short int     uint16_t;
typedef unsigned int           uint32_t;
typedef unsigned long long int uint64_t;

/* shorthand macros for bit operations */
#define SHL(x, n)   (uint32_t)((x) << n)
#define SHR(x, n)   (uint32_t)((x) >> n)
#define ROTR(x, n)  (uint32_t)(((x) >> n) | ((x) << (32 - n)))
#define ADD(x, y)   (((x) + (y)) & 0xFFFFFFFF) /* addition mod 2^32 */
#define SIGMA0(x)   ((ROTR(x, 2)) ^ (ROTR(x, 13)) ^  (ROTR(x, 22)))
#define SIGMA1(x)   ((ROTR(x, 6)) ^ (ROTR(x, 11)) ^  (ROTR(x, 25)))
#define RHO0(x)     ((ROTR(x, 7)) ^ (ROTR(x, 18)) ^  (SHR(x, 3)))
#define RHO1(x)     ((ROTR(x, 17)) ^ (ROTR(x, 19)) ^ (SHR(x, 10)))
#define CH(x, y, z)  (((x) & (y)) ^ ((~x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

void
SHA2_preprocessing(uint8_t *data, const uint32_t hash_size);

void
SHA2_prepare_words(const uint8_t *block, uint32_t *words);

void
SHA2_decoding(const uint32_t *words, uint8_t *output);

void
SHA2_compression(uint8_t *data, uint8_t *output);

#endif