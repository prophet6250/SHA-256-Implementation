#include <stdio.h>

typedef unsigned char uint8_t;
typedef unsigned int  uint32_t;

/* external function declaration */
extern void SHA2_compression(uint8_t [], uint8_t[]); 

int main(int argc, char *argv[])
{
	uint8_t output[32];
	SHA2_compression(argv[1], output);

	int i = 0;
	while (i < 32) {
		printf("%x", output[i]);
		i += 1;
	}
	printf("\n");
	return 0;
}
