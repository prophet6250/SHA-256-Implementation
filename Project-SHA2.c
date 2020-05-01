#include <stdio.h>
#include "SHA2.h"

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
