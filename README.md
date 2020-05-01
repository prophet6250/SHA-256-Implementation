# SHA-256-Implementation
This is my implementation of the SHA-256 cryptographic hashing algorithm.

Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 2^32

Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63

Note 3: The compression function uses 8 working variables, a through h

Note 4: Big-endian convention is used when expressing the constants in this pseudocode, and when parsing message block data from bytes to words, for example, the first word of the input message "abc" after padding is 0x61626380

Note 5: The answers may not (most probably) match with the online SHA-256 tools. So, **this is by no means a standard and perfect implementation of the algorithm**.

## Compilation And Usage
compile both the source files using:

`gcc Project-SHA2.c SHA2.c -o SHA2`

Run the executable, supplying a string to hash (size of string should be less than 2^64 - 1) using the command:

`./SHA2 <enter your string here>`

## Resources Used
1. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
2. https://en.wikipedia.org/wiki/SHA-2#Implementations
3. http://homepage.cs.uiowa.edu/~jones/bcd/mod.shtml
