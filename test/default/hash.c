
#define TEST_NAME "hash"
#include "cmptest.h"

int j = 0;

static unsigned char x1[] = "testing\n";
static unsigned char x2[] =
    "The Conscience of a Hacker is a small essay written January 8, 1986 by a "
    "computer security hacker who went by the handle of The Mentor, who "
    "belonged to the 2nd generation of Legion of Doom.";
static unsigned char x3[] = "abc";
static unsigned char x4[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static unsigned char x5[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

/*
 * SHA-256 Test Data
 * #1) 1 byte 0xbd
 *     68325720 aabd7c82 f30f554b 313d0570 c95accbb 7dc4b5aa e11204c0 8ffe732b
 */
static unsigned char x6[] = { 0xbd };

/* #2) 4 bytes 0xc98c8e55
 *     7abc22c0 ae5af26c e93dbb94 433a0e0b 2e119d01 4f8e7f65 bd56c61c cccd9504
 */
static unsigned char x7[] = { 0xc9, 0x8c, 0x8e, 0x55 };

/* #3) 55 bytes of zeros
 *     02779466 cdec1638 11d07881 5c633f21 90141308 1449002f 24aa3e80 f0b88ef7
 */
static unsigned char x8[55] = { 0 };

/* #4) 56 bytes of zeros
 *     d4817aa5 497628e7 c77e6b60 6107042b bba31308 88c5f47a 375e6179 be789fbb
 */
static unsigned char x9[56] = { 0 };

/* #5) 57 bytes of zeros
 *     65a16cb7 861335d5 ace3c607 18b5052e 44660726 da4cd13b b745381b 235a1785
 */
static unsigned char x10[57] = { 0 };

/* #6) 64 bytes of zeros
 *     f5a5fd42 d16a2030 2798ef6e d309979b 43003d23 20d9f0e8 ea9831a9 2759fb4b
 */
static unsigned char x11[64] = { 0 };

/* #7) 1000 bytes of zeros
 *     541b3e9d aa09b20b f85fa273 e5cbd3e8 0185aa4e c298e765 db87742b 70138a53
 */
static unsigned char x12[1000] = { 0 };

/* #8) 1000 bytes of 0x41 ‘A’
 *     c2e68682 3489ced2 017f6059 b8b23931 8b6364f6 dcd835d0 a519105a 1eadd6e4
 */
static unsigned char x13[1000];

/* #9) 1005 bytes of 0x55 ‘U’
 *     f4d62dde c0f3dd90 ea1380fa 16a5ff8d c4c54b21 740650f2 4afc4120 903552b0
 */
static unsigned char x14[1005];

/* #10) 1000000 bytes of zeros
 *      d29751f2 649b32ff 572b5e0a 9f541ea6 60a50f94 ff0beedf b0b692b9 24cc8025
 * #11) 0x20000000 (536870912) bytes of 0x5a ‘Z’
 *      15a1868c 12cc5395 1e182344 277447cd 0979536b adcc512a d24c67e9 b2d4f3dd
 * #12) 0x41000000 (1090519040) bytes of zeros
 *      461c19a9 3bd4344f 9215f5ec 64357090 342bc66b 15a14831 7d276e31 cbc20b53
 * #13) 0x6000003e (1610612798) bytes of 0x42 ‘B’
 *      c23ce8a7 895f4b21 ec0daf37 920ac0a2 62a22004 5a03eb2d fed48ef9 b05aabea
 */

static unsigned char h[crypto_hash_BYTES];

int
main(void)
{
    size_t i;

    printf("x1: %zu\n", (sizeof x1 - 1U) );
    crypto_hash(h, x1, sizeof x1 - 1U);
    for (i = 0; i < crypto_hash_BYTES; ++i) {
        printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x2: %zu\n", (sizeof x2 - 1U) );
    crypto_hash(h, x2, sizeof x2 - 1U);
    for (i = 0; i < crypto_hash_BYTES; ++i) {
        printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x3: %zu\n", (sizeof x3 - 1U) );
    crypto_hash(h, x3, sizeof x3 - 1U);
    for (i = 0; i < crypto_hash_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x5: %zu\n", (sizeof x5 - 1U) );
    crypto_hash(h, x5, sizeof x5 - 1U);
    for (i = 0; i < crypto_hash_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n\n");

    printf("x1: %zu\n", (sizeof x1 - 1U) );
    crypto_hash_sha256(h, x1, sizeof x1 - 1U);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
        printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x2: %zu\n", (sizeof x2 - 1U) );
    crypto_hash_sha256(h, x2, sizeof x2 - 1U);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
        printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x3: %zu\n", (sizeof x3 - 1U) );
    crypto_hash_sha256(h, x3, sizeof x3 - 1U);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x4: %zu\n", (sizeof x4 - 1U) );
    crypto_hash_sha256(h, x4, sizeof x4 - 1U);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x6: %zu\n", (sizeof x6) );
    crypto_hash_sha256(h, x6, sizeof x6);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x7: %zu\n", (sizeof x7) );
    crypto_hash_sha256(h, x7, sizeof x7);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x8: %zu\n", (sizeof x8) );
    crypto_hash_sha256(h, x8, sizeof x8);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x9: %zu\n", (sizeof x9) );
    crypto_hash_sha256(h, x9, sizeof x9);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x10: %zu\n", (sizeof x10) );
    crypto_hash_sha256(h, x10, sizeof x10);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x11: %zu\n", (sizeof x11) );
    crypto_hash_sha256(h, x11, sizeof x11);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    printf("x12: %zu\n", (sizeof x12) );
    crypto_hash_sha256(h, x12, sizeof x12);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    for (j = 0; j < sizeof(x13); j++) {
      x13[j] = 0x41; // Initializing each element separately
    }

    printf("x13: %zu\n", (sizeof x13) );
    crypto_hash_sha256(h, x13, sizeof x13);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    for (j = 0; j < sizeof(x14); j++) {
      x14[j] = 0x55; // Initializing each element separately
    }

    printf("x14: %zu\n", (sizeof x14) );
    crypto_hash_sha256(h, x14, sizeof x14);
    for (i = 0; i < crypto_hash_sha256_BYTES; ++i) {
      printf("%02x", (unsigned int) h[i]);
    }
    printf("\n");

    assert(crypto_hash_bytes() > 0U);
    assert(strcmp(crypto_hash_primitive(), "sha512") == 0);
    assert(crypto_hash_sha256_bytes() > 0U);
    assert(crypto_hash_sha512_bytes() >= crypto_hash_sha256_bytes());
    assert(crypto_hash_sha512_bytes() == crypto_hash_bytes());
    assert(crypto_hash_sha256_statebytes() == sizeof(crypto_hash_sha256_state));
    assert(crypto_hash_sha512_statebytes() == sizeof(crypto_hash_sha512_state));

    return 0;
}