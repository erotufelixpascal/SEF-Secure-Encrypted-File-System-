/*
 * Master key/IV generator. Writes 16 random key bytes followed by 16 random IV
 * bytes. Replace with the lecturer's sample generator if its format differs.
 * Usage: keygen [output file]   (default: master.key)
 */
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "master.key";
    unsigned char buf[32];
    FILE *f;
    int ok;

    if (RAND_bytes(buf, sizeof buf) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        return 1;
    }
    if ((f = fopen(path, "wb")) == NULL) {
        perror(path);
        return 1;
    }
    ok = fwrite(buf, 1, sizeof buf, f) == sizeof buf;
    if (fclose(f) != 0)
        ok = 0;
    OPENSSL_cleanse(buf, sizeof buf);
    if (!ok) {
        fprintf(stderr, "write failed\n");
        return 1;
    }
    printf("wrote %s (16-byte key + 16-byte IV)\n", path);
    return 0;
}
