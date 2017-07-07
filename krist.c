#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sha256.c"

SHA_CTX c;
SHA_CTX pass2privTemplate;

char CHR2HXPRT(char n) {
    return (n > 9) ? (n + 87) : (n + 48);
}

char *bytes2hex(char *bytes, unsigned int len) { /* does not give you string with \00 */
    char *ret;
    if (len == 0) {
        ret = malloc(1);
        *ret = '\00';
    } else {
        ret = malloc(len * 2 + 1);
        for (int i = 0; i < len; i++) {
            ret[i * 2 + 1] = CH2HXPRT((bytes[i] & 0xf0) / 16);
            ret[i * 2 + 2] = CH2HXPRT(bytes[i] & 0x0f);
        }
        return ret;
    }
}

void pass2privInit() {
    sha256_init(&pass2privTemplate);
    sha256_update(&pass2privTemplate, "KRISTWALLET", 11);
}

char *pass2priv(char *pass, char *str, char final) {
    memcpy(&c, &pass2privTemplate, sizeof(c));
    sha256_update(&c, pass, strlen(pass));
    char out[32];
    sha256_finalize(&c, out)
    char *ret = realloc(bytes2hex(out, 32), final ? 68 : 69);
    ret[64] = '-';
    ret[65] = '0';
    ret[66] = '0';
    ret[67] = '0';
    if (!final) {
        ret[68] = 0;
        return ret;
    } else {
        sha256_init(&c);
        sha256_update(&c, ret, 68);
        sha256_finalize(&c, out);
        free(ret);
        ret = realloc(bytes2hex(out, 5), 11);
        ret[10] = 0;
        return ret;
    }
}

char pubKeyCharMap[256];

void num2pubKeyCharInit() {
    int n = 47;
    for (int i = 0; i < 256; i++) {
        if ((i % 7) == 0) {
            n = n + 1;
            if (n == 58) {
                n = 97;
            }
        }
        pubKeyCharMap[i] = n;
    }
}

char *checkPrivKey(char *privKey, char *pubKey) { /* assumes length, 69 chars (64 byte hexcode hash, 5 chars "-000\x00") */
    /* TODO: find lua code when wifi is avalible */
}
