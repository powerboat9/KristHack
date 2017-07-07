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
        return NULL;
    } else {
        ret = malloc(len * 2);
        for (int i = 0; i < len; i++) {
            ret[i * 2] = CH2HXPRT((bytes[i] & 0xf0) / 16);
            ret[i * 2 + 1] = CH2HXPRT(bytes[i] & 0x0f);
        }
        return ret;
    }
}

char hex2bytes(char *in) { /* Should malfunction with non-hex chars :P */
    return ((in[0] > 57) ? (in[0] - 87) : (in[0] - 48)) * 16 + ((in[1] > 57) ? (in[1] - 87) : (in[1] - 48));
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

char *checkPrivKey(char *privKey, char *pubKey) { /* assumes length, 68 chars (64 byte hexcode hash, 4 chars "-000") */
    if ((pubKey != NULL) && (pubKey[0] != 'k')) {
        return NULL;
    }
    sha256_init(&c);
    char out[32];
    char *out2;
    /* Hashes privKey twice */
    sha256_update(&c, privKey, 68);
    sha256_finalize(&c, out);
    out2 = bytes2hex(out, 32);
    sha256_init(&c);
    sha256_update(&c, out2, 64);
    free(out2);
    sha256_finalize(&c, out);
    out2 = bytes2hex(out);
    /* Generates "protein" */
    char protein[18];
    for (int i = 0; i < 9; i++) {
        protein[i * 2] = out2[0];
        protein[i * 2 + 1] = out2[1];
        for (int j = 0; j < 2; j++) {
            sha256_init(&c);
            sha256_update(&c, out2, 64);
            free(out2);
            sha256_finalize(&c, out);
            out2 = bytes2hex(out, 32);
        }
    }
    /* Does scrambly-stuff */
    short hasDone = 0x01ff;
    int n = 0;
    char address[10];
    address[0] = 'k';
    while (n < 9) {
        int link = hex2bytes(out2 + n * 2) % 9;
        if (hasDone & (2 ^ link)) {
            hasDone &= ~(2 ^ link);
            address[n + 1] = pubKeyCharMap[hex2bytes(protein + link * 2)];
            if (address[n + 1] != pubKey[n + 1]) {
                free(out2);
                return NULL;
            }
            n = n + 1;
        } else {
            sha256_init(&c);
            sha256_update(&c, out2, 64);
            free(out2);
            sha256_finalize(&c, out);
            out2 = bytes2hex(out, 32);
        }
    }
    free(out2);
    return address;
}
