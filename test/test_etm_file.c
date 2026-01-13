#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "AES/AESEncryption.h"
#include "AES/AESDecryption.h"

static int files_equal(const char *a, const char *b) {
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); return 0; }
    fseek(fa, 0, SEEK_END); long la = ftell(fa); fseek(fa, 0, SEEK_SET);
    fseek(fb, 0, SEEK_END); long lb = ftell(fb); fseek(fb, 0, SEEK_SET);
    if (la != lb) { fclose(fa); fclose(fb); return 0; }
    int ok = 1;
    for (long i = 0; i < la; i++) {
        int ca = fgetc(fa);
        int cb = fgetc(fb);
        if (ca != cb) { ok = 0; break; }
    }
    fclose(fa); fclose(fb);
    return ok;
}

int main(void) {
    byte ciph_key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    byte mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = (byte)i;

    const char *plain = "sample_plain.txt";
    const char *enc = "tmp_etm_encrypted.aes";
    const char *dec = "tmp_etm_decrypted.txt";

    if (encrypt_file_etm(plain, enc, ciph_key, mac_key) != 0) {
        printf("encrypt_file_etm failed\n");
        return 1;
    }
    printf("File encrypted to %s\n", enc);

    int dlen = decrypt_file_etm(enc, dec, ciph_key, mac_key);
    if (dlen < 0) {
        printf("decrypt_file_etm failed\n");
        return 1;
    }
    printf("File decrypted to %s (len=%d)\n", dec, dlen);

    if (files_equal(plain, dec)) {
        printf("Roundtrip file comparison: PASS\n");
    } else {
        printf("Roundtrip file comparison: FAIL\n");
        return 1;
    }

    // Tamper test: flip one byte in encrypted file and expect decryption failure
    FILE *f = fopen(enc, "rb+");
    if (!f) { printf("Failed to open encrypted file for tamper test\n"); return 1; }
    // flip a byte inside ciphertext (after IV)
    fseek(f, ETM_IV_SIZE + 1, SEEK_SET);
    int b = fgetc(f);
    if (b == EOF) { fclose(f); printf("Encrypted file too small for tamper test\n"); return 1; }
    fseek(f, ETM_IV_SIZE + 1, SEEK_SET);
    fputc(b ^ 0x01, f);
    fclose(f);

    int d2 = decrypt_file_etm(enc, "AES/tmp_etm_decrypted_tampered.txt", ciph_key, mac_key);
    if (d2 < 0) {
        printf("Tamper detection: PASS (decryption failed as expected)\n");
    } else {
        printf("Tamper detection: FAIL (decryption succeeded unexpectedly)\n");
        return 1;
    }

    return 0;
}
