#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "AES/AESEncryption.h"
#include "AES/AESDecryption.h"

static void print_hex(const byte *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static int run_roundtrip(const byte *ciperkey, const byte *mackey, const byte *msg, size_t msg_len)
{
    size_t out_cap = msg_len + BLOCK_SIZE + ETM_OVERHEAD + 16;
    byte *out = malloc(out_cap);
    if (!out)
    {
        perror("malloc");
        return 1;
    }

    int out_len = encrypt_etm((byte *)ciperkey, (byte *)mackey,NULL, (byte *)msg, msg_len, out);
    if (out_len <= 0)
    {
        printf("encrypt_etm failed\n");
        free(out);
        return 1;
    }

    // Verify tag appended by encrypt_etm by recomputing HMAC over IV||ciphertext
    byte recomputed_tag[ETM_HMAC_SIZE];
    hmac_sha256((const byte *)mackey, 32, out, out_len - ETM_HMAC_SIZE, recomputed_tag);
    if (memcmp(recomputed_tag, out + out_len - ETM_HMAC_SIZE, ETM_HMAC_SIZE) != 0)
    {
        printf("FAIL: tag mismatch right after encrypt (encryption side)");
        printf("\ncomputed: ");
        print_hex(recomputed_tag, ETM_HMAC_SIZE);
        printf("\nstored  : ");
        print_hex(out + out_len - ETM_HMAC_SIZE, ETM_HMAC_SIZE);
        free(out);
        return 1;
    }

    byte *decrypted = malloc(out_len);
    if (!decrypted)
    {
        perror("malloc");
        free(out);
        return 1;
    }

    int dec_len = decrypt_etm((byte *)ciperkey, (byte *)mackey, out, out_len, decrypted);
    if (dec_len != (int)msg_len)
    {
        printf("FAIL: roundtrip length mismatch: got %d expected %zu\n", dec_len, msg_len);
        free(out);
        free(decrypted);
        return 1;
    }
    if (memcmp(decrypted, msg, msg_len) != 0)
    {
        printf("FAIL: roundtrip content mismatch\n");
        printf("original: ");
        print_hex(msg, msg_len);
        printf("decrypted: ");
        print_hex(decrypted, dec_len);
        free(out);
        free(decrypted);
        return 1;
    }

    free(out);
    free(decrypted);
    return 0;
}

static int run_tamper_checks(const byte *ciperkey, const byte *mackey, const byte *msg, size_t msg_len)
{
    int failures = 0;
    size_t out_cap = msg_len + BLOCK_SIZE + ETM_OVERHEAD + 16;
    byte *out = malloc(out_cap);
    if (!out)
    {
        perror("malloc");
        return 1;
    }

    int out_len = encrypt_etm((byte *)ciperkey, (byte *)mackey,NULL, (byte *)msg, msg_len, out);
    if (out_len <= 0)
    {
        printf("encrypt_etm failed\n");
        free(out);
        return 1;
    }

    // tamper: flip a byte in ciphertext (after IV)
    byte *tam = malloc(out_len);
    memcpy(tam, out, out_len);
    size_t pos = ETM_IV_SIZE + 1; // inside ciphertext
    tam[pos] ^= 0x01;
    byte buf[1024]; // output buffer
    if (decrypt_etm((byte *)ciperkey, (byte *)mackey, tam, out_len, buf) != -1)
    {
        printf("FAIL: tamper in ciphertext not detected\n");
        failures++;
    }

    // tamper: flip iv
    memcpy(tam, out, out_len);
    tam[0] ^= 0x01;
    if (decrypt_etm((byte *)ciperkey, (byte *)mackey, tam, out_len, buf) != -1)
    {
        printf("FAIL: tamper in IV not detected\n");
        failures++;
    }

    // tamper: flip tag (last byte)
    memcpy(tam, out, out_len);
    tam[out_len - 1] ^= 0x01;
    if (decrypt_etm((byte *)ciperkey, (byte *)mackey, tam, out_len, buf) != -1)
    {
        printf("FAIL: tamper in tag not detected\n");
        failures++;
    }

    free(out);
    free(tam);
    return failures;
}

int main(void)
{
    int failures = 0;

    // fixed keys for deterministic testing
    byte ciph_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    byte mac_key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    const char *msg1 = "The quick brown fox jumps over the lazy dog";
    failures += run_roundtrip(ciph_key, mac_key, (const byte *)msg1, strlen(msg1));

    const char *msg2 = ""; // empty message
    failures += run_roundtrip(ciph_key, mac_key, (const byte *)msg2, 0);

    const char *msg3 = "0123456789ABCDEF"; // block-aligned 16 bytes
    failures += run_roundtrip(ciph_key, mac_key, (const byte *)msg3, 16);

    // tamper checks
    failures += run_tamper_checks(ciph_key, mac_key, (const byte *)msg1, strlen(msg1));

    // positive authentication test: encrypt, verify tag, then decrypt
    int auth_ok = 0;

    size_t out_cap = strlen(msg1) + BLOCK_SIZE + ETM_OVERHEAD + 16;
    byte *out = malloc(out_cap);
    int out_len = encrypt_etm((byte *)ciph_key, (byte *)mac_key,NULL, (byte *)msg1, strlen(msg1), out);
    if (out_len > 0)
    {
        byte recomputed[ETM_HMAC_SIZE];
        hmac_sha256(mac_key, 32, out, out_len - ETM_HMAC_SIZE, recomputed);
        if (memcmp(recomputed, out + out_len - ETM_HMAC_SIZE, ETM_HMAC_SIZE) == 0)
        {
            byte *dec = malloc(out_len);
            int dec_len = decrypt_etm((byte *)ciph_key, (byte *)mac_key, out, out_len, dec);
            if (dec_len == (int)strlen(msg1) && memcmp(dec, msg1, dec_len) == 0)
            {
                auth_ok = 1;
            }
            else
            {
                printf("Auth positive test: decrypt failed or content mismatch\n");
            }
            free(dec);
        }
        else
        {
            printf("Auth positive test: tag mismatch after encrypt (unexpected)\n");
        }
    }
    else
    {
        printf("Auth positive test: encrypt_etm failed\n");
    }
    free(out);

    if (auth_ok)
        printf("Auth positive test passed\n");
    else
    {
        printf("Auth positive test failed\n");
        failures++;
    }

    if (failures == 0)
        printf("All EtM tests passed\n");
    else
        printf("Some EtM tests failed (failures=%d)\n", failures);

    return failures;
}
