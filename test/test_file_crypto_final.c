#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/file_crypto.h"

size_t get_file_size(const char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f) return 0;
    
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fclose(f);
    return size;
}

int main(void)
{
    printf("=== File Crypto Test (Debug 5) ===\n");
    fflush(stdout);

    // Create a simple test file
    FILE *f = fopen("testinput5.txt", "wb");
    fprintf(f, "Hello World!");
    fclose(f);
    printf("[+] Created test input file\n");
    fflush(stdout);

    const char *password = "TestPassword";
    size_t pass_len = strlen(password);

    printf("[*] Starting encryption (iterations=1000)...\n");
    fflush(stdout);

    int ret = encrypt_file_password("testinput5.txt", "testoutput5.aes", password, pass_len, 1000);

    printf("[*] Encryption completed with return code: %d\n", ret);
    fflush(stdout);

    if (ret == 0) {
        printf("[+] File encrypted successfully\n");
        
        printf("[*] Starting decryption...\n");
        fflush(stdout);

        ret = decrypt_file_password("testoutput5.aes", "testoutput5.txt", password, pass_len);
        printf("[*] Decryption completed with return code: %d\n", ret);
        fflush(stdout);

        if (ret == 0) {
            printf("[+] File decrypted successfully\n");
        } else {
            printf("[-] Decryption failed\n");
        }
    } else {
        printf("[-] Encryption failed\n");
    }

    return 0;
}
