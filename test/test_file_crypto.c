#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/file_crypto.h"

// Helper: compare files
int compare_files(const char *file1, const char *file2)
{
    FILE *f1 = fopen(file1, "rb");
    FILE *f2 = fopen(file2, "rb");
    
    if (!f1 || !f2) {
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return -1;
    }

    fseek(f1, 0, SEEK_END);
    size_t size1 = ftell(f1);
    fseek(f1, 0, SEEK_SET);
    
    fseek(f2, 0, SEEK_END);
    size_t size2 = ftell(f2);
    fseek(f2, 0, SEEK_SET);

    if (size1 != size2) {
        fclose(f1);
        fclose(f2);
        return 1;
    }

    byte buf1[1024], buf2[1024];
    size_t read_size;
    
    while ((read_size = fread(buf1, 1, sizeof(buf1), f1)) > 0) {
        if (fread(buf2, 1, read_size, f2) != read_size) {
            fclose(f1);
            fclose(f2);
            return 1;
        }
        if (memcmp(buf1, buf2, read_size) != 0) {
            fclose(f1);
            fclose(f2);
            return 1;
        }
    }

    fclose(f1);
    fclose(f2);
    return 0;
}

void test_basic_encryption()
{
    printf("\n[Test 1] Basic Encryption and Decryption\n");
    fflush(stdout);
    
    // Create input file
    FILE *f = fopen("test1_input.txt", "wb");
    fprintf(f, "Hello, World! This is a test message.");
    fclose(f);
    printf("  [+] Created input file\n");
    fflush(stdout);
    
    const char *password = "TestPassword123";
    int ret = encrypt_file_HKDF("test1_input.txt", "test1_encrypted.aes", password, strlen(password), 1000);
    if (ret != 0) {
        printf("  [-] Encryption failed: %d\n", ret);
        fflush(stdout);
        remove("test1_input.txt");
        return;
    }
    printf("  [+] Encryption successful\n");
    fflush(stdout);
    
    ret = decrypt_file_HKDF("test1_encrypted.aes", "test1_output.txt", password, strlen(password));
    if (ret != 0) {
        printf("  [-] Decryption failed: %d\n", ret);
        fflush(stdout);
        remove("test1_input.txt");
        remove("test1_encrypted.aes");
        return;
    }
    printf("  [+] Decryption successful\n");
    fflush(stdout);
    
    if (compare_files("test1_input.txt", "test1_output.txt") == 0) {
        printf("TEST PASSED - Files match!\n");
    } else {
        printf("TEST FAILED - Files don't match\n");
    }
    fflush(stdout);
    
    remove("test1_input.txt");
    remove("test1_encrypted.aes");
    remove("test1_output.txt");
}

void test_wrong_password()
{
    printf("\n[Test 2] Wrong Password Protection\n");
    fflush(stdout);
    
    FILE *f = fopen("test2_input.txt", "wb");
    fprintf(f, "Secret data should not be readable");
    fclose(f);
    printf("  [+] Created input file\n");
    fflush(stdout);
    
    const char *correct_pwd = "CorrectPassword";
    const char *wrong_pwd = "WrongPassword";
    
    int ret = encrypt_file_HKDF("test2_input.txt", "test2_encrypted.aes", correct_pwd, strlen(correct_pwd), 1000);
    if (ret != 0) {
        printf("  [-] Encryption failed\n");
        fflush(stdout);
        remove("test2_input.txt");
        return;
    }
    printf("  [+] Encryption successful\n");
    fflush(stdout);
    
    ret = decrypt_file_HKDF("test2_encrypted.aes", "test2_output.txt", wrong_pwd, strlen(wrong_pwd));
    if (ret != 0) {
        printf("Wrong password correctly rejected\n");
        printf("TEST PASSED\n");
    } else {
        if (compare_files("test2_input.txt", "test2_output.txt") != 0) {
            printf("Decrypted data corrupted with wrong password\n");
            printf("TEST PASSED\n");
        } else {
            printf("TEST FAILED - Wrong password still worked\n");
        }
        remove("test2_output.txt");
    }
    fflush(stdout);
    
    remove("test2_input.txt");
    remove("test2_encrypted.aes");
}

void test_binary_data()
{
    printf("\n[Test 3] Binary Data Handling\n");
    fflush(stdout);
    
    // Create binary file with all byte values
    FILE *f = fopen("test3_input.bin", "wb");
    byte binary_data[256];
    for (int i = 0; i < 256; i++) {
        binary_data[i] = (byte)i;
    }
    for (int i = 0; i < 10; i++) {
        fwrite(binary_data, 1, 256, f);
    }
    fclose(f);
    printf("  [+] Created binary test file (2560 bytes)\n");
    fflush(stdout);
    
    const char *password = "BinaryPassword";
    int ret = encrypt_file_HKDF("test3_input.bin", "test3_encrypted.aes", password, strlen(password), 1000);
    if (ret != 0) {
        printf("  [-] Encryption failed\n");
        fflush(stdout);
        remove("test3_input.bin");
        return;
    }
    printf("  [+] Encryption successful\n");
    fflush(stdout);
    
    ret = decrypt_file_HKDF("test3_encrypted.aes", "test3_output.bin", password, strlen(password));
    if (ret != 0) {
        printf("  [-] Decryption failed\n");
        fflush(stdout);
        remove("test3_input.bin");
        remove("test3_encrypted.aes");
        return;
    }
    printf("  [+] Decryption successful\n");
    fflush(stdout);
    
    if (compare_files("test3_input.bin", "test3_output.bin") == 0) {
        printf("TEST PASSED - Binary data preserved\n");
    } else {
        printf("TEST FAILED - Binary data corrupted\n");
    }
    fflush(stdout);
    
    remove("test3_input.bin");
    remove("test3_encrypted.aes");
    remove("test3_output.bin");
}

void test_different_iterations()
{
    printf("\n[Test 4] Different Iteration Counts\n");
    fflush(stdout);
    
    FILE *f = fopen("test4_input.txt", "wb");
    fprintf(f, "Test data for iterations");
    fclose(f);
    printf("  [+] Created input file\n");
    fflush(stdout);
    
    const char *password = "IterationTest";
    size_t iterations[] = {100, 1000, 10000};
    int passed = 0;
    
    for (int i = 0; i < 3; i++) {
        char enc_file[32], out_file[32];
        snprintf(enc_file, sizeof(enc_file), "test4_enc_%zu.aes", iterations[i]);
        snprintf(out_file, sizeof(out_file), "test4_out_%zu.txt", iterations[i]);
        
        printf("  [*] Testing with %zu iterations...\n", iterations[i]);
        fflush(stdout);
        
        int ret = encrypt_file_HKDF("test4_input.txt", enc_file, password, strlen(password), iterations[i]);
        if (ret != 0) {
            printf("    [-] Encryption failed\n");
            fflush(stdout);
            continue;
        }
        
        ret = decrypt_file_HKDF(enc_file, out_file, password, strlen(password));
        if (ret != 0) {
            printf("    [-] Decryption failed\n");
            fflush(stdout);
            remove(enc_file);
            continue;
        }
        
        if (compare_files("test4_input.txt", out_file) == 0) {
            printf("    [+] Iterations %zu: OK\n", iterations[i]);
            passed++;
        } else {
            printf("    [-] Iterations %zu: FAILED\n", iterations[i]);
        }
        fflush(stdout);
        
        remove(enc_file);
        remove(out_file);
    }
    
    if (passed == 3) {
        printf("TEST PASSED - All iterations successful\n");
    } else {
        printf("TEST FAILED - Some iterations failed\n");
    }
    fflush(stdout);
    
    remove("test4_input.txt");
}

int main(void)
{
    printf("========================================\n");
    printf("   File Crypto Encryption/Decryption\n");
    printf("              Test Suite\n");
    printf("========================================\n");
    fflush(stdout);

    test_basic_encryption();
    test_wrong_password();
    test_binary_data();
    test_different_iterations();

    printf("\n========================================\n");
    printf("All tests completed!\n");
    printf("========================================\n");
    fflush(stdout);

    return 0;
}
