#include "./header.h"



// Функция для шифрования сообщения
int encrypt_message(const char *message, unsigned char *encrypted, EVP_PKEY *public_key, int key_size)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    size_t encrypted_len = key_size / 8;
    if (EVP_PKEY_encrypt(ctx, encrypted, &encrypted_len, (unsigned char*)message, strlen(message) + 1) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return (int)encrypted_len;
}


int encrypt(const char *message, char *name_file_public, int key_size)
{
    // Инициализация библиотеки OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Загрузка ключа
    EVP_PKEY *public_key = load_key(name_file_public, 1);

    if (public_key == NULL) {
        fprintf(stderr, "Failed to load RSA public key.\n");
        return 1;
    }

    unsigned char encrypted[key_size / 8];

    // Шифрование сообщения
    int encrypted_length = encrypt_message(message, encrypted, public_key, key_size);
    if (encrypted_length == -1) {
        fprintf(stderr, "Encryption failed.\n");
        return 1;
    }

    printf("Encrypted message length: %d\n", encrypted_length);

    // Вывод зашифрованного сообщения в шестнадцатеричном формате
    printf("Encrypted message (hex): ");
    print_hex(encrypted, encrypted_length);
    printf("\n");

    // Очистка
    EVP_PKEY_free(public_key);
    
    // Завершение работы библиотеки OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}