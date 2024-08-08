#include "./header.h"


// Функция для расшифрования сообщения
int decrypt_message(const unsigned char *encrypted, unsigned char *decrypted, EVP_PKEY *private_key , int key_size) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    size_t decrypted_len = key_size / 8;
    if (EVP_PKEY_decrypt(ctx, decrypted, &decrypted_len, encrypted, key_size / 8) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return (int)decrypted_len;
}


// Функция для преобразования шестнадцатеричной строки в массив байтов
unsigned char *hex_string_to_bytes(const char *hex_string, size_t *out_length) {
    size_t length = strlen(hex_string) / 2;
    unsigned char *bytes = (unsigned char *)malloc(length);
    if (!bytes) {
        perror("Unable to allocate memory");
        return NULL;
    }

    for (size_t i = 0; i < length; ++i) {
        sscanf(hex_string + 2 * i, "%2hhx", &bytes[i]);
    }

    *out_length = length;
    return bytes;
}

int decrypt(const char *hex_message, char *name_file_private, int key_size)
{
    size_t encrypted_length;

    // Инициализация библиотеки OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Загрузка ключей
    EVP_PKEY *private_key = load_key(name_file_private, 0);

    if (private_key == NULL) {
        fprintf(stderr, "Failed to load RSA keys.\n");
        return 1;
    }

    // Исходное сообщение
    unsigned char decrypted[key_size / 8];
    unsigned char *encrypted = hex_string_to_bytes(hex_message, &encrypted_length);


    // Расшифрование сообщения
    int decrypted_length = decrypt_message(encrypted, decrypted, private_key, key_size);
    if (decrypted_length == -1) {
        fprintf(stderr, "Decryption failed.\n");
        return 1;
    }
    decrypted[decrypted_length] = '\0'; // Null-terminate the decrypted message
    printf("Decrypted message: %s\n\n", decrypted);

    // Очистка
    EVP_PKEY_free(private_key);
    
    // Завершение работы библиотеки OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
