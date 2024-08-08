#include "./header.h"


void generate_rsa_key(int key_size, char *name_file_public, char *name_file_private) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    // Инициализация библиотеки OpenSSL
    OpenSSL_add_all_algorithms();

    // Создание контекста для генерации ключей
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return;
    }

    // Инициализация контекста для генерации ключей
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Установка размера ключа
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0) {
        fprintf(stderr, "Failed to set key size\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Генерация ключей
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Запись закрытого ключа в файл
    FILE *private_key_file = fopen(name_file_private, "wb");
    if (!private_key_file) {
        fprintf(stderr, "Failed to open private key file\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    PEM_write_PrivateKey(private_key_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    // Запись открытого ключа в файл
    FILE *public_key_file = fopen(name_file_public, "wb");
    if (!public_key_file) {
        fprintf(stderr, "Failed to open public key file\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    PEM_write_PUBKEY(public_key_file, pkey);
    fclose(public_key_file);

    printf("Keys have been successfully created and saved.\n\n");

    // Освобождение ресурсов
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}