#include "./header.h"

// Функция для загрузки ключей из PEM файлов
EVP_PKEY *load_key(char *filename, int is_public)
{
    FILE *key_file = fopen(filename, "r");
    if (key_file == NULL) {
        perror("Unable to open key file");
        return NULL;
    }
    
    EVP_PKEY *key = NULL;
    if (is_public) {
        key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    } else {
        key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    }
    
    fclose(key_file);
    return key;
}



// Функция для вывода данных в шестнадцатеричном формате
void print_hex(const unsigned char *data, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}


int get_public_key_size(char *name_file_public)
{
    EVP_PKEY *public_key = load_key(name_file_public, 1);
    if (public_key == NULL) {
        fprintf(stderr, "Failed to load public key\n");
        return -1; // Ошибка
    }

    // Создание контекста для получения параметров
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
        EVP_PKEY_free(public_key);
        return -1; // Ошибка
    }

    // Получение битовой длины ключа
    int key_bits = EVP_PKEY_bits(public_key);
    if (key_bits <= 0) {
        fprintf(stderr, "Failed to get key bits\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return -1; // Ошибка
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);

    return key_bits;
}

int get_private_key_size(const char *private_key) {
    EVP_PKEY *key = NULL;
    FILE *file = fopen(private_key, "r");
    if (file == NULL) {
        perror("Unable to open key file");
        return -1;
    }

    // Загрузка приватного ключа из файла
    key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);

    if (key == NULL) {
        fprintf(stderr, "Failed to read private key\n");
        return -1;
    }

    // Получение размера ключа
    int key_size = EVP_PKEY_bits(key);
    EVP_PKEY_free(key);

    return key_size;
}


void print_public_key_info(char *name_file_public)
{
    EVP_PKEY *public_key = load_key(name_file_public, 1);
    if (public_key == NULL) {
        fprintf(stderr, "Failed to load public key\n");
        return;
    }

    // Получение битовой длины ключа
    int key_bits = EVP_PKEY_bits(public_key);
    if (key_bits <= 0) {
        fprintf(stderr, "Failed to get key bits\n");
        EVP_PKEY_free(public_key);
        return;
    }

    // Печать битовой длины ключа
    printf("Public-Key: (%d bit)\n\n", key_bits);

    // Инициализация параметров для извлечения
    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;
    // Получение модуля
    if (!EVP_PKEY_get_bn_param(public_key, "n", &modulus)) {
        fprintf(stderr, "Failed to get modulus\n");
        EVP_PKEY_free(public_key);
        return;
    }

    // Получение экспоненты
    if (!EVP_PKEY_get_bn_param(public_key, "e", &exponent)) {
        fprintf(stderr, "Failed to get exponent\n");
        BN_free(modulus);
        EVP_PKEY_free(public_key);
        return;
    }

    // Печать модуля
    if (modulus != NULL) {
        char *modulus_hex = BN_bn2hex(modulus);
        if (modulus_hex != NULL) {
            printf("Modulus HEX: %s\n\n", modulus_hex);
            hex_to_decimal(modulus_hex);
            OPENSSL_free(modulus_hex);
        } else {
            fprintf(stderr, "Failed to convert modulus to hex\n");
        }
        BN_free(modulus);
    } else {
        fprintf(stderr, "Modulus parameter is not available\n");
    }

    // Печать экспоненты
    if (exponent != NULL) {
        // Преобразование экспоненты в целое число
        char *exponent_hex = BN_bn2hex(exponent);
        if (exponent_hex != NULL) {
            // Преобразование из шестнадцатеричного формата в целое
            char *endptr;
            long int exp_value = strtol(exponent_hex, &endptr, 16);
            
            if (*endptr == '\0') {
                printf("Exponent: %ld (0x%s)\n\n", exp_value, exponent_hex);
            } else {
                printf("Exponent: %s (0x%s)\n\n", exponent_hex, exponent_hex);
            }
            
            OPENSSL_free(exponent_hex);
        } else {
            fprintf(stderr, "Failed to convert exponent to hex\n");
        }
        BN_free(exponent);
    } else {
        fprintf(stderr, "Exponent parameter is not available\n");
    }

    // Очистка
    EVP_PKEY_free(public_key);
}


void hex_to_decimal(const char *hex_str)
{
    // Создаем переменную для хранения числа
    mpz_t decimal_value;

    // Инициализируем переменную
    mpz_init(decimal_value);

    // Преобразуем шестнадцатеричную строку в десятичное число
    if (mpz_set_str(decimal_value, hex_str, 16) != 0) {
        fprintf(stderr, "Failed to convert hex string to decimal\n");
        mpz_clear(decimal_value);
        return;
    }

    // Печатаем десятичное значение
    gmp_printf("Modulus DEC: %Zd\n\n", decimal_value);

    // Освобождаем память
    mpz_clear(decimal_value);
}


void print_help_message() {
    printf("./rsa_crypt                                      - Create default keys for 2048 bit\n");
    printf("./rsa_crypt -e message                           - encrypt message\n");
    printf("./rsa_crypt -d crypto-message                    - decrypt message\n");
    printf("./rsa_crypt -i                                   - info\n");
    printf("./rsa_crypt -h                                   - help\n");
    printf("\n");
    printf("./rsa_crypt -s size_key                          - If you want to specify your key size\n");
    printf("./rsa_crypt -n name_public_key name_private_key  - If you want to specify your own file names when creating keys\n");
    printf("./rsa_crypt -i                                   - public key information\n");
    printf("./rsa_crypt -h                                   - help\n");
    printf("\n");
    printf("Examples:\n");
    printf("    ./rsa_crypt -s 512 -n my_pub.pem my_priv.pem\n");
    printf("    ./rsa_crypt -e hello_world -n my_pub.pem\n");
    printf("    ./rsa_crypt -d 20CE458CE323F9387494C96D1B5711CD2A313A... -n my_priv.pem\n");
    printf("\n");
    printf("Default (2048bit):\n");
    printf("    ./rsa_crypt\n");
    printf("    ./rsa_crypt -e \"hello  world\"\n");
    printf("    ./rsa_crypt -d 11E63C2202E572671446FEF08C270BEBDB2861F...\n");
    printf("\n");
    printf("Info about public key:\n");
    printf("    ./rsa_crypt -i\n");
    printf("        - Public-Key: (2048 bit)\n");
    printf("        - Modulus HEX: D54212E86BDC9A642A4A527EA267...\n");
    printf("        - Modulus DEC: 269213411919841670691106985814...\n");
    printf("        - Exponent: 65537 (0x010001)\n");
    printf("\n");
}

