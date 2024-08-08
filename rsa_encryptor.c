#include "./header.h"


void plus_name_and_size(char *argv[], int argc, int *key_size, char *name_file_public, char *name_file_private) {
    for (int i = 1; i < argc; ++i) {
        if (strstr(argv[i], "-s") != NULL) {
            if (i+1 <= argc) {
                *key_size = atoi(argv[i+1]);
                if (*key_size < 512) {
                    fprintf(stderr, "Key size must be at least 512 bits\n");
                    exit(EXIT_FAILURE);
                }
            } else {
                fprintf(stderr, "No value provided for -s\n");
                exit(EXIT_FAILURE);
            }
        } else if (strstr(argv[i], "-e") != NULL || strstr(argv[i], "-d") != NULL) {
            for (int j = 1; j < argc; ++j) {
                if (strstr(argv[j], "-n") != NULL) {
                    if (j+1 <= argc) {
                        strstr(argv[i], "-e") != NULL ? strcpy(name_file_public, argv[j + 1]) : strcpy(name_file_private, argv[j + 1]);
                    } else {
                        fprintf(stderr, "No value provided for -n\n");
                        exit(EXIT_FAILURE);
                    }
                }
            }
        } else if (strstr(argv[i], "-n") != NULL) {
            for (int k = 1; k < argc; ++k) {
                if (strstr(argv[k], "-e") != NULL || strstr(argv[k], "-d") != NULL) {
                    goto exit;
                }
            }
            if (i+2 <= argc) {
                strcpy(name_file_public, argv[i + 1]);
                strcpy(name_file_private, argv[i + 2]);
            } else {
                fprintf(stderr, "No value provided for -n\n");
                exit(EXIT_FAILURE);
            }
            exit:
        }
    }
}


int main(int argc, char *argv[])
{
    int key_size = 4096;
    char name_file_public[32] = "public_key.pem";
    char name_file_private[32] = "private_key.pem";

    if (argc < 2) {
        generate_rsa_key(key_size, name_file_public, name_file_private);
        return 0;
    }

    if (argc != 1 && !((strstr(argv[1], "-e") != NULL || strstr(argv[1], "-d") != NULL) && argc == 3)) {
        plus_name_and_size(argv, argc, &key_size, name_file_public, name_file_private);
    }

    if (strstr(argv[1], "-e") != NULL) {
        key_size = get_public_key_size(name_file_public);
        encrypt(argv[2], name_file_public, key_size);
    } else if (strstr(argv[1], "-d") != NULL) {
        key_size = get_private_key_size(name_file_private);
        decrypt(argv[2], name_file_private, key_size);
    } else if (strstr(argv[1], "-i") != NULL) {
        print_public_key_info(name_file_public);
    } else if (strstr(argv[1], "-h") != NULL) {
        print_help_message();
    } else {
        generate_rsa_key(key_size, name_file_public, name_file_private);
    }

    return 0;
}


