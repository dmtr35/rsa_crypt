#ifndef FUNC_H
#define FUNC_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <gmp.h>



// generate_rsa_key.c
void generate_rsa_key(int key_size, char *name_file_public, char *name_file_private);
void plus_name_and_size(char *argv[], int argc, int *key_size, char *name_file_public, char *name_file_private);

// rsa_encrypt.c
int encrypt(const char *message, char *name_file_public, int key_size);
int encrypt_message(const char *message, unsigned char *encrypted, EVP_PKEY *public_key, int key_size);


// rsa_decrypt.c
int decrypt(const char *hex_message, char *name_file_private, int key_size);
int decrypt_message(const unsigned char *encrypted, unsigned char *decrypted, EVP_PKEY *private_key , int key_size);
unsigned char *hex_string_to_bytes(const char *hex_string, size_t *out_length);

// extra.c
EVP_PKEY *load_key(char *filename, int is_public);
void print_hex(const unsigned char *data, size_t length);
void print_public_key_info(char *name_file_public);
int get_public_key_size(char *name_file_public);
int get_private_key_size(const char *private_key);

void print_available_params(char *name_file_public);
void hex_to_decimal(const char *hex_str);
void print_help_message();

#endif
