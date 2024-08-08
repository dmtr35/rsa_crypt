CC = gcc
CFLAGS = -Wall -g -std=c99
LIBS = -lssl -lcrypto -lgmp

# Определение всех объектных файлов
OBJS = rsa_encryptor.o generate_rsa_key.o rsa_decrypt_message.o rsa_encrypt_message.o extra.o

all: rsa_crypt

# Компиляция объекта
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Линковка исполняемого файла
rsa_crypt: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS)
	rm -f $(OBJS)

# Очистка
clean:
	rm -f $(OBJS) rsa_crypt
