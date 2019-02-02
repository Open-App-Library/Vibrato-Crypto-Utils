#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "vibrato-crypto.h"

#define MESSAGE ((const unsigned char *) "I like awesome")
#define MESSAGE_LEN 14
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

int main()
{
  if (vcrypto_init() < 0) {
    puts("vcrypto cannot init!");
  }

  // Create a random key
  unsigned char key[crypto_secretbox_KEYBYTES];
  crypto_secretbox_keygen(key);

  // Encrypt a message
  char *msg = "Hello world.";
  char myenc[vcrypto_encrypt_string_len(strlen(msg))];
  vcrypto_encrypt_string(myenc, key, msg, strlen(msg));

  // Decryption
  char dec[strlen(msg)];
  vcrypto_decrypt_string(dec, key, myenc, strlen(myenc));
  printf("Msg is %s\n", dec);
}
