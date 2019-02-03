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

  unsigned char key[crypto_secretbox_KEYBYTES];
  unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
  if (vcrypto_get_privatekey(key, "dsdfsdfsfougie.io", "hello this is an awesome test") != 0)
    puts("FAILED! privkey");
  if (vcrypto_get_publickey(pubkey, key) != 0)
    puts("FAILED! pubkey");

  // Encrypt a message
  char *msg = "hello world";
  char myenc[vcrypto_encrypt_string_len(strlen(msg))];
  vcrypto_encrypt_string(myenc, key, msg, strlen(msg));

  // Decryption
  int dec_len = vcrypto_decrypt_string_len(myenc, strlen(myenc));
  char dec[dec_len];
  printf("The dec_len is %i\n", dec_len);
  vcrypto_decrypt_string(dec, strlen(msg)+1, key, myenc, strlen(myenc));
  printf("Msg is %s\n", dec);
}
