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
    puts("Sodium cannot init!");
  }
  unsigned char key[crypto_secretbox_KEYBYTES];

  crypto_secretbox_keygen(key);



  char *msg = "Hello world. This is a complete test.\nThis message is so secret you have to be really badass to get it.";
  char myenc[vcrypto_encrypt_string_len(strlen(msg))];
  vcrypto_encrypt_string(myenc, key, msg, strlen(msg));


  VibratoEncryptedObject obj;
  vcrypto_parse_triad(&obj, myenc, strlen(myenc));

  printf("%s\n%s\n%s\n", obj.versiontag, obj.ciphertext64, obj.nonce64);

  vcrypto_free_triad(obj);
}
