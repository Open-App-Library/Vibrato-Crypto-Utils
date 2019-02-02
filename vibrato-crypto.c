#include "vibrato-crypto.h"
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <sodium.h>

#define ENCRYPTED_LEN_FROM_B64(b64_ciphertext_len, b64_nonce_len) (VCRYPTO_VERSIONTAG_LEN+1 + b64_ciphertext_len + b64_nonce_len)

#define VCRYPTO_DEBUG
#ifdef VCRYPTO_DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( 0 )
#else
#define DEBUG_PRINT(...) do{ } while ( 0 )
#endif

int vcrypto_init()
{
  return sodium_init();
}

int vcrypto_encrypt_string_len(const int message_len)
{
  int  b64_ciphertext_len = sodium_base64_encoded_len(crypto_secretbox_MACBYTES + message_len,
                                                      sodium_base64_VARIANT_ORIGINAL);
  int  b64_nonce_len = sodium_base64_encoded_len(crypto_secretbox_NONCEBYTES,
                                                 sodium_base64_VARIANT_ORIGINAL);
  return ENCRYPTED_LEN_FROM_B64(b64_ciphertext_len, b64_nonce_len);
}

int vcrypto_encrypt_string(char *encrypted,
                           const unsigned char *key,
                           const unsigned char *message, const unsigned long long message_len)
{
  // Define our ciphertext variable
  int ciphertext_len = crypto_secretbox_MACBYTES + message_len;
  unsigned char ciphertext[ciphertext_len];

  // Create our nonce and fill it with random bytes
  int nonce_len = crypto_secretbox_NONCEBYTES;
  unsigned char nonce[nonce_len];
  randombytes_buf(nonce, sizeof nonce);

  int status=0;
  status = crypto_secretbox_easy(ciphertext, message, message_len, nonce, key);
  if (status == -1) {
    DEBUG_PRINT("Error encrypting message.");
    return status;
  }

  // Converting the ciphertext to base64
  int  b64_ciphertext_len = sodium_base64_encoded_len(ciphertext_len, sodium_base64_VARIANT_ORIGINAL);
  char b64_ciphertext[b64_ciphertext_len];
  sodium_bin2base64(b64_ciphertext, b64_ciphertext_len, ciphertext, ciphertext_len, sodium_base64_VARIANT_ORIGINAL);

  // Converting the nonce to base64
  int  b64_nonce_len = sodium_base64_encoded_len(nonce_len, sodium_base64_VARIANT_ORIGINAL);
  char b64_nonce[b64_nonce_len];
  sodium_bin2base64(b64_nonce, b64_nonce_len, nonce, nonce_len, sodium_base64_VARIANT_ORIGINAL);

  // Creating the return string
  // It is in the format of CIPHERTEXT.NONCE - ie. Separated by a period
  int return_string_len = ENCRYPTED_LEN_FROM_B64(b64_ciphertext_len, b64_nonce_len);
  char return_string[return_string_len];

  strcat(return_string, VCRYPTO_VERSIONTAG);
  strcat(return_string, ".");
  strcat(return_string, b64_ciphertext);
  strcat(return_string, ".");
  strcat(return_string, b64_nonce);

  strcpy(encrypted, return_string);

  return 0;
}

int base64_decoded_length(int b64_len)
{
  return 3 * ceil(b64_len / 4.0) + 1;
}

int base64_to_bin(unsigned char *bin, int bin_len, char *b64, int b64_len)
{
  return sodium_base642bin(bin, bin_len, b64, b64_len, NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
}

int vcrypto_decrypt_string(char *decrypted,
                           const unsigned char *key,
                           const unsigned char *encrypted_string, const int encrypted_string_len)
{
  VibratoEncryptedObject obj;
  int status;
  status = vcrypto_parse_triad(&obj, encrypted_string, encrypted_string_len);
  if (status == -1) {
    DEBUG_PRINT("Failed to parse triad.");
    return -1;
  }

  int ciphertext64_len = strlen(obj.ciphertext64);
  int ciphertext_len = base64_decoded_length(ciphertext64_len);
  char ciphertext[ciphertext_len];

  status = base64_to_bin(ciphertext, ciphertext_len, obj.ciphertext64, ciphertext64_len);
  if (!status) {
    DEBUG_PRINT("Failed to parse ciphertext base64.");
    return -1;
  }


  printf("The success is %i\n", success);

  //  crypto_secretbox_open_easy(decrypted, , CIPHERTEXT_LEN, nonce, key)
  return 0;
}

int periodCount(char *str, int str_len)
{
  int count = 0;
  for (int i=0; i<str_len; i++) {
    if (str[i] == '.') count++;
  }
  return count;
}

int vcrypto_parse_triad(VibratoEncryptedObject *obj, const unsigned char *triad, const int triad_len)
{
  // First make sure we have two periods
  int periodCount = 0;
  for (int i = 0; i < triad_len; i++)
    if (triad[i] == '.') periodCount++;
  if (periodCount != 2) {
    DEBUG_PRINT("Encrypted triad has more than two periods.");
    return -1;
  }

  int curSection = 0;       // The current section we are working on.
  int start = 0;  // The starting position of the section.
  for (int i = 0; i < triad_len; i++) {
    char c = triad[i];
    if (c == '.' || i == triad_len-1) {
      if (i == triad_len-1)
        i++;

      int end = i-1;

      int str_len = end-start+1; // Full length
      char str[str_len+1];

      memcpy(str, &triad[start], str_len);
      str[str_len] = '\0';

      switch (curSection) {
      case 0: // Version Tag
        obj->versiontag = malloc(str_len+1);
        strcpy(obj->versiontag, str);
        break;
      case 1: // Ciphertext
        obj->ciphertext64 = malloc(str_len+1);
        strcpy(obj->ciphertext64, str);
        break;
      case 2: // nonce
        obj->nonce64 = malloc(str_len+1);
        strcpy(obj->nonce64, str);
        break;
      }

      curSection++;
      start = i+1;
    }
  }

  return 0;
}

void vcrypto_free_triad(VibratoEncryptedObject obj)
{
  free(obj.versiontag);
  free(obj.ciphertext64);
  free(obj.nonce64);
}
