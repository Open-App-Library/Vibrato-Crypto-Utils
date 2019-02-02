#ifndef VIBRATO_CRYPTO_H
#define VIBRATO_CRYPTO_H

#define VCRYPTO_VERSIONTAG "vcrypto-0-0-1"
#define VCRYPTO_VERSIONTAG_LEN 13

typedef struct {
  char *versiontag;
  char *ciphertext64;
  char *nonce64;
} VibratoEncryptedObject;

int vcrypto_init();

int vcrypto_encrypt_string_len(const int message_len);
int vcrypto_decrypt_string_len(char *encrypted_string, const int encrypted_string_len);

int vcrypto_encrypt_string(char *encrypted,
                           const unsigned char *key,
                           const unsigned char *message, const unsigned long long message_len);

int vcrypto_decrypt_string(unsigned char *decrypted, int decrypted_len,
                           const unsigned char *key,
                           const unsigned char *encrypted_string, const int encrypted_string_len);

int vcrypto_parse_triad(VibratoEncryptedObject *obj, const unsigned char *triad, const int triad_len);

void vcrypto_free_triad(VibratoEncryptedObject obj);

#endif
