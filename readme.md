# Vibrato-Crypto

## To compile:

The whole library is just two files `vibrato-crypto.h` and `vibrato-crypto.c`.

The library depends on `libsodium`.

## API

```c++
int vcrypto_init();

int vcrypto_get_privatekey(unsigned char *privatekey, const unsigned char *email, const char *password);
int vcrypto_get_publickey(unsigned char *publickey, const unsigned char *privatekey);

int vcrypto_encrypt_string_len(const int message_len);
int vcrypto_decrypt_string_len(const unsigned char *encrypted_string, const int encrypted_string_len);

int vcrypto_encrypt_string(char *encrypted,
                           const unsigned char *key,
                           const unsigned char *message, const unsigned long long message_len);

int vcrypto_decrypt_string(unsigned char *decrypted, int decrypted_len,
                           const unsigned char *key,
                           const unsigned char *encrypted_string, const int encrypted_string_len);
```
