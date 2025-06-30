#ifndef CRYPTO_GPGME_H
#define CRYPTO_GPGME_H
void *encrypt_with_passphrase (size_t *res_size, const void *data, size_t size,
                         const char *passphrase, GError **error);

void *decrypt_with_passphrase (size_t *res_size, const void *data, size_t size,
                         const char *passphrase, GError **error);
#endif
#ifndef CRYPTO_GPGME_H
#define CRYPTO_GPGME_H
void *encrypt_with_passphrase (size_t *res_size, const void *data, size_t size,
                         const char *passphrase, GError **error);

void *decrypt_with_passphrase (size_t *res_size, const void *data, size_t size,
                         const char *passphrase, GError **error);
#endif
