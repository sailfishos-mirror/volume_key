#ifndef SQME_H
#define SQME_H

#include <stddef.h>
#include <glib.h>

typedef enum {
    SQGPGME_ERR_NO_ERROR = 0,
    SQGPGME_ERR_GENERAL = 1,
    SQGPGME_ERR_ENOMEM = 2,
    SQGPGME_ERR_CANCELED = 3,
    SQGPGME_ERR_BAD_PASSPHRASE = 4,
    SQGPGME_ERR_SYSTEM = 5
} sqme_error_t;

typedef struct _sqme_ctx sqme_ctx_t;
typedef struct _sqme_data sqme_data_t;

// Error domain for sqme
GQuark sqme_error_quark(void);
#define SQGPGME_ERROR (sqme_error_quark())

sqme_error_t sqme_new(sqme_ctx_t **ctx);
void sqme_release(sqme_ctx_t *ctx);
sqme_error_t sqme_set_passphrase(sqme_ctx_t *ctx, const char *passphrase);

sqme_error_t sqme_data_new_from_mem(sqme_data_t **data, const void *buf, size_t size, int copy);
sqme_error_t sqme_data_new(sqme_data_t **data);
void sqme_data_release(sqme_data_t *data);
void *sqme_data_release_and_get_mem(sqme_data_t *data, size_t *size);

sqme_error_t sqme_op_encrypt(sqme_ctx_t *ctx, sqme_data_t *in, sqme_data_t *out, GError **error);
sqme_error_t sqme_op_decrypt(sqme_ctx_t *ctx, sqme_data_t *in, sqme_data_t *out, GError **error);

const char *sqme_strerror(sqme_error_t err);
void sqme_set_error(GError **error, sqme_error_t e, const char *msg);

void *encrypt_with_passphrase(size_t *res_size, const void *data, size_t size,
                        const char *passphrase, GError **error);

void *decrypt_with_passphrase(size_t *res_size, const void *data, size_t size,
                        const char *passphrase, GError **error);

#endif /* SQME_H */

