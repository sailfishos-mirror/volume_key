/* libgpgme utils */
static void
error_from_gpgme (GError **error, gpgme_error_t e)
{
    size_t len;
    char *s;

    s = NULL;
    len = 100;
    for (;;)
    {
        s = g_realloc (s, len);
        if (gpgme_strerror_r (e, s, len) == 0)
            break;
        len *= 2;
    }
    g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO, _("%s: %s"),
                gpgme_strsource (e), s);
    g_free (s);
}

static gpgme_error_t
gpgme_passphrase_cb (void *hook, const char *uid_hint,
                    const char *passphrase_info, int prev_was_bad, int fd)
{
    static const char nl = '\n';

    const char *pw;
    size_t len;
    ssize_t res;

    (void)uid_hint;
    (void)passphrase_info;
    if (prev_was_bad != 0)
        return GPG_ERR_CANCELED;
    pw = hook;
    len = strlen (pw);
    while (len != 0)
    {
        res = write (fd, pw, len);
        if (res < 0)
            return gpgme_error_from_errno (errno);
        pw += res;
        len -= res;
    }
    if (write (fd, &nl, sizeof (nl)) < 0)
        return gpgme_error_from_errno (errno);
    return 0;
}
// Error helper (simplified from GPGME’s error_from_gpgme)


/* Create and configure a gpgme context, to use PASSPHRASE.
 *   Return 0 if OK, -1 on error. */
static int
init_gpgme (gpgme_ctx_t *res, const char *passphrase, GError **error)
{
    gpgme_ctx_t ctx;
    gpgme_error_t e;

    (void)gpgme_check_version (NULL);
    e = gpgme_new (&ctx);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err;
    }
    e = gpgme_set_locale (ctx, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_set_locale (ctx, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_OpenPGP, GPG_PATH, NULL);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
    gpgme_set_passphrase_cb (ctx, gpgme_passphrase_cb, (void *)passphrase);
    *res = ctx;
    return 0;

    err_ctx:
    gpgme_release (ctx);
    err:
    return -1;
}

/* LIBVK_PACKET_FORMAT_PASSPHRASE */

/* Encrypt DATA of SIZE using PASSPHRASE.
 *   Return encrypted data (for g_free()), setting RES_SIZE to the size of the
 *   result, on success, NULL otherwise. */
void *
encrypt_with_passphrase (size_t *res_size, const void *data, size_t size,
                         const char *passphrase, GError **error)
{
    gpgme_ctx_t ctx;
    gpgme_error_t e;
    gpgme_data_t src_data, dest_data;
    void *gpgme_res, *res;

    // FIXME: this should eventually use CMS
    if (init_gpgme (&ctx, passphrase, error) != 0)
        goto err;
    e = gpgme_data_new_from_mem (&src_data, data, size, 0);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_data_new (&dest_data);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_src_data;
    }
    e = gpgme_op_encrypt (ctx, NULL, 0, src_data, dest_data);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_dest_data;
    }
    gpgme_data_release (src_data);
    gpgme_res = gpgme_data_release_and_get_mem (dest_data, res_size);
    if (gpgme_res == NULL)
    {
        g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO,
                     _("Unknown error getting encryption result"));
        goto err_ctx;
    }
    res = g_memdup2 (gpgme_res, *res_size);
    gpgme_free (gpgme_res);

    gpgme_release (ctx);
    return res;

    err_dest_data:
    gpgme_data_release (src_data);
    err_src_data:
    gpgme_data_release (dest_data);
    err_ctx:
    gpgme_release (ctx);
    err:
    return NULL;
}

/* Decrypt DATA of SIZE using PASSPHRASE.
 *   Return decrypted data (for g_free()), setting RES_SIZE to the size of the
 *   result, on success, NULL otherwise. */
void *
decrypt_with_passphrase (size_t *res_size, const void *data, size_t size,
                        const char *passphrase, GError **error)
{
    gpgme_ctx_t ctx;
    gpgme_error_t e;
    gpgme_data_t src_data, dest_data;
    void *gpgme_res, *res;

    if (init_gpgme (&ctx, passphrase, error) != 0)
        goto err;
    e = gpgme_data_new_from_mem (&src_data, data, size, 0);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_data_new (&dest_data);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_src_data;
    }
    e = gpgme_op_decrypt (ctx, src_data, dest_data);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_dest_data;
    }
    gpgme_data_release (src_data);
    gpgme_res = gpgme_data_release_and_get_mem (dest_data, res_size);
    if (gpgme_res == NULL)
    {
        g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO,
                     _("Unknown error getting decryption result"));
        goto err_ctx;
    }
    res = g_memdup2 (gpgme_res, *res_size);
    gpgme_free (gpgme_res);

    gpgme_release (ctx);
    return res;

    err_dest_data:
    gpgme_data_release (src_data);
    err_src_data:
    gpgme_data_release (dest_data);
    err_ctx:
    gpgme_release (ctx);
    err:
    return NULL;
}
/* libgpgme utils */
static void
error_from_gpgme (GError **error, gpgme_error_t e)
{
    size_t len;
    char *s;

    s = NULL;
    len = 100;
    for (;;)
    {
        s = g_realloc (s, len);
        if (gpgme_strerror_r (e, s, len) == 0)
            break;
        len *= 2;
    }
    g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO, _("%s: %s"),
                gpgme_strsource (e), s);
    g_free (s);
}

static gpgme_error_t
gpgme_passphrase_cb (void *hook, const char *uid_hint,
                    const char *passphrase_info, int prev_was_bad, int fd)
{
    static const char nl = '\n';

    const char *pw;
    size_t len;
    ssize_t res;

    (void)uid_hint;
    (void)passphrase_info;
    if (prev_was_bad != 0)
        return GPG_ERR_CANCELED;
    pw = hook;
    len = strlen (pw);
    while (len != 0)
    {
        res = write (fd, pw, len);
        if (res < 0)
            return gpgme_error_from_errno (errno);
        pw += res;
        len -= res;
    }
    if (write (fd, &nl, sizeof (nl)) < 0)
        return gpgme_error_from_errno (errno);
    return 0;
}
// Error helper (simplified from GPGME’s error_from_gpgme)


/* Create and configure a gpgme context, to use PASSPHRASE.
 *   Return 0 if OK, -1 on error. */
static int
init_gpgme (gpgme_ctx_t *res, const char *passphrase, GError **error)
{
    gpgme_ctx_t ctx;
    gpgme_error_t e;

    (void)gpgme_check_version (NULL);
    e = gpgme_new (&ctx);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err;
    }
    e = gpgme_set_locale (ctx, LC_CTYPE, setlocale (LC_CTYPE, NULL));
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_set_locale (ctx, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_OpenPGP, GPG_PATH, NULL);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
    gpgme_set_passphrase_cb (ctx, gpgme_passphrase_cb, (void *)passphrase);
    *res = ctx;
    return 0;

    err_ctx:
    gpgme_release (ctx);
    err:
    return -1;
}

/* LIBVK_PACKET_FORMAT_PASSPHRASE */

/* Encrypt DATA of SIZE using PASSPHRASE.
 *   Return encrypted data (for g_free()), setting RES_SIZE to the size of the
 *   result, on success, NULL otherwise. */
void *
encrypt_with_passphrase (size_t *res_size, const void *data, size_t size,
                         const char *passphrase, GError **error)
{
    gpgme_ctx_t ctx;
    gpgme_error_t e;
    gpgme_data_t src_data, dest_data;
    void *gpgme_res, *res;

    // FIXME: this should eventually use CMS
    if (init_gpgme (&ctx, passphrase, error) != 0)
        goto err;
    e = gpgme_data_new_from_mem (&src_data, data, size, 0);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_data_new (&dest_data);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_src_data;
    }
    e = gpgme_op_encrypt (ctx, NULL, 0, src_data, dest_data);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_dest_data;
    }
    gpgme_data_release (src_data);
    gpgme_res = gpgme_data_release_and_get_mem (dest_data, res_size);
    if (gpgme_res == NULL)
    {
        g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO,
                     _("Unknown error getting encryption result"));
        goto err_ctx;
    }
    res = g_memdup2 (gpgme_res, *res_size);
    gpgme_free (gpgme_res);

    gpgme_release (ctx);
    return res;

    err_dest_data:
    gpgme_data_release (src_data);
    err_src_data:
    gpgme_data_release (dest_data);
    err_ctx:
    gpgme_release (ctx);
    err:
    return NULL;
}

/* Decrypt DATA of SIZE using PASSPHRASE.
 *   Return decrypted data (for g_free()), setting RES_SIZE to the size of the
 *   result, on success, NULL otherwise. */
void *
decrypt_with_passphrase (size_t *res_size, const void *data, size_t size,
                        const char *passphrase, GError **error)
{
    gpgme_ctx_t ctx;
    gpgme_error_t e;
    gpgme_data_t src_data, dest_data;
    void *gpgme_res, *res;

    if (init_gpgme (&ctx, passphrase, error) != 0)
        goto err;
    e = gpgme_data_new_from_mem (&src_data, data, size, 0);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_ctx;
    }
    e = gpgme_data_new (&dest_data);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_src_data;
    }
    e = gpgme_op_decrypt (ctx, src_data, dest_data);
    if (e != GPG_ERR_NO_ERROR)
    {
        error_from_gpgme (error, e);
        goto err_dest_data;
    }
    gpgme_data_release (src_data);
    gpgme_res = gpgme_data_release_and_get_mem (dest_data, res_size);
    if (gpgme_res == NULL)
    {
        g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO,
                     _("Unknown error getting decryption result"));
        goto err_ctx;
    }
    res = g_memdup2 (gpgme_res, *res_size);
    gpgme_free (gpgme_res);

    gpgme_release (ctx);
    return res;

    err_dest_data:
    gpgme_data_release (src_data);
    err_src_data:
    gpgme_data_release (dest_data);
    err_ctx:
    gpgme_release (ctx);
    err:
    return NULL;
}
