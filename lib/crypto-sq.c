#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "crypto-sq.h"
#include "libvolume_key.h"
#include <glib.h>
#include <glib/gi18n-lib.h>

struct _sqme_ctx {
    char *passphrase;
};

struct _sqme_data {
    void *buf;
    size_t size;
    int owned;  // Whether we own the buffer (1) or not (0)
};

/* Error Handling */
GQuark sqme_error_quark(void) {
    return g_quark_from_static_string("sqme-error-quark");
}

void sqme_set_error(GError **error, sqme_error_t e, const char *msg) {
    if (error) {
        g_set_error(error, SQGPGME_ERROR, e, "%s", msg);
    }
}

const char *sqme_strerror(sqme_error_t err) {
    switch (err) {
        case SQGPGME_ERR_NO_ERROR: return "No error";
        case SQGPGME_ERR_GENERAL: return "General error";
        case SQGPGME_ERR_ENOMEM: return "Out of memory";
        case SQGPGME_ERR_CANCELED: return "Operation canceled";
        case SQGPGME_ERR_BAD_PASSPHRASE: return "Bad passphrase";
        case SQGPGME_ERR_SYSTEM: return "System error";
        default: return "Unknown error";
    }
}

/* Context Management */
sqme_error_t sqme_new(sqme_ctx_t **ctx) {
    *ctx = g_malloc0(sizeof(sqme_ctx_t));
    if (!*ctx) return SQGPGME_ERR_ENOMEM;
    return SQGPGME_ERR_NO_ERROR;
}

void sqme_release(sqme_ctx_t *ctx) {
    if (!ctx) return;
    g_free(ctx->passphrase);
    g_free(ctx);
}

sqme_error_t sqme_set_passphrase(sqme_ctx_t *ctx, const char *passphrase) {
    if (!ctx) return SQGPGME_ERR_GENERAL;
    g_free(ctx->passphrase);
    ctx->passphrase = g_strdup(passphrase);
    return SQGPGME_ERR_NO_ERROR;
}

/* Data Management */
sqme_error_t sqme_data_new_from_mem(sqme_data_t **data, const void *buf, size_t size, int copy) {
    *data = g_malloc0(sizeof(sqme_data_t));
    if (!*data) return SQGPGME_ERR_ENOMEM;
    if (copy) {
        (*data)->buf = g_memdup2(buf, size);
        (*data)->owned = 1;
    } else {
        (*data)->buf = (void *)buf;
        (*data)->owned = 0;
    }
    (*data)->size = size;
    return SQGPGME_ERR_NO_ERROR;
}

sqme_error_t sqme_data_new(sqme_data_t **data) {
    *data = g_malloc0(sizeof(sqme_data_t));
    if (!*data) return SQGPGME_ERR_ENOMEM;
    return SQGPGME_ERR_NO_ERROR;
}

void sqme_data_release(sqme_data_t *data) {
    if (!data) return;
    if (data->owned) g_free(data->buf);
    g_free(data);
}

void *sqme_data_release_and_get_mem(sqme_data_t *data, size_t *size) {
    if (!data) return NULL;
    void *buf = data->buf;
    *size = data->size;
    data->buf = NULL;  // Prevent double free
    sqme_data_release(data);
    return buf;
}

/* Encryption/Decryption Helpers */
static sqme_error_t run_sq(const char *passphrase, const char *cmd, const void *in, size_t in_size, void **out, size_t *out_size, GError **error) {
    int in_pipe[2], out_pipe[2], err_pipe[2];
    pid_t pid;
    ssize_t total_read = 0;
    char *out_buf = NULL;
    size_t buf_size = 0;
    char fifo_prefix[] = "/tmp/sqme_fifoXXXXXX";
    char fifo_path[64]; // reserve some space for fifo_prefix and strcat later
    int fifo_fd;

    // Create named pipe (FIFO)
    if (mkdtemp(fifo_prefix) == NULL) {
        return SQGPGME_ERR_SYSTEM;
    }
    strcat(strcpy(fifo_path, fifo_prefix), "/fifo");
    if (mkfifo(fifo_path, 0600) < 0) {
        rmdir(fifo_prefix);
        return SQGPGME_ERR_SYSTEM;
    }

    if (pipe(in_pipe) < 0 || pipe(out_pipe) < 0 || pipe(err_pipe) < 0) {
        unlink(fifo_path);
        return SQGPGME_ERR_SYSTEM;
    }

    pid = fork();
    if (pid < 0) {
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        unlink(fifo_path);
        rmdir(fifo_prefix);
        return SQGPGME_ERR_SYSTEM;
    }

    if (pid == 0) {  // Child process
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(err_pipe[0]);

        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);

        if (strcmp(cmd, "encrypt") == 0) {
            execlp(SQ_PATH, SQ_PATH, "encrypt", "--with-password-file", fifo_path, "--without-signature", NULL);
        } else if (strcmp(cmd, "decrypt") == 0) {
            execlp(SQ_PATH, SQ_PATH, "decrypt", "--password-file", fifo_path, NULL);
        }
        if (errno == ENOENT)
            _exit(127);
        _exit(126);  // If exec fails
    }

    // Parent process
    close(in_pipe[0]);
    close(out_pipe[1]);
    close(err_pipe[1]);

    // Write passphrase to FIFO (non-blocking write in a separate fork to avoid blocking)
    pid_t fifo_pid = fork();
    if (fifo_pid < 0) {
        close(in_pipe[1]);
        close(out_pipe[0]);
        close(err_pipe[0]);
        waitpid(pid, NULL, 0);
        unlink(fifo_path);
        return SQGPGME_ERR_SYSTEM;
    }
    if (fifo_pid == 0) {
        fifo_fd = open(fifo_path, O_WRONLY);  // Blocks until sq opens for reading
        if (fifo_fd >= 0) {
            write(fifo_fd, passphrase, strlen(passphrase));  // No \n
            close(fifo_fd);
        }
        _exit(0);
    }

    // Write input data to in_pipe
    size_t remaining = in_size;
    const char *in_ptr = in;
    while (remaining > 0) {
        ssize_t written = write(in_pipe[1], in_ptr, remaining);
        if (written < 0) {
            close(in_pipe[1]);
            close(out_pipe[0]);
            close(err_pipe[0]);
            waitpid(pid, NULL, 0);
            waitpid(fifo_pid, NULL, 0);
            unlink(fifo_path);
            rmdir(fifo_prefix);
            return SQGPGME_ERR_SYSTEM;
        }
        in_ptr += written;
        remaining -= written;
    }
    close(in_pipe[1]);

    // Read output from out_pipe
    char buffer[4096];
    while (1) {
        ssize_t n = read(out_pipe[0], buffer, sizeof(buffer));
        if (n <= 0) break;  // EOF or error
        if (total_read + n > buf_size) {
            buf_size = total_read + n + 4096;  // Grow buffer with padding
            out_buf = g_realloc(out_buf, buf_size);
        }
        memcpy(out_buf + total_read, buffer, n);
        total_read += n;
    }
    close(out_pipe[0]);

    // Read stderr for error messages
    char err_buf[1024];
    ssize_t err_len = read(err_pipe[0], err_buf, sizeof(err_buf) - 1);
    close(err_pipe[0]);
    if (err_len > 0) {
        err_buf[err_len] = '\0';
    }

    int status;
    waitpid(pid, &status, 0);

    int exit_code = 0;
    if (WIFEXITED(status) && ((exit_code=WEXITSTATUS(status)) !=0)) {
        // exit_code = WEXITSTATUS(status);
        kill(fifo_pid, SIGTERM); // Terminate second child if still running
        g_free(out_buf);
        if (err_len > 0) {
            sqme_set_error(error, SQGPGME_ERR_BAD_PASSPHRASE, err_buf);
        } else if (exit_code == 126) {
            sqme_set_error(error, SQGPGME_ERR_SYSTEM, "Execution of 'sq' failed");
        } else if (exit_code == 127) {
            sqme_set_error(error, SQGPGME_ERR_SYSTEM, "sq executable not found");
        } else {
            sqme_set_error(error, SQGPGME_ERR_BAD_PASSPHRASE, "Command failed, possibly bad passphrase");
        }
    }
    waitpid(fifo_pid, NULL, 0);  // Clean up FIFO writer
    rmdir(fifo_prefix);
    unlink(fifo_path);  // Remove FIFO

    if (exit_code) {
        return SQGPGME_ERR_BAD_PASSPHRASE;
    }

    *out = out_buf;
    *out_size = total_read;
    return SQGPGME_ERR_NO_ERROR;
}

sqme_error_t sqme_op_encrypt(sqme_ctx_t *ctx, sqme_data_t *in, sqme_data_t *out, GError **error) {
    if (!ctx || !in || !out || !ctx->passphrase) return SQGPGME_ERR_GENERAL;
    void *out_buf;
    size_t out_size;
    sqme_error_t err = run_sq(ctx->passphrase, "encrypt", in->buf, in->size, &out_buf, &out_size, error);
    if (err == SQGPGME_ERR_NO_ERROR) {
        out->buf = out_buf;
        out->size = out_size;
        out->owned = 1;
    }
    return err;
}

sqme_error_t sqme_op_decrypt(sqme_ctx_t *ctx, sqme_data_t *in, sqme_data_t *out, GError **error) {
    if (!ctx || !in || !out || !ctx->passphrase) return SQGPGME_ERR_GENERAL;
    void *out_buf;
    size_t out_size;
    sqme_error_t err = run_sq(ctx->passphrase, "decrypt", in->buf, in->size, &out_buf, &out_size, error);
    if (err == SQGPGME_ERR_NO_ERROR) {
        out->buf = out_buf;
        out->size = out_size;
        out->owned = 1;
    }
    return err;
}

void *
encrypt_with_passphrase(size_t *res_size, const void *data, size_t size,
                        const char *passphrase, GError **error)
{
    sqme_ctx_t *ctx;
    sqme_data_t *src_data, *dest_data;
    void *res;

    if (sqme_new(&ctx) != SQGPGME_ERR_NO_ERROR) {
        sqme_set_error(error, SQGPGME_ERR_ENOMEM, "Failed to create context");
        goto err;
    }
    if (sqme_set_passphrase(ctx, passphrase) != SQGPGME_ERR_NO_ERROR) {
        sqme_set_error(error, SQGPGME_ERR_GENERAL, "Failed to set passphrase");
        goto err_ctx;
    }
    if (sqme_data_new_from_mem(&src_data, data, size, 0) != SQGPGME_ERR_NO_ERROR) {
        sqme_set_error(error, SQGPGME_ERR_ENOMEM, "Failed to create source data");
        goto err_ctx;
    }
    if (sqme_data_new(&dest_data) != SQGPGME_ERR_NO_ERROR) {
        sqme_set_error(error, SQGPGME_ERR_ENOMEM, "Failed to create destination data");
        goto err_src_data;
    }
    if (sqme_op_encrypt(ctx, src_data, dest_data, error) != SQGPGME_ERR_NO_ERROR) {
        if (!*error)
            sqme_set_error(error, SQGPGME_ERR_BAD_PASSPHRASE, "Encryption failed, possibly bad passphrase");
        goto err_dest_data;
    }

    sqme_data_release(src_data);
    res = sqme_data_release_and_get_mem(dest_data, res_size);
    if (!res) {
        g_set_error(error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO, _("Unknown error getting encryption result"));
        goto err_ctx;
    }
    sqme_release(ctx);
    return res;

    err_dest_data:
    sqme_data_release(dest_data);
    err_src_data:
    sqme_data_release(src_data);
    err_ctx:
    sqme_release(ctx);
    err:
    return NULL;
}


/* Decrypt DATA of SIZE using PASSPHRASE.
 *   Return decrypted data (for g_free()), setting RES_SIZE to the size of the
 *   result, on success, NULL otherwise. */
void *
decrypt_with_passphrase(size_t *res_size, const void *data, size_t size,
                        const char *passphrase, GError **error)
{
    sqme_ctx_t *ctx;
    sqme_data_t *src_data, *dest_data;
    void *res;

    if (sqme_new(&ctx) != SQGPGME_ERR_NO_ERROR) {
        sqme_set_error(error, SQGPGME_ERR_ENOMEM, "Failed to create context");
        goto err;
    }
    if (sqme_set_passphrase(ctx, passphrase) != SQGPGME_ERR_NO_ERROR) {
        sqme_set_error(error, SQGPGME_ERR_GENERAL, "Failed to set passphrase");
        goto err_ctx;
    }
    if (sqme_data_new_from_mem(&src_data, data, size, 0) != SQGPGME_ERR_NO_ERROR) {
        sqme_set_error(error, SQGPGME_ERR_ENOMEM, "Failed to create source data");
        goto err_ctx;
    }
    if (sqme_data_new(&dest_data) != SQGPGME_ERR_NO_ERROR) {
        sqme_set_error(error, SQGPGME_ERR_ENOMEM, "Failed to create destination data");
        goto err_src_data;
    }
    if (sqme_op_decrypt(ctx, src_data, dest_data, error) != SQGPGME_ERR_NO_ERROR) {
        if (!*error)
            sqme_set_error(error, SQGPGME_ERR_BAD_PASSPHRASE, "Decryption failed, possibly bad passphrase");
        goto err_dest_data;
    }

    sqme_data_release(src_data);
    res = sqme_data_release_and_get_mem(dest_data, res_size);
    if (!res) {
        g_set_error(error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO, _("Unknown error getting encryption result"));
        goto err_ctx;
    }
    sqme_release(ctx);
    return res;

    err_dest_data:
    sqme_data_release(dest_data);
    err_src_data:
    sqme_data_release(src_data);
    err_ctx:
    sqme_release(ctx);
    err:
    return NULL;
}
