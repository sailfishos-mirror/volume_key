/* Internal encryption utilities.

Copyright (C) 2009, 2010 Red Hat, Inc. All rights reserved.
This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU General
Public License v.2.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110-1301, USA.

Author: Miloslav Trmač <mitr@redhat.com> */
#include <config.h>

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <cert.h>
#include <cms.h>
#include <glib.h>
#include <glib/gi18n-lib.h>
#include <keyhi.h>
#include <nss.h>
#include <pk11pub.h>
#include <prerror.h>
#include <prinit.h>
#include <smime.h>

#if WITH_SQ
# include "crypto-sq.h"
#else
# include "crypto-gpgme.h"
#endif
#include "crypto.h"
#include "nss_error.h"
#include "libvolume_key.h"

 /* NSS utils */

static void
error_from_pr (GError **error)
{
  size_t len;
  const char *err_utf8;
  char *err;

  err_utf8 = libvk_nss_error_text__ (PR_GetError ());
  if (err_utf8 == NULL)
    err_utf8 = PR_ErrorToString (PR_GetError (), PR_LANGUAGE_I_DEFAULT);
  err = g_locale_from_utf8 (err_utf8, -1, NULL, NULL, NULL);
  /* Fall back to err_utf8 on error below. */
  len = PR_GetErrorTextLength();
  if (len == 0)
    g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO, "%s",
		 err != NULL ? err : err_utf8);
  else
    {
      char *msg;

      msg = g_malloc (len);
      PR_GetErrorText (msg);
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO, _("%s: %s"),
		   err != NULL ? err : err_utf8, msg);
      g_free (msg);
    }
  g_free (err);
}

/*
 * FIPS compliant implementation of PK11_ImportSymKey().
 * Source: https://github.com/ceph/ceph/pull/27104/files
 */
static PK11SymKey *
import_sym_key (PK11SlotInfo *slot, CK_MECHANISM_TYPE type, PK11Origin origin,
                CK_ATTRIBUTE_TYPE operation, SECItem *key, void *wincx)
{
  CK_MECHANISM_TYPE wrap_mechanism = 0UL;
  PK11SymKey *wrapping_key = NULL, *sym_key = NULL;
  SECItem tmp_sec_item, wrapped_key_item, *raw_key_aligned = NULL;
  PK11Context *wrap_key_crypt_context = NULL;
  int block_size = 0;
  size_t wrapped_key_size = 0;
  unsigned char *wrapped_key = NULL;
  int out_len = 0;
  SECStatus ret = 0;

  /* Fall back to PK11_ImportSymKey() if FIPS mode is disabled. */
  if (PK11_IsFIPS () == PR_FALSE)
    return PK11_ImportSymKey (slot, type, origin, operation, key, wincx);

  /* Get the best mechanism for the wrapping operation. */
  wrap_mechanism = PK11_GetBestWrapMechanism (slot);

  /* Based on that mechanism, generate a symetric key <wrapping_key>. */
  wrapping_key = PK11_KeyGen (slot, wrap_mechanism, NULL,
                              PK11_GetBestKeyLength (slot, wrap_mechanism),
                              NULL);
  if (wrapping_key == NULL)
    return NULL;

  /* Create the context for the wrapping operation. The context contains:
   *   - <wrapping_key>
   *   - operation to perform (CKA_ENCRYPT)
   */
  memset (&tmp_sec_item, 0, sizeof (tmp_sec_item));
  wrap_key_crypt_context = PK11_CreateContextBySymKey (wrap_mechanism,
                                                       CKA_ENCRYPT,
                                                       wrapping_key,
                                                       &tmp_sec_item);
  if (wrap_key_crypt_context == NULL) {
    PK11_FreeSymKey (wrapping_key);
    return NULL;
  }

  /* Align <key> to the block size specified by the wrapping mechanism. */
  block_size = PK11_GetBlockSize (wrap_mechanism, NULL);
  raw_key_aligned = PK11_BlockData (key, block_size);
  if (raw_key_aligned == NULL) {
    PK11_DestroyContext (wrap_key_crypt_context, PR_TRUE);
    PK11_FreeSymKey (wrapping_key);
    return NULL;
  }

  /* Prepare for <key> wrap. First, allocate enough space for
   * the wrapped <key>. Add the padding of the size of one block behind the
   * aligned <key> to make sure the wrapping operation will not hit the wall.
   */
  wrapped_key_size = raw_key_aligned->len + block_size;
  wrapped_key = g_try_malloc0 (wrapped_key_size);
  if (wrapped_key == NULL) {
    SECITEM_FreeItem (raw_key_aligned, PR_TRUE);
    PK11_DestroyContext (wrap_key_crypt_context, PR_TRUE);
    PK11_FreeSymKey (wrapping_key);
    return NULL;
  }

  /* Do the wrap operation. <wrapped_key> is now a pair (<wrapping_key>, <key>)
   * expressing that raw key <key> is now encrypted with the <wrapping_key>.
   */
  ret = PK11_CipherOp (wrap_key_crypt_context, wrapped_key, &out_len,
                       wrapped_key_size, raw_key_aligned->data,
                       raw_key_aligned->len);
  if (ret != SECSuccess) {
    g_free (wrapped_key);
    SECITEM_FreeItem (raw_key_aligned, PR_TRUE);
    PK11_DestroyContext (wrap_key_crypt_context, PR_TRUE);
    PK11_FreeSymKey (wrapping_key);
    return NULL;
  }

  /* Finish the wrapping operation and release no more needed resources. */
  ret = PK11_Finalize (wrap_key_crypt_context);
  SECITEM_FreeItem (raw_key_aligned, PR_TRUE);
  PK11_DestroyContext (wrap_key_crypt_context, PR_TRUE);
  if (ret != SECSuccess) {
    g_free (wrapped_key);
    PK11_FreeSymKey (wrapping_key);
    return NULL;
  }

  /* Prepare for unwrapping the <key>. */
  memset (&tmp_sec_item, 0, sizeof (tmp_sec_item));
  memset (&wrapped_key_item, 0, sizeof (wrapped_key_item));
  wrapped_key_item.data = wrapped_key;
  wrapped_key_item.len = wrapped_key_size;

  /* Unwrap the <key>. First, decrypt the <key> with the <wrapping_key> to get
   * its raw form. Then make a symmetric key (<key>, <type>, <operation>). This
   * makes a symmetric key from the raw <key> in a FIPS compliant manner.
   */
  sym_key = PK11_UnwrapSymKey (wrapping_key, wrap_mechanism, &tmp_sec_item,
                               &wrapped_key_item, type, operation, key->len);
  g_free (wrapped_key);
  PK11_FreeSymKey (wrapping_key);
  return sym_key;
}

 /* LIBVK_PACKET_FORMAT_ASYMMETRIC */

/* Encrypt DATA of SIZE for CERT.
   Return encrypted data (for g_free()), setting RES_SIZE to the size of the
   result, on success, NULL otherwise.
   Use PWFN_ARG for PK11 password callback. */
void *
encrypt_asymmetric (size_t *res_size, const void *data, size_t size,
		    CERTCertificate *cert, void *pwfn_arg, GError **error)
{
  NSSCMSMessage *cmsg;
  NSSCMSEnvelopedData *enveloped;
#if 0
  SECAlgorithmID digest_algorithm;
  NSSCMSDigestedData *digested;
#endif
  NSSCMSContentInfo *content;
  SECItem dest_item;
  NSSCMSEncoderContext *encoder;
  NSSCMSRecipientInfo *recipient;
  PLArenaPool *res_arena;
  void *res;

  // FIXME: Use "digested" inside "enveloped"

  cmsg = NSS_CMSMessage_Create (NULL);
  if (cmsg == NULL)
    {
      error_from_pr (error);
      goto err;
    }

  /* Hard-code the algorithm; the best NSS would choose automatically for
     certificates that are not in the database is 3DES. */
  enveloped = NSS_CMSEnvelopedData_Create (cmsg, SEC_OID_AES_256_CBC, 256);
  if (enveloped == NULL)
    {
      error_from_pr (error);
      goto err_cmsg;
    }
  content = NSS_CMSMessage_GetContentInfo (cmsg);
  if (NSS_CMSContentInfo_SetContent_EnvelopedData (cmsg, content, enveloped)
      != SECSuccess)
    {
      error_from_pr (error);
      NSS_CMSEnvelopedData_Destroy (enveloped);
      goto err_cmsg;
    }
  recipient = NSS_CMSRecipientInfo_Create (cmsg, cert);
  if (recipient == NULL)
    {
      error_from_pr (error);
      goto err_cmsg;
    }
  if (NSS_CMSEnvelopedData_AddRecipient (enveloped, recipient) != SECSuccess)
    {
      error_from_pr (error);
      NSS_CMSRecipientInfo_Destroy (recipient);
      goto err_cmsg;
    }

#if 0
  /* Hard-code the algorithm. */
  memset (&digest_algorithm, 0, sizeof (digest_algorithm));
  if (SECOID_SetAlgorithmID (NULL, &digest_algorithm, SEC_OID_SHA512, NULL)
      != SECSuccess)
    {
      error_from_pr (error);
      goto err_cmsg;
    }
  digested = NSS_CMSDigestedData_Create (cmsg, &digest_algorithm);
#endif
  content = NSS_CMSEnvelopedData_GetContentInfo (enveloped);
#if 0
  if (NSS_CMSContentInfo_SetContent_DigestedData (cmsg, content, digested)
      != SECSuccess)
    {
      error_from_pr (error);
      NSS_CMSDigestedData_Destroy (digested);
      goto err_cmsg;
    }
#endif

#if 0
  content = NSS_CMSDigestedData_GetContentInfo (digested);
#endif
  /* Supplying a SECItem of (data, size) here doesn't work (#499440). */
  if (NSS_CMSContentInfo_SetContent_Data(cmsg, content, NULL, PR_FALSE)
      != SECSuccess)
    {
      error_from_pr (error);
      goto err_cmsg;
    }

  res_arena = PORT_NewArena (BUFSIZ);
  if (res_arena == NULL)
    {
      error_from_pr (error);
      goto err_cmsg;
    }
  memset (&dest_item, 0, sizeof (dest_item));
  encoder = NSS_CMSEncoder_Start (cmsg, NULL, NULL, &dest_item, res_arena,
				  NULL, pwfn_arg, NULL, NULL, NULL, NULL);
  if (encoder == NULL)
    {
      error_from_pr (error);
      goto err_res_arena;
    }
  if (NSS_CMSEncoder_Update (encoder, data, size) != SECSuccess)
    {
      error_from_pr (error);
      goto err_res_arena;
    }
  if (NSS_CMSEncoder_Finish (encoder) != SECSuccess)
    {
      error_from_pr (error);
      goto err_res_arena;
    }

  *res_size = dest_item.len;
  res = g_memdup2 (dest_item.data, dest_item.len);
  PORT_FreeArena (res_arena, PR_FALSE);
  NSS_CMSMessage_Destroy (cmsg);
  return res;

 err_res_arena:
  PORT_FreeArena (res_arena, PR_FALSE);
 err_cmsg:
  NSS_CMSMessage_Destroy (cmsg);
 err:
  return NULL;
}

/* Decrypt DATA of SIZE, assuming the private key is stored in a NSS database.
   Return plaintext data (for g_free()), setting RES_SIZE to the size of the
   result, on success, NULL otherwise.
   Use PWFN_ARG for PK11 password callback. */
void *
decrypt_asymmetric (size_t *res_size, const void *data, size_t size,
		    void *pwfn_arg, GError **error)
{
  SECItem src_item, *dest;
  NSSCMSMessage *cmsg;
  void *res;

  memset (&src_item, 0, sizeof (src_item));
  if (SECITEM_AllocItem (NULL, &src_item, size) == NULL)
    {
      error_from_pr (error);
      goto err;
    }
  memcpy (src_item.data, data, size);
  cmsg = NSS_CMSMessage_CreateFromDER (&src_item, NULL, NULL, NULL, pwfn_arg,
				       NULL, NULL);
  if (cmsg == NULL)
    {
      error_from_pr (error);
      goto err_src_item;
    }
  dest = NSS_CMSMessage_GetContent (cmsg);
  if (dest == NULL)
    {
      error_from_pr (error);
      goto err_cmsg;
    }
  res = g_memdup2 (dest->data, dest->len);
  *res_size = dest->len;

  NSS_CMSMessage_Destroy (cmsg);
  SECITEM_FreeItem (&src_item, FALSE);
  return res;

 err_cmsg:
  NSS_CMSMessage_Destroy (cmsg);
 err_src_item:
  SECITEM_FreeItem (&src_item, FALSE);
 err:
  return NULL;
}

 /* LIBVK_PACKET_FORMAT_ASYMMETRIC_WRAP_SECRET_ONLY */

/* Wrap CLEAR_SECRET_DATA of CLEAR_SECRET_SIZE for CERT.
   Store result into WRAPPED_SECRET, WRAPPED_SECRET_SIZE, encoded issuer into
   ISSUER, ISSUER_SIZE, encoded serial number into SN, SN_SIZE (all data for
   g_free ()), used mechanism to MECHANISM, and return 0 on success, -1
   otherwise.
   Use PWFN_ARG for PK11 password callback. */
int
wrap_asymmetric (void **wrapped_secret, size_t *wrapped_secret_size,
		 void **issuer, size_t *issuer_size, void **sn, size_t *sn_size,
		 CK_MECHANISM_TYPE *mechanism, const void *clear_secret_data,
		 size_t clear_secret_size, CERTCertificate *cert,
		 void *pwfn_arg, GError **error)
{
  PK11SlotInfo *slot;
  SECItem wrapped_secret_item, clear_secret_item;
  PK11SymKey *secret_key;
  PLArenaPool *isn_arena;
  CERTIssuerAndSN *isn;
  SECKEYPublicKey *public_key;
  unsigned dest_size;

  /* PK11_PubUnwrapSymKey() chooses a mechanism automatically based on key
     type; PK11_PubWrapSymKey() chooses the mechanism automatically as well,
     except that it uses the supplied mechanism to choose a slot for the
     operation.  As it happens, the only mechanism NSS currently choses is
     CKM_RSA_PKCS anyway, so don't bother trying to extract the information
     from the certificate. */
  *mechanism = CKM_RSA_PKCS;

  slot = PK11_GetBestSlot (*mechanism, pwfn_arg);
  if (slot == NULL)
    {
      error_from_pr (error);
      goto err;
    }
  /* The disk encryption mechanism might not have a PKCS11 name, and we don't
     really need to tell NSS specifics anyway, so just use
     CKM_GENERIC_SECRET_KEY_GEN. */
  clear_secret_item.data = (void *)clear_secret_data;
  clear_secret_item.len = clear_secret_size;
  secret_key = import_sym_key (slot, CKM_GENERIC_SECRET_KEY_GEN,
			       PK11_OriginUnwrap, CKA_WRAP,
			       &clear_secret_item, pwfn_arg);
  PK11_FreeSlot (slot);
  if (secret_key == NULL)
    {
      error_from_pr (error);
      goto err;
    }

  isn_arena = PORT_NewArena (0);
  if (isn_arena == NULL)
    {
      error_from_pr (error);
      goto err_secret_key;
    }
  isn = CERT_GetCertIssuerAndSN (isn_arena, cert);
  if (isn == NULL)
    {
      error_from_pr (error);
      goto err_secret_key;
    }

  public_key = CERT_ExtractPublicKey (cert);
  if (public_key == NULL)
    {
      error_from_pr (error);
      goto err_isn_arena;
    }
  dest_size = SECKEY_PublicKeyStrength(public_key);
  if (dest_size == 0)
    {
      error_from_pr (error);
      goto err_public_key;
    }
  if (SECITEM_AllocItem (NULL, &wrapped_secret_item, dest_size) == NULL)
    {
      error_from_pr (error);
      goto err_public_key;
    }
  if (PK11_PubWrapSymKey (*mechanism, public_key, secret_key,
			  &wrapped_secret_item) != SECSuccess)
    {
      error_from_pr (error);
      goto err_wrapped_secret_item;
    }
  SECKEY_DestroyPublicKey (public_key);
  PK11_FreeSymKey (secret_key);

  *wrapped_secret = g_memdup2 (wrapped_secret_item.data,
			      wrapped_secret_item.len);
  *wrapped_secret_size = wrapped_secret_item.len;
  SECITEM_FreeItem (&wrapped_secret_item, PR_FALSE);
  *issuer = g_memdup2 (isn->derIssuer.data, isn->derIssuer.len);
  *issuer_size = isn->derIssuer.len;
  *sn = g_memdup2 (isn->serialNumber.data, isn->serialNumber.len);
  *sn_size = isn->serialNumber.len;
  PORT_FreeArena (isn_arena, PR_FALSE);
  return 0;

 err_wrapped_secret_item:
  SECITEM_FreeItem (&wrapped_secret_item, PR_FALSE);
 err_public_key:
  SECKEY_DestroyPublicKey (public_key);
 err_isn_arena:
  PORT_FreeArena (isn_arena, PR_FALSE);
 err_secret_key:
  PK11_FreeSymKey (secret_key);
 err:
  return -1;
}

/* Unwrap WRAPPED_SECRET_DATA of WRAPPED_SECRET_SIZE, assuming the private key
   for ISSUER with ISSUER_SIZE and SN with SN_SIZE is stored in a NSS database.
   Return plaintext secret (for (g_free ()), setting CLEAR_SECRET_SIZE to the
   size of the result, on success, NULL otherwise.
   Use PWFN_ARG for PK11 password callback. */
void *
unwrap_asymmetric (size_t *clear_secret_size, const void *wrapped_secret_data,
		   size_t wrapped_secret_size, const void *issuer,
		   size_t issuer_size, const void *sn, size_t sn_size,
		   void *pwfn_arg, GError **error)
{
  CERTIssuerAndSN isn;
  CERTCertificate *cert;
  PK11SlotInfo *slot;
  SECKEYPrivateKey *private_key;
  SECItem wrapped_secret_item, *clear_secret_item;
  PK11SymKey *secret_key;
  void *ret;

  isn.derIssuer.data = (void *)issuer;
  isn.derIssuer.len = issuer_size;
  memset (&isn.issuer, 0, sizeof (isn.issuer));
  isn.serialNumber.data = (void *)sn;
  isn.serialNumber.len = sn_size;
  cert = CERT_FindCertByIssuerAndSN (CERT_GetDefaultCertDB (), &isn);
  if (cert == NULL)
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_CRYPTO,
		   _("Unable to find the certificate necessary for "
		     "decryption"));
      goto err;
    }

  slot = PK11_GetInternalKeySlot ();
  if (slot == NULL)
    {
      error_from_pr (error);
      CERT_DestroyCertificate (cert);
      goto err;
    }
  private_key = PK11_FindPrivateKeyFromCert (slot, cert, pwfn_arg);
  PK11_FreeSlot (slot);
  CERT_DestroyCertificate (cert);
  if (private_key == NULL)
    {
      error_from_pr (error);
      goto err;
    }

  wrapped_secret_item.data = (void *)wrapped_secret_data;
  wrapped_secret_item.len = wrapped_secret_size;
  /* See the comment in wrap_asymmetric() about CKM_GENERIC_SECRET_KEY_GEN. */
  secret_key = PK11_PubUnwrapSymKey (private_key, &wrapped_secret_item,
				    CKM_GENERIC_SECRET_KEY_GEN, CKA_UNWRAP, 0);
  SECKEY_DestroyPrivateKey (private_key);
  if (secret_key == NULL)
    {
      error_from_pr (error);
      goto err;
    }
  if (PK11_ExtractKeyValue (secret_key) != SECSuccess)
    {
      error_from_pr (error);
      goto err_secret_key;
    }
  clear_secret_item = PK11_GetKeyData (secret_key);
  ret = g_memdup2 (clear_secret_item->data, clear_secret_item->len);
  *clear_secret_size = clear_secret_item->len;
  PK11_FreeSymKey (secret_key);

  return ret;

 err_secret_key:
  PK11_FreeSymKey (secret_key);
 err:
  return NULL;
}

 /* LIBVK_PACKET_FORMAT_SYMMETRIC_WRAP_SECRET_ONLY */

/* Wrap CLEAR_SECRET_DATA of CLEAR_SECRET_SIZE for WRAPPING_KEY using MECHANISM.
   Store result into WRAPPED_SECRET, WRAPPED_SECRET_SIZE, IV, IV_SIZE (both data
   for g_free ()), and return 0 on success, -1 otherwise.
   Use PWFN_ARG for PK11 password callback. */
int
wrap_symmetric (void **wrapped_secret, size_t *wrapped_secret_size, void **iv,
		size_t *iv_size, PK11SymKey *wrapping_key,
		CK_MECHANISM_TYPE mechanism, const void *clear_secret,
		size_t clear_secret_size, void *pwfn_arg, GError **error)
{
  PK11SlotInfo *slot;
  PK11SymKey *secret_key;
  SECItem clear_secret_item, *wrapping_param, wrapped_secret_item;
  unsigned char *iv_data;
  int iv_data_size;
  size_t dest_size;

  slot = PK11_GetBestSlot (mechanism, pwfn_arg);
  if (slot == NULL)
    {
      error_from_pr (error);
      goto err;
    }
  clear_secret_item.data = (void *)clear_secret;
  clear_secret_item.len = clear_secret_size;
  /* The disk encryption mechanism might not have a PKCS11 name, and we don't
     really need to tell NSS specifics anyway, so just use
     CKM_GENERIC_SECRET_KEY_GEN. */
  secret_key = import_sym_key (slot, CKM_GENERIC_SECRET_KEY_GEN,
			       PK11_OriginUnwrap, CKA_WRAP,
			       &clear_secret_item, pwfn_arg);
  PK11_FreeSlot (slot);
  if (secret_key == NULL)
    {
      error_from_pr (error);
      goto err;
    }

  wrapping_param = PK11_GenerateNewParam (mechanism, wrapping_key);
  if (wrapping_param == NULL)
    {
      error_from_pr (error);
      goto err_secret_key;
    }

  dest_size = clear_secret_size + 4096; /* FIXME? Just a wild guess */
  if (SECITEM_AllocItem (NULL, &wrapped_secret_item, dest_size) == NULL)
    {
      error_from_pr (error);
      goto err_wrapping_param;
    }
  if (PK11_WrapSymKey (mechanism, wrapping_param, wrapping_key, secret_key,
		       &wrapped_secret_item) != SECSuccess)
    {
      error_from_pr (error);
      goto err_wrapping_param;
    }
  PK11_FreeSymKey (secret_key);

  iv_data = PK11_IVFromParam (mechanism, wrapping_param, &iv_data_size);
  *iv = g_memdup2 (iv_data, iv_data_size);
  *iv_size = iv_data_size;
  SECITEM_FreeItem (wrapping_param, PR_TRUE);

  *wrapped_secret = g_memdup2 (wrapped_secret_item.data,
			      wrapped_secret_item.len);
  *wrapped_secret_size = wrapped_secret_item.len;
  SECITEM_FreeItem (&wrapped_secret_item, PR_FALSE);
  return 0;

 err_wrapping_param:
  SECITEM_FreeItem (wrapping_param, PR_TRUE);
 err_secret_key:
  PK11_FreeSymKey (secret_key);
 err:
  return -1;
}

/* Unwrap WRAPPED_SECRET_DATA of WRAPPED_SECRET_SIZE with IV of IV_SIZE with
   WRAPPING_KEY using MECHANISM.
   Return plaintext secret (for (g_free ()), setting CLEAR_SECRET_SIZE to the
   size of the result, on success, NULL otherwise. */
void *
unwrap_symmetric (size_t *clear_secret_size, PK11SymKey *wrapping_key,
		  CK_MECHANISM_TYPE mechanism, const void *wrapped_secret_data,
		  size_t wrapped_secret_size, const void *iv, size_t iv_size,
		  GError **error)
{
  PK11SymKey *secret_key;
  SECItem iv_item, *wrapping_param, wrapped_secret_item, *clear_secret_item;
  void *ret;

  iv_item.data = (void *)iv;
  iv_item.len = iv_size;
  wrapping_param = PK11_ParamFromIV (mechanism, &iv_item);
  if (wrapping_param == NULL)
    {
      error_from_pr (error);
      goto err;
    }

  wrapped_secret_item.data = (void *)wrapped_secret_data;
  wrapped_secret_item.len = wrapped_secret_size;
  /* See the comment in wrap_symmetric() about CKM_GENERIC_SECRET_KEY_GEN. */
  secret_key = PK11_UnwrapSymKey (wrapping_key, mechanism,
				  wrapping_param, &wrapped_secret_item,
				  CKM_GENERIC_SECRET_KEY_GEN, CKA_UNWRAP, 0);
  SECITEM_FreeItem (wrapping_param, PR_TRUE);
  if (secret_key == NULL)
    {
      error_from_pr (error);
      goto err;
    }
  if (PK11_ExtractKeyValue (secret_key) != SECSuccess)
    {
      error_from_pr (error);
      goto err_secret_key;
    }
  clear_secret_item = PK11_GetKeyData (secret_key);
  ret = g_memdup2 (clear_secret_item->data, clear_secret_item->len);
  *clear_secret_size = clear_secret_item->len;
  PK11_FreeSymKey (secret_key);

  return ret;

 err_secret_key:
  PK11_FreeSymKey (secret_key);
 err:
  return NULL;
}
