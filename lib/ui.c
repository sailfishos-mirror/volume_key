/* User interaction context and handling.

Copyright (C) 2009 Red Hat, Inc. All rights reserved.
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

#include <glib.h>
#include <glib/gi18n-lib.h>

#include "libvolume_key.h"
#include "ui.h"

/* Create and return an empty context. */
struct libvk_ui *
libvk_ui_new (void)
{
  return g_new0 (struct libvk_ui, 1);
}

/* Free an user interaction context. */
void
libvk_ui_free (struct libvk_ui *ui)
{
  g_return_if_fail (ui != NULL);
  if (ui->generic_free_data != NULL)
    ui->generic_free_data (ui->generic_data);
  if (ui->passphrase_free_data != NULL)
    ui->passphrase_free_data (ui->passphrase_data);
  if (ui->nss_pwfn_free_arg != NULL)
    ui->nss_pwfn_free_arg (ui->nss_pwfn_arg);
  g_free (ui);
}

/* Set a generic conversation callback of UI to CB with DATA.
   This callback is used if a more specific callback is not define or not set.

   The callback is called with the supplied data, a prompt, and an indication
   whether the response should be echoed.  It returns a response (for
   g_free ()), or NULL on error.

   Upon libvk_ui_free (UI), FREE_DATA (DATA) will be called if FREE_DATA is not
   NULL. */
void
libvk_ui_set_generic_cb (struct libvk_ui *ui,
			 char *(*cb) (void *data, const char *prompt, int echo),
			 void *data, void (*free_data) (void *data))
{
  g_return_if_fail (ui != NULL);
  ui->generic_cb = cb;
  ui->generic_data = data;
  ui->generic_free_data = free_data;
}

/* Set a simple passphrase callback of UI to CB with DATA.
   The callback is used to collect a passphrase or passphrase (which should
   probably not be echoed), using a simple prompt.

   The callbacks is called with the supplied data, a prompt, and number of
   preceding failed attempts.  It returns a passphrase (for g_free ()), or
   NULL on error.

   Upon libvk_ui_free (UI), FREE_DATA (DATA) will be called if FREE_DATA is not
   NULL. */
void
libvk_ui_set_passphrase_cb (struct libvk_ui *ui,
			  char *(*cb) (void *data, const char *prompt,
				       unsigned failed_attempts),
			  void *data, void (*free_data) (void *data))
{
  g_return_if_fail (ui != NULL);
  ui->passphrase_cb = cb;
  ui->passphrase_data = data;
  ui->passphrase_free_data = free_data;
}

/* Set a NSS password callback (set by PK11_SetPasswordFunc) parameter to DATA.

   Upon libvk_ui_free (UI), FREE_DATA (DATA) will be called if FREE_DATA is not
   NULL. */
void
libvk_ui_set_nss_pwfn_arg (struct libvk_ui *ui, void *data,
			   void (*free_data) (void *data))
{
  g_return_if_fail (ui != NULL);
  ui->nss_pwfn_arg = data;
  ui->nss_pwfn_free_arg = free_data;
}

/* Get a passphrase using UI, using PROMPT; there were FAILED_ATTEMPTS before.

   Return a passphrase (for g_free()), or NULL. */
char *
ui_get_passphrase (const struct libvk_ui *ui, const char *prompt,
		   unsigned failed_attempts, GError **error)
{
  char *res;

  if (ui->passphrase_cb != NULL)
    res = ui->passphrase_cb (ui->passphrase_data, prompt, failed_attempts);
  else if (ui->generic_cb != NULL)
    res = ui->generic_cb (ui->generic_data, prompt, 0);
  else
    {
      g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_FAILED,
		   _("User interface callbacks not provided"));
      return NULL;
    }
  if (res != NULL)
    return res;
  g_set_error (error, LIBVK_ERROR, LIBVK_ERROR_UI_NO_RESPONSE,
	       _("Passphrase not provided"));
  return NULL;
}
