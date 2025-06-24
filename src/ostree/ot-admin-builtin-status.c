/*
 * Copyright (C) 2012,2013 Colin Walters <walters@verbum.org>
 *
 * SPDX-License-Identifier: LGPL-2.0+
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <https://www.gnu.org/licenses/>.
 *
 * Author: Colin Walters <walters@verbum.org>
 */

#include "config.h"

#include "libglnx.h"
#include "ostree.h"
#include "ot-admin-builtins.h"
#include "ot-admin-functions.h"

#include <glib/gi18n.h>

static gboolean opt_verify;
static gboolean opt_skip_signatures;
static gboolean opt_is_default;

static GOptionEntry options[]
    = { { "verify", 'V', 0, G_OPTION_ARG_NONE, &opt_verify, "Print the commit verification status",
          NULL },
        { "skip-signatures", 'S', 0, G_OPTION_ARG_NONE, &opt_skip_signatures,
          "Skip signatures in output", NULL },
        { "is-default", 'D', 0, G_OPTION_ARG_NONE, &opt_is_default,
          "Output \"default\" if booted into the default deployment, otherwise \"not-default\"",
          NULL },
        { NULL } };

static gboolean
deployment_is_prepared_for_soft_reboot (OstreeSysroot *sysroot, OstreeDeployment *deployment)
{
  // Check if /run/ostree/nextroot-booted exists (indicating a soft-reboot is prepared)
  if (!g_file_test ("/run/ostree/nextroot-booted", G_FILE_TEST_EXISTS))
    return FALSE;

  // Also verify that /run/nextroot actually contains a deployment
  if (!g_file_test ("/run/nextroot", G_FILE_TEST_IS_DIR))
    return FALSE;

  // Check if /run/nextroot has actual content (not just an empty directory)
  if (!g_file_test ("/run/nextroot/sysroot", G_FILE_TEST_IS_DIR))
    return FALSE;

  // Load the metadata from the nextroot-booted file
  gchar *metadata_contents = NULL;
  gsize metadata_length = 0;
  g_autoptr(GError) local_error = NULL;
  if (!g_file_get_contents ("/run/ostree/nextroot-booted", &metadata_contents, &metadata_length, &local_error))
    {
      g_debug ("Failed to read /run/ostree/nextroot-booted: %s", local_error->message);
      return FALSE;
    }

  g_autoptr(GBytes) metadata_bytes = g_bytes_new_take (metadata_contents, metadata_length);
  g_autoptr(GVariant) metadata = g_variant_new_from_bytes (G_VARIANT_TYPE ("a{sv}"), 
                                                           metadata_bytes, FALSE);
  if (!metadata)
    {
      g_debug ("Failed to parse metadata from /run/ostree/nextroot-booted");
      return FALSE;
    }

  // Get the backing device/inode from metadata
  guint64 backing_dev, backing_ino;
  g_autoptr(GVariant) backing_devino = g_variant_lookup_value (metadata, "backing-root-device-inode", G_VARIANT_TYPE ("(tt)"));
  if (!backing_devino)
    {
      g_debug ("No backing-root-device-inode found in nextroot-booted metadata");
      return FALSE;
    }
  
  g_variant_get (backing_devino, "(tt)", &backing_dev, &backing_ino);

  // Get the deployment's actual device/inode
  g_autofree char *deployment_path = ostree_sysroot_get_deployment_dirpath (sysroot, deployment);
  g_autofree char *sysroot_path = g_file_get_path (ostree_sysroot_get_path (sysroot));
  g_autofree char *deployment_full_path = g_build_filename (sysroot_path, deployment_path, NULL);
  
  struct stat deployment_stat;
  if (lstat (deployment_full_path, &deployment_stat) < 0)
    {
      g_debug ("Failed to stat deployment at %s", deployment_full_path);
      return FALSE;
    }

  // Compare device/inode
  return (deployment_stat.st_dev == backing_dev && deployment_stat.st_ino == backing_ino);
}

static gboolean
deployment_print_status (OstreeSysroot *sysroot, OstreeRepo *repo, OstreeDeployment *deployment,
                         gboolean is_booted, gboolean is_pending, gboolean is_rollback,
                         GCancellable *cancellable, GError **error)
{
  const char *ref = ostree_deployment_get_csum (deployment);

  /* Load the backing commit; shouldn't normally fail, but if it does,
   * we stumble on.
   */
  g_autoptr (GVariant) commit = NULL;
  (void)ostree_repo_load_variant (repo, OSTREE_OBJECT_TYPE_COMMIT, ref, &commit, NULL);
  g_autoptr (GVariant) commit_metadata = NULL;
  if (commit)
    commit_metadata = g_variant_get_child_value (commit, 0);
  g_autoptr (GVariant) commit_detached_metadata = NULL;
  if (commit)
    {
      if (!ostree_repo_read_commit_detached_metadata (repo, ref, &commit_detached_metadata,
                                                      cancellable, error))
        return FALSE;
    }

  const char *version = NULL;
  const char *source_title = NULL;
  if (commit_metadata)
    {
      (void)g_variant_lookup (commit_metadata, OSTREE_COMMIT_META_KEY_VERSION, "&s", &version);
      (void)g_variant_lookup (commit_metadata, OSTREE_COMMIT_META_KEY_SOURCE_TITLE, "&s",
                              &source_title);
    }

  GKeyFile *origin = ostree_deployment_get_origin (deployment);
  g_autofree char *origin_refspec
      = origin ? g_key_file_get_string (origin, "origin", "refspec", NULL) : NULL;

  g_autoptr (GString) deployment_status = g_string_new ("");
  gboolean is_soft_reboot_prepared = deployment_is_prepared_for_soft_reboot (sysroot, deployment);

  if (ostree_deployment_is_finalization_locked (deployment))
    g_string_append (deployment_status, " (finalization locked)");
  else if (ostree_deployment_is_staged (deployment))
    g_string_append (deployment_status, " (staged)");
  else if (is_pending)
    g_string_append (deployment_status, " (pending)");
  else if (is_rollback)
    g_string_append (deployment_status, " (rollback)");

  if (is_soft_reboot_prepared)
    g_string_append (deployment_status, " (soft-reboot)");

  char deployment_marker = is_booted ? '*' : ' ';
  g_print ("%c %s %s.%d%s\n", deployment_marker, ostree_deployment_get_osname (deployment),
           ostree_deployment_get_csum (deployment), ostree_deployment_get_deployserial (deployment),
           deployment_status->str);
  if (version)
    g_print ("    Version: %s\n", version);

  OstreeDeploymentUnlockedState unlocked = ostree_deployment_get_unlocked (deployment);
  switch (unlocked)
    {
    case OSTREE_DEPLOYMENT_UNLOCKED_NONE:
      break;
    default:
      g_print ("    %s%sUnlocked: %s%s%s\n", ot_get_red_start (), ot_get_bold_start (),
               ostree_deployment_unlocked_state_to_string (unlocked), ot_get_bold_end (),
               ot_get_red_end ());
    }
  if (ostree_deployment_is_pinned (deployment))
    g_print ("    Pinned: yes\n");
  if (!origin)
    g_print ("    origin: none\n");
  else
    {
      if (!origin_refspec)
        g_print ("    origin: <unknown origin type>\n");
      else
        g_print ("    origin refspec: %s\n", origin_refspec);
      if (source_title)
        g_print ("    `- %s\n", source_title);
    }

#ifndef OSTREE_DISABLE_GPGME
  g_autofree char *remote = NULL;
  if (origin_refspec && !ostree_parse_refspec (origin_refspec, &remote, NULL, NULL))
    return FALSE;

  gboolean gpg_verify = FALSE;
  if (remote)
    (void)ostree_repo_remote_get_gpg_verify (repo, remote, &gpg_verify, NULL);
  if (!opt_skip_signatures && !opt_verify && gpg_verify)
    {
      g_assert (remote);
      g_autoptr (GString) output_buffer = g_string_sized_new (256);
      /* Print any digital signatures on this commit. */

      g_autoptr (GError) local_error = NULL;
      g_autoptr (OstreeGpgVerifyResult) result
          = ostree_repo_verify_commit_for_remote (repo, ref, remote, cancellable, &local_error);

      /* G_IO_ERROR_NOT_FOUND just means the commit is not signed. */
      if (g_error_matches (local_error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND))
        {
          g_clear_error (&local_error);
          return TRUE;
        }
      else if (local_error != NULL)
        {
          g_propagate_error (error, g_steal_pointer (&local_error));
          return glnx_prefix_error (error, "Deployment %i",
                                    ostree_deployment_get_index (deployment));
        }

      const guint n_signatures = ostree_gpg_verify_result_count_all (result);
      for (guint jj = 0; jj < n_signatures; jj++)
        {
          ostree_gpg_verify_result_describe (result, jj, output_buffer,
                                             "    GPG: ", OSTREE_GPG_SIGNATURE_FORMAT_DEFAULT);
        }

      g_print ("%s", output_buffer->str);
    }
#else
  g_autofree char *remote = NULL;
#endif /* OSTREE_DISABLE_GPGME */
  if (opt_verify)
    {
      if (!commit)
        return glnx_throw (error, "Cannot verify, failed to load commit");
      if (origin_refspec == NULL)
        return glnx_throw (error, "No origin/refspec, cannot verify");
      if (remote == NULL)
        return glnx_throw (error, "Cannot verify deployment without remote");

      g_autoptr (GBytes) commit_data = g_variant_get_data_as_bytes (commit);
      g_autoptr (GBytes) commit_detached_metadata_bytes
          = commit_detached_metadata ? g_variant_get_data_as_bytes (commit_detached_metadata)
                                     : NULL;
      g_autofree char *verify_text = NULL;
      if (!ostree_repo_signature_verify_commit_data (
              repo, remote, commit_data, commit_detached_metadata_bytes, 0, &verify_text, error))
        return FALSE;
      g_print ("%s\n", verify_text);
    }

  return TRUE;
}

gboolean
ot_admin_builtin_status (int argc, char **argv, OstreeCommandInvocation *invocation,
                         GCancellable *cancellable, GError **error)
{
  g_autoptr (GOptionContext) context = g_option_context_new ("");

  g_autoptr (OstreeSysroot) sysroot = NULL;
  if (!ostree_admin_option_context_parse (context, options, &argc, &argv,
                                          OSTREE_ADMIN_BUILTIN_FLAG_UNLOCKED, invocation, &sysroot,
                                          cancellable, error))
    return FALSE;

  g_autoptr (OstreeRepo) repo = NULL;
  if (!ostree_sysroot_get_repo (sysroot, &repo, cancellable, error))
    return FALSE;

  g_autoptr (GPtrArray) deployments = ostree_sysroot_get_deployments (sysroot);
  OstreeDeployment *booted_deployment = ostree_sysroot_get_booted_deployment (sysroot);

  g_autoptr (OstreeDeployment) pending_deployment = NULL;
  g_autoptr (OstreeDeployment) rollback_deployment = NULL;
  if (booted_deployment)
    ostree_sysroot_query_deployments_for (sysroot, NULL, &pending_deployment, &rollback_deployment);

  if (opt_is_default)
    {
      if (deployments->len == 0)
        return glnx_throw (error, "Not in a booted OSTree system");

      const gboolean is_default_booted = deployments->pdata[0] == booted_deployment;
      g_print ("%s\n", is_default_booted ? "default" : "not-default");
    }
  else if (deployments->len == 0)
    {
      g_print ("No deployments.\n");
    }
  else
    {
      for (guint i = 0; i < deployments->len; i++)
        {
          OstreeDeployment *deployment = deployments->pdata[i];
          if (!deployment_print_status (sysroot, repo, deployment, deployment == booted_deployment,
                                        deployment == pending_deployment,
                                        deployment == rollback_deployment, cancellable, error))
            return FALSE;
        }
    }

  return TRUE;
}
