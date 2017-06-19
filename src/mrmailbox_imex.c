/*******************************************************************************
 *
 *                              Delta Chat Core
 *                      Copyright (C) 2017 Björn Petersen
 *                   Contact: r10s@b44t.com, http://b44t.com
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see http://www.gnu.org/licenses/ .
 *
 *******************************************************************************
 *
 * File:    mrmailbox_imex.c - Import and Export things
 *
 ******************************************************************************/


#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/rand.h>
#include <libetpan/mmapstring.h>
#include "mrmailbox.h"
#include "mrmimeparser.h"
#include "mrosnative.h"
#include "mraheader.h"
#include "mrapeerstate.h"
#include "mrtools.h"
#include "mre2ee_driver.h"

static int s_imex_do_exit = 1; /* the value 1 avoids MR_IMEX_CANCEL from stopping already stopped threads */


/*******************************************************************************
 * Import
 ******************************************************************************/


static int poke_public_key(mrmailbox_t* mailbox, const char* addr, const char* public_key_file)
{
	/* mainly for testing: if the partner does not support Autocrypt,
	encryption is disabled as soon as the first messages comes from the partner */
	mraheader_t*    header = mraheader_new();
	mrapeerstate_t* peerstate = mrapeerstate_new();
	int             locked = 0, success = 0;

	if( addr==NULL || public_key_file==NULL || peerstate==NULL || header==NULL ) {
		goto cleanup;
	}

	/* create a fake autocrypt header */
	header->m_addr             = safe_strdup(addr);
	header->m_prefer_encrypt   = MRA_PE_MUTUAL;
	if( !mrkey_set_from_file(header->m_public_key, public_key_file, mailbox)
	 || !mre2ee_driver_is_valid_key(mailbox, header->m_public_key) ) {
		mrmailbox_log_warning(mailbox, 0, "No valid key found in \"%s\".", public_key_file);
		goto cleanup;
	}

	/* update/create peerstate */
	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		if( mrapeerstate_load_from_db__(peerstate, mailbox->m_sql, addr) ) {
			mrapeerstate_apply_header(peerstate, header, time(NULL));
			mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 0);
		}
		else {
			mrapeerstate_init_from_header(peerstate, header, time(NULL));
			mrapeerstate_save_to_db__(peerstate, mailbox->m_sql, 1);
		}

		success = 1;

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	mrapeerstate_unref(peerstate);
	mraheader_unref(header);
	return success;
}


int mrmailbox_poke_spec(mrmailbox_t* mailbox, const char* spec__) /* spec is a file, a directory or NULL for the last import */
{
	int            success = 0;
	char*          spec = NULL;
	char*          suffix = NULL;
	DIR*           dir = NULL;
	struct dirent* dir_entry;
	int            read_cnt = 0;
	char*          name;

	if( mailbox == NULL ) {
		return 0;
	}

	if( !mrsqlite3_is_open(mailbox->m_sql) ) {
        mrmailbox_log_error(mailbox, 0, "Import: Database not opened.");
		goto cleanup;
	}

	/* if `spec` is given, remember it for later usage; if it is not given, try to use the last one */
	if( spec__ )
	{
		spec = safe_strdup(spec__);
		mrsqlite3_lock(mailbox->m_sql);
			mrsqlite3_set_config__(mailbox->m_sql, "import_spec", spec);
		mrsqlite3_unlock(mailbox->m_sql);
	}
	else {
		mrsqlite3_lock(mailbox->m_sql);
			spec = mrsqlite3_get_config__(mailbox->m_sql, "import_spec", NULL); /* may still NULL */
		mrsqlite3_unlock(mailbox->m_sql);
		if( spec == NULL ) {
			mrmailbox_log_error(mailbox, 0, "Import: No file or folder given.");
			goto cleanup;
		}
	}

	suffix = mr_get_filesuffix_lc(spec);
	if( suffix && strcmp(suffix, "eml")==0 ) {
		/* import a single file */
		if( mrmailbox_poke_eml_file(mailbox, spec) ) { /* errors are logged in any case */
			read_cnt++;
		}
	}
	else if( suffix && (strcmp(suffix, "pem")==0||strcmp(suffix, "asc")==0) ) {
		/* import a publix key */
		char* separator = strchr(spec, ' ');
		if( separator==NULL ) {
			mrmailbox_log_error(mailbox, 0, "Import: Key files must be specified as \"<addr> <key-file>\".");
			goto cleanup;
		}
		*separator = 0;
		if( poke_public_key(mailbox, spec, separator+1) ) {
			read_cnt++;
		}
		*separator = ' ';
	}
	else {
		/* import a directory */
		if( (dir=opendir(spec))==NULL ) {
			mrmailbox_log_error(mailbox, 0, "Import: Cannot open directory \"%s\".", spec);
			goto cleanup;
		}

		while( (dir_entry=readdir(dir))!=NULL ) {
			name = dir_entry->d_name; /* name without path; may also be `.` or `..` */
			if( strlen(name)>=4 && strcmp(&name[strlen(name)-4], ".eml")==0 ) {
				char* path_plus_name = mr_mprintf("%s/%s", spec, name);
				mrmailbox_log_info(mailbox, 0, "Import: %s", path_plus_name);
				if( mrmailbox_poke_eml_file(mailbox, path_plus_name) ) { /* no abort on single errors errors are logged in any case */
					read_cnt++;
				}
				free(path_plus_name);
            }
		}
	}

	mrmailbox_log_info(mailbox, 0, "Import: %i items read from \"%s\".", read_cnt, spec);
	if( read_cnt > 0 ) {
		mailbox->m_cb(mailbox, MR_EVENT_MSGS_CHANGED, 0, 0); /* even if read_cnt>0, the number of messages added to the database may be 0. While we regard this issue using IMAP, we ignore it here. */
	}

	/* success */
	success = 1;

	/* cleanup */
cleanup:
	if( dir ) {
		closedir(dir);
	}
	free(spec);
	free(suffix);
	return success;
}


static int import_self_keys(mrmailbox_t* mailbox, const char* dir_name)
{
	int            imported_count = 0, locked = 0;
	DIR*           dir_handle = NULL;
	struct dirent* dir_entry = NULL;
	char*          suffix = NULL;
	char*          path_plus_name = NULL;
	mrkey_t*       private_key = mrkey_new();
	mrkey_t*       public_key = mrkey_new();
	sqlite3_stmt*  stmt = NULL;
	char*          self_addr = NULL;

	if( mailbox==NULL || dir_name==NULL ) {
		goto cleanup;
	}

	if( (dir_handle=opendir(dir_name))==NULL ) {
		mrmailbox_log_error(mailbox, 0, "Import: Cannot open directory \"%s\".", dir_name);
		goto cleanup;
	}

	while( (dir_entry=readdir(dir_handle))!=NULL )
	{
		free(suffix);
		suffix = mr_get_filesuffix_lc(dir_entry->d_name);
		if( suffix==NULL || strcmp(suffix, "asc")!=0 ) {
			continue;
		}

		free(path_plus_name);
		path_plus_name = mr_mprintf("%s/%s", dir_name, dir_entry->d_name/* name without path; may also be `.` or `..` */);
		mrmailbox_log_info(mailbox, 0, "Checking: %s", path_plus_name);
		if( !mrkey_set_from_file(private_key, path_plus_name, mailbox) ) {
			mrmailbox_log_error(mailbox, 0, "Cannot read key from \"%s\".", path_plus_name);
			continue;
		}

		if( private_key->m_type!=MR_PRIVATE ) {
			continue; /* this is no error but quite normal as we always export the public keys together with the private ones */
		}

		if( !mre2ee_driver_is_valid_key(mailbox, private_key) ) {
			mrmailbox_log_error(mailbox, 0, "\"%s\" is no valid key.", path_plus_name);
			continue;
		}

		if( !mre2ee_driver_split_key(mailbox, private_key, public_key) ) {
			mrmailbox_log_error(mailbox, 0, "\"%s\" seems not to contain a private key.", path_plus_name);
			continue;
		}

		/* add keypair as default; before this, delete other keypairs with the same binary key and reset defaults */
		mrsqlite3_lock(mailbox->m_sql);
		locked = 1;

			stmt = mrsqlite3_prepare_v2_(mailbox->m_sql, "DELETE FROM keypairs WHERE public_key=? OR private_key=?;");
			sqlite3_bind_blob (stmt, 1, public_key->m_binary, public_key->m_bytes, SQLITE_STATIC);
			sqlite3_bind_blob (stmt, 2, private_key->m_binary, private_key->m_bytes, SQLITE_STATIC);
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
			stmt = NULL;

			mrsqlite3_execute__(mailbox->m_sql, "UPDATE keypairs SET is_default=0;");

			free(self_addr);
			self_addr = mrsqlite3_get_config__(mailbox->m_sql, "configured_addr", NULL);
			if( !mrkey_save_self_keypair__(public_key, private_key, self_addr, mailbox->m_sql) ) {
				mrmailbox_log_error(mailbox, 0, "Cannot save keypair.");
				goto cleanup;
			}

			imported_count++;

		mrsqlite3_unlock(mailbox->m_sql);
		locked = 0;
	}

	if( imported_count == 0 ) {
		mrmailbox_log_error(mailbox, 0, "No private keys found in \"%s\".", dir_name);
		goto cleanup;
	}

cleanup:
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	if( dir_handle ) { closedir(dir_handle); }
	free(suffix);
	free(path_plus_name);
	mrkey_unref(private_key);
	mrkey_unref(public_key);
	if( stmt ) { sqlite3_finalize(stmt); }
	free(self_addr);
	return imported_count;
}


/*******************************************************************************
 * Export keys
 ******************************************************************************/


/* a complete Autocrypt Setup Message looks like the following

To: me@mydomain.com
From: me@mydomain.com
Autocrypt-Setup-Message: v1
Content-type: multipart/mixed; boundary="==break1=="

	--==break1==
	Content-Type: text/plain

	This is the Autocrypt setup message.

	--==break1==
	Content-Type: application/autocrypt-key-backup
	Content-Disposition: attachment; filename="autocrypt-key-backup.html"

	<html>
	<body>
	<p>
		This is the Autocrypt setup file used to transfer keys between clients.
	</p>
	<pre>
	-----BEGIN PGP MESSAGE-----
	Version: BCPG v1.53
	Passphrase-Format: numeric9x4
	Passphrase-Begin: 12

	hQIMAxC7JraDy7DVAQ//SK1NltM+r6uRf2BJEg+rnpmiwfAEIiopU0LeOQ6ysmZ0
	CLlfUKAcryaxndj4sBsxLllXWzlNiFDHWw4OOUEZAZd8YRbOPfVq2I8+W4jO3Moe
	-----END PGP MESSAGE-----
	</pre>
	</body>
	</html>
	--==break1==--

The encrypted message part contains:

	Content-type: multipart/mixed; boundary="==break2=="
	Autocrypt-Prefer-Encrypt: mutual

	--==break2==
	Content-type: application/autocrypt-key-backup

	-----BEGIN PGP PRIVATE KEY BLOCK-----
	Version: GnuPG v1.2.3 (GNU/Linux)

	xcLYBFke7/8BCAD0TTmX9WJm9elc7/xrT4/lyzUDMLbuAuUqRINtCoUQPT2P3Snfx/jou1YcmjDgwT
	Ny9ddjyLcdSKL/aR6qQ1UBvlC5xtriU/7hZV6OZEmW2ckF7UgGd6ajE+UEjUwJg2+eKxGWFGuZ1P7a
	4Av1NXLayZDsYa91RC5hCsj+umLN2s+68ps5pzLP3NoK2zIFGoCRncgGI/pTAVmYDirhVoKh14hCh5
	.....
	-----END PGP PRIVATE KEY BLOCK-----
	--==break2==--

mrmailbox_render_keys_to_html() renders the part after the second `-==break1==` part in this example. */
int mrmailbox_render_keys_to_html(mrmailbox_t* mailbox, const char* setup_code, char** ret_msg)
{
	int                    success = 0, locked = 0, col = 0;
	sqlite3_stmt*          stmt = NULL;
	mrkey_t*               private_key = mrkey_new();
	struct mailmime*       payload_mime_msg = NULL;
	struct mailmime*       payload_mime_anchor = NULL;
	MMAPString*            payload_string = mmap_string_new("");

	if( mailbox==NULL || setup_code==NULL || ret_msg==NULL
	 || *ret_msg!=NULL || private_key==NULL || payload_string==NULL ) {
		goto cleanup;
	}

	/* create the payload */
	payload_mime_anchor = mailmime_new_empty(mailmime_content_new_with_str("multipart/mixed"), mailmime_fields_new_empty());
	payload_mime_msg    = mailmime_new_message_data(payload_mime_anchor);

	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;

		int e2ee_enabled = mrsqlite3_get_config_int__(mailbox->m_sql, "e2ee_enabled", MR_E2EE_DEFAULT_ENABLED);

		struct mailimf_fields* imffields = mailimf_fields_new_empty();
		mailimf_fields_add(imffields, mailimf_field_new_custom(strdup("Autocrypt-Prefer-Encrypt"), strdup(e2ee_enabled? "mutual" : "nopreference")));
		mailmime_set_imf_fields(payload_mime_msg, imffields);

		if( (stmt=mrsqlite3_prepare_v2_(mailbox->m_sql, "SELECT private_key FROM keypairs ORDER BY addr=? DESC, is_default DESC;"))==NULL ) {
			goto cleanup;
		}

		while( sqlite3_step(stmt)==SQLITE_ROW )
		{
			if( !mrkey_set_from_stmt(private_key, stmt, 0, MR_PRIVATE) ) {
				goto cleanup;
			}

			char* key_asc = mrkey_render_asc(private_key);
			if( key_asc == NULL ) {
				goto cleanup;
			}

			struct mailmime_content* content_type = mailmime_content_new_with_str("application/autocrypt-key-backup");
			struct mailmime_fields* mime_fields = mailmime_fields_new_empty();
			struct mailmime* key_mime = mailmime_new_empty(content_type, mime_fields);
			mailmime_set_body_text(key_mime, key_asc, strlen(key_asc));

			mailmime_smart_add_part(payload_mime_anchor, key_mime);
		}

	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	mailmime_write_mem(payload_string, &col, payload_mime_msg);
	//char* t2=mr_null_terminate(payload_string->str,payload_string->len);printf("\n~~~~~~~~~~~~~~~~~~~~SETUP-PAYLOAD~~~~~~~~~~~~~~~~~~~~\n%s~~~~~~~~~~~~~~~~~~~~/SETUP-PAYLOAD~~~~~~~~~~~~~~~~~~~~\n",t2);free(t2); // DEBUG OUTPUT

	/* encrypt the payload using the setup code */

	//AES_encrypt();
	// TODO

	/* wrap HTML-commands with instructions around the encrypted payload */

	// TODO

	success = 1;

cleanup:
	if( stmt ) { sqlite3_finalize(stmt); }
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }
	if( payload_mime_msg && payload_mime_anchor ) {
		clistiter* cur;
		for( cur=clist_begin(payload_mime_anchor->mm_data.mm_multipart.mm_mp_list); cur!=NULL; cur=clist_next(cur)) { /* looks complicated, but only free()'s the pointers allocated above (they're used by mime, but not owned by it) */
			struct mailmime* key_mime = (struct mailmime*)clist_content(cur);
			if( key_mime->mm_type==MAILMIME_SINGLE
			 && key_mime->mm_data.mm_single->dt_type==MAILMIME_DATA_TEXT ) {
				char* key_asc = (char*)key_mime->mm_data.mm_single->dt_data.dt_text.dt_data;
				free(key_asc);
			}
		}
		mailmime_free(payload_mime_msg);
	}
	if( payload_string ) { mmap_string_free(payload_string); }
	return success;
}


static int export_self_keys(mrmailbox_t* mailbox, const char* dir, const char* setup_code)
{
	int           success = 0;
	char*         file_content = NULL;
	char*         file_name = mr_mprintf("%s/autocrypt-key-backup.html", dir);

	if( !mrmailbox_render_keys_to_html(mailbox, setup_code, &file_content) || file_content==NULL ) {
		mrmailbox_log_error(mailbox, 0, "Cannot generate Autocrypt setup file in %s", file_name);
		goto cleanup;
	}

	if( !mr_write_file(file_name, file_content, strlen(file_content), mailbox) ) {
		mrmailbox_log_error(mailbox, 0, "Cannot write keys to %s", file_name);
	}
	else {
		mailbox->m_cb(mailbox, MR_EVENT_IMEX_FILE_WRITTEN, (uintptr_t)file_name, (uintptr_t)"application/autocrypt-key-backup");
	}

	success = 1;

cleanup:
	free(file_content);
	free(file_name);
	return success;
}


/*******************************************************************************
 * Export backup
 ******************************************************************************/


static int export_backup(mrmailbox_t* mailbox, const char* dir, const char* setup_code)
{
	int            success = 0, locked = 0, closed = 0;
	char*          dest_pathNfilename = NULL;
	mrsqlite3_t*   dest_sql = NULL;
	time_t         now = time(NULL);
	DIR*           dir_handle = NULL;
	struct dirent* dir_entry;
	int            prefix_len = strlen(MR_BAK_PREFIX);
	int            suffix_len = strlen(MR_BAK_SUFFIX);
	char*          curr_pathNfilename = NULL;
	void*          buf = NULL;
	size_t         buf_bytes = 0;
	sqlite3_stmt*  stmt = NULL;
	int            total_files_count = 0, processed_files_count = 0;
	int            delete_dest_file = 0;

	/* get a fine backup file name (the name includes the date so that multiple backup instances are possible) */
	{
		struct tm* timeinfo;
		char buffer[256];
		timeinfo = localtime(&now);
		strftime(buffer, 256, MR_BAK_PREFIX "-%Y-%m-%d." MR_BAK_SUFFIX, timeinfo);
		if( (dest_pathNfilename=mr_get_fine_pathNfilename(dir, buffer))==NULL ) {
			mrmailbox_log_error(mailbox, 0, "Cannot get backup file name.");
			goto cleanup;
		}
	}

	/* temporary lock and close the source (we just make a copy of the whole file, this is the fastest and easiest approach) */
	mrsqlite3_lock(mailbox->m_sql);
	locked = 1;
	mrsqlite3_close__(mailbox->m_sql);
	closed = 1;

	/* copy file to backup directory */
	mrmailbox_log_info(mailbox, 0, "Backup \"%s\" to \"%s\".", mailbox->m_dbfile, dest_pathNfilename);
	if( !mr_copy_file(mailbox->m_dbfile, dest_pathNfilename, mailbox) ) {
		goto cleanup; /* error already logged */
	}

	/* unlock and re-open the source and make it availabe again for the normal use */
	mrsqlite3_open__(mailbox->m_sql, mailbox->m_dbfile);
	closed = 0;
	mrsqlite3_unlock(mailbox->m_sql);
	locked = 0;

	/* add all files as blobs to the database copy (this does not require the source to be locked, neigher the destination as it is used only here) */
	if( (dest_sql=mrsqlite3_new(mailbox/*for logging only*/))==NULL
	 || !mrsqlite3_open__(dest_sql, dest_pathNfilename) ) {
		goto cleanup; /* error already logged */
	}

	if( !mrsqlite3_table_exists__(dest_sql, "backup_blobs") ) {
		if( !mrsqlite3_execute__(dest_sql, "CREATE TABLE backup_blobs (id INTEGER PRIMARY KEY, file_name, file_content);") ) {
			goto cleanup; /* error already logged */
		}
	}

	/* scan directory, pass 1: collect file info */
	total_files_count = 0;
	if( (dir_handle=opendir(mailbox->m_blobdir))==NULL ) {
		mrmailbox_log_error(mailbox, 0, "Backup: Cannot get info for blob-directory \"%s\".", mailbox->m_blobdir);
		goto cleanup;
	}

	while( (dir_entry=readdir(dir_handle))!=NULL ) {
		total_files_count++;
	}

	closedir(dir_handle);
	dir_handle = NULL;

	if( total_files_count>0 )
	{
		/* scan directory, pass 2: copy files */
		if( (dir_handle=opendir(mailbox->m_blobdir))==NULL ) {
			mrmailbox_log_error(mailbox, 0, "Backup: Cannot copy from blob-directory \"%s\".", mailbox->m_blobdir);
			goto cleanup;
		}

		stmt = mrsqlite3_prepare_v2_(dest_sql, "INSERT INTO backup_blobs (file_name, file_content) VALUES (?, ?);");
		while( (dir_entry=readdir(dir_handle))!=NULL )
		{
			if( s_imex_do_exit ) {
				delete_dest_file = 1;
				goto cleanup;
			}

			processed_files_count++;

			int percent = (processed_files_count*100)/total_files_count;
			if( percent < 1 ) { percent = 1; }
			if( percent > 100 ) { percent = 100; }
			mailbox->m_cb(mailbox, MR_EVENT_IMEX_PROGRESS, percent, 0);

			char* name = dir_entry->d_name; /* name without path; may also be `.` or `..` */
			int name_len = strlen(name);
			if( (name_len==1 && name[0]=='.')
			 || (name_len==2 && name[0]=='.' && name[1]=='.')
			 || (name_len > prefix_len && strncmp(name, MR_BAK_PREFIX, prefix_len)==0 && name_len > suffix_len && strncmp(&name[name_len-suffix_len-1], "." MR_BAK_SUFFIX, suffix_len)==0) ) {
				//mrmailbox_log_info(mailbox, 0, "Backup: Skipping \"%s\".", name);
				continue;
			}

			//mrmailbox_log_info(mailbox, 0, "Backup \"%s\".", name);
			free(curr_pathNfilename);
			curr_pathNfilename = mr_mprintf("%s/%s", mailbox->m_blobdir, name);
			free(buf);
			if( !mr_read_file(curr_pathNfilename, &buf, &buf_bytes, mailbox) || buf==NULL || buf_bytes<=0 ) {
				continue;
			}

			sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
			sqlite3_bind_blob(stmt, 2, buf, buf_bytes, SQLITE_STATIC);
			if( sqlite3_step(stmt)!=SQLITE_DONE ) {
				mrmailbox_log_error(mailbox, 0, "Disk full? Cannot add file \"%s\" to backup.", curr_pathNfilename);
				goto cleanup; /* this is not recoverable! writing to the sqlite database should work! */
			}
			sqlite3_reset(stmt);
		}
	}
	else
	{
		mrmailbox_log_info(mailbox, 0, "Backup: No files to copy.", mailbox->m_blobdir);
	}

	/* done - set some special config values (do this last to avoid importing crashed backups) */
	mrsqlite3_set_config_int__(dest_sql, "backup_time", now);
	mrsqlite3_set_config__    (dest_sql, "backup_for", mailbox->m_blobdir);

	mailbox->m_cb(mailbox, MR_EVENT_IMEX_FILE_WRITTEN, (uintptr_t)dest_pathNfilename, (uintptr_t)"application/octet-stream");
	success = 1;

cleanup:
	if( dir_handle ) { closedir(dir_handle); }
	if( closed ) { mrsqlite3_open__(mailbox->m_sql, mailbox->m_dbfile); }
	if( locked ) { mrsqlite3_unlock(mailbox->m_sql); }

	if( stmt ) { sqlite3_finalize(stmt); }
	mrsqlite3_close__(dest_sql);
	mrsqlite3_unref(dest_sql);
	if( delete_dest_file ) { mr_delete_file(dest_pathNfilename, mailbox); }
	free(dest_pathNfilename);

	free(curr_pathNfilename);
	free(buf);
	return success;
}


/*******************************************************************************
 * Import/Export Thread and Main Interface
 ******************************************************************************/


typedef struct mrimexthreadparam_t
{
	mrmailbox_t* m_mailbox;
	int          m_what;
	char*        m_dir;
	char*        m_setup_code;
} mrimexthreadparam_t;


static pthread_t s_imex_thread;
static int       s_imex_thread_created = 0;


static void* imex_thread_entry_point(void* entry_arg)
{
	int                  success = 0;
	mrimexthreadparam_t* thread_param = (mrimexthreadparam_t*)entry_arg;
	mrmailbox_t*         mailbox = thread_param->m_mailbox; /*keep a local pointer as we free thread_param sooner or later */

	mrosnative_setup_thread(mailbox); /* must be first */
	mrmailbox_log_info(mailbox, 0, "Import/export thread started.");

	if( !mrsqlite3_is_open(thread_param->m_mailbox->m_sql) ) {
        mrmailbox_log_error(mailbox, 0, "Import/export: Database not opened.");
		goto cleanup;
	}

	if( (thread_param->m_what&MR_IMEX_EXPORT_BITS)!=0 ) {
		/* before we export anything, make sure the private key exists */
		if( !mrmailbox_ensure_secret_key_exists(mailbox) ) {
			mrmailbox_log_error(mailbox, 0, "Import/export: Cannot create private key or private key not available.");
			goto cleanup;
		}
	}

	mr_create_folder(thread_param->m_dir, mailbox);

	switch( thread_param->m_what )
	{
		case MR_IMEX_EXPORT_SELF_KEYS:
			if( !export_self_keys(mailbox, thread_param->m_dir, thread_param->m_setup_code) ) {
				goto cleanup;
			}
			break;

		case MR_IMEX_IMPORT_SELF_KEYS:
			if( !import_self_keys(mailbox, thread_param->m_dir) ) {
				goto cleanup;
			}
			break;

		case MR_IMEX_EXPORT_BACKUP:
			if( !export_backup(mailbox, thread_param->m_dir, thread_param->m_setup_code) ) {
				goto cleanup;
			}
			break;
	}

	success = 1;

cleanup:
	mrmailbox_log_info(mailbox, 0, "Import/export thread ended.");
	s_imex_do_exit = 1; /* set this before sending MR_EVENT_EXPORT_ENDED, avoids MR_IMEX_CANCEL to stop the thread */
	mailbox->m_cb(mailbox, MR_EVENT_IMEX_ENDED, success, 0);
	s_imex_thread_created = 0;
	free(thread_param->m_dir);
	free(thread_param->m_setup_code);
	free(thread_param);
	mrosnative_unsetup_thread(mailbox); /* must be very last (here we really new the local copy of the pointer) */
	return NULL;
}


void mrmailbox_imex(mrmailbox_t* mailbox, int what, const char* dir, const char* setup_code)
{
	mrimexthreadparam_t* thread_param;

	if( mailbox==NULL || mailbox->m_sql==NULL ) {
		return;
	}

	if( what == MR_IMEX_CANCEL ) {
		/* cancel an running export */
		if( s_imex_thread_created && s_imex_do_exit==0 ) {
			mrmailbox_log_info(mailbox, 0, "Stopping import/export thread...");
				s_imex_do_exit = 1;
				pthread_join(s_imex_thread, NULL);
			mrmailbox_log_info(mailbox, 0, "Import/export thread stopped.");
		}
		return;
	}

	if( dir == NULL ) {
		mrmailbox_log_error(mailbox, 0, "No Import/export dir given.");
		return;
	}

	if( s_imex_thread_created || s_imex_do_exit==0 ) {
		mrmailbox_log_warning(mailbox, 0, "Already importing/exporting.");
		return;
	}
	s_imex_thread_created = 1;
	s_imex_do_exit = 0;

	memset(&s_imex_thread, 0, sizeof(pthread_t));
	thread_param = calloc(1, sizeof(mrimexthreadparam_t));
	thread_param->m_mailbox    = mailbox;
	thread_param->m_what       = what;
	thread_param->m_dir        = safe_strdup(dir);
	thread_param->m_setup_code = safe_strdup(setup_code); /*empty string if no code given, this will not work but also not crash.*/
	pthread_create(&s_imex_thread, NULL, imex_thread_entry_point, thread_param);
}


/* create an "Autocrypt Level 1" setup code in the form
1234-1234-1234-
1234-1234-1234-
1234-1234-1234
Linebreaks and spaces MUST NOT be added to the setup code, but the "-" are. */
char* mrmailbox_create_setup_code(mrmailbox_t* mailbox)
{
	#define   CODE_ELEMS 9
	#define   BUF_BYTES  (CODE_ELEMS*sizeof(uint16_t))
	uint16_t  buf[CODE_ELEMS];
	int       i;

	if( !RAND_bytes((unsigned char*)buf, BUF_BYTES) ) {
		mrmailbox_log_warning(mailbox, 0, "Falling back to pseudo-number generation for the setup code.");
		RAND_pseudo_bytes((unsigned char*)buf, BUF_BYTES);
	}

	for( i = 0; i < CODE_ELEMS; i++ ) {
		buf[i] = buf[i] % 10000; /* force all blocks into the range 0..9999 */
	}

	return mr_mprintf("%04i-%04i-%04i-"
	                  "%04i-%04i-%04i-"
	                  "%04i-%04i-%04i",
		(int)buf[0], (int)buf[1], (int)buf[2],
		(int)buf[3], (int)buf[4], (int)buf[5],
		(int)buf[6], (int)buf[7], (int)buf[8]);
}