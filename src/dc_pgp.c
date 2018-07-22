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
 ******************************************************************************/


/* End-to-end-encryption and other cryptographic functions based upon OpenSSL
and BSD's netpgp.

If we want to switch to other encryption engines, here are the functions to
be replaced.

However, eg. GpgME cannot (easily) be used standalone and GnuPG's licence
would not allow the original creator of Delta Chat to release a proprietary
version, which, however, is required for the Apple store. (NB: the original
creator is the only person who could do this, a normal licensee is not
allowed to do so at all)

So, we do not see a simple alternative - but everyone is welcome to implement
one :-) */


#include <sequoia.h>
#include <netpgp-extra.h>
#include <openssl/rand.h>
#include "dc_context.h"
#include "dc_key.h"
#include "dc_keyring.h"
#include "dc_pgp.h"
#include "dc_hash.h"


static int      s_io_initialized = 0;
static pgp_io_t s_io;


void dc_pgp_init(void)
{
	if (s_io_initialized) {
		return;
	}

	memset(&s_io, 0, sizeof(pgp_io_t));
	s_io.outs = stdout;
	s_io.errs = stderr;
	s_io.res  = stderr;

	s_io_initialized = 1;
}


void dc_pgp_exit(void)
{
}


void dc_pgp_rand_seed(dc_context_t* context, const void* buf, size_t bytes)
{
	if (buf==NULL || bytes<=0) {
		return;
	}

	RAND_seed(buf, bytes);
}


/* Split data from PGP Armored Data as defined in https://tools.ietf.org/html/rfc4880#section-6.2.
The given buffer is modified and the returned pointers just point inside the modified buffer,
no additional data to free therefore.
(NB: netpgp allows only parsing of Version, Comment, MessageID, Hash and Charset) */
int dc_split_armored_data(char* buf, const char** ret_headerline, const char** ret_setupcodebegin, const char** ret_preferencrypt, const char** ret_base64)
{
	int    success = 0;
	size_t line_chars = 0;
	char*  line = buf;
	char*  p1 = buf;
	char*  p2 = NULL;
	char*  headerline = NULL;
	char*  base64 = NULL;
	#define PGP_WS "\t\r\n "

	if (ret_headerline)     { *ret_headerline = NULL; }
	if (ret_setupcodebegin) { *ret_setupcodebegin = NULL; }
	if (ret_preferencrypt)  { *ret_preferencrypt = NULL; }
	if (ret_base64)         { *ret_base64 = NULL; }

	if (buf==NULL || ret_headerline==NULL) {
		goto cleanup;
	}

	dc_remove_cr_chars(buf);
	while (*p1) {
		if (*p1=='\n') {
			/* line found ... */
			line[line_chars] = 0;
			if (headerline==NULL) {
				/* ... headerline */
				dc_trim(line);
				if (strncmp(line, "-----BEGIN ", 11)==0 && strncmp(&line[strlen(line)-5], "-----", 5)==0) {
					headerline = line;
					if (ret_headerline) {
						*ret_headerline = headerline;
					}
				}
			}
			else if (strspn(line, PGP_WS)==strlen(line)) {
				/* ... empty line: base64 starts on next line */
				base64 = p1+1;
				break;
			}
			else if ((p2=strchr(line, ':'))==NULL) {
				/* ... non-standard-header without empty line: base64 starts with this line */
				line[line_chars] = '\n';
				base64 = line;
				break;
			}
			else {
				/* header line */
				*p2 = 0;
				dc_trim(line);
				if (strcasecmp(line, "Passphrase-Begin")==0) {
					p2++;
					dc_trim(p2);
					if (ret_setupcodebegin) {
						*ret_setupcodebegin = p2;
					}
				}
				else if (strcasecmp(line, "Autocrypt-Prefer-Encrypt")==0) {
					p2++;
					dc_trim(p2);
					if (ret_preferencrypt) {
						*ret_preferencrypt = p2;
					}
				}
			}

			/* prepare for next line */
			p1++;
			line = p1;
			line_chars = 0;
		}
		else {
			p1++;
			line_chars++;
		}
	}

	if (headerline==NULL || base64==NULL) {
		goto cleanup;
	}

	/* now, line points to beginning of base64 data, search end */
	if ((p1=strstr(base64, "-----END "/*the trailing space makes sure, this is not a normal base64 sequence*/))==NULL
	 || strncmp(p1+9, headerline+11, strlen(headerline+11))!=0) {
		goto cleanup;
	}

	*p1 = 0;
	dc_trim(base64);

	if (ret_base64) {
		*ret_base64 = base64;
	}

	success = 1;

cleanup:
	return success;
}


/*******************************************************************************
 * Key generatation
 ******************************************************************************/


int dc_pgp_create_keypair(dc_context_t* context, const char* addr, dc_key_t* ret_public_key, dc_key_t* ret_private_key)
{
	int              success = 0;
	char*            user_id = NULL;
	sq_status_t      rc;
	sq_tpk_t         tpk = NULL;
	sq_tsk_t         tsk = NULL;
	void*            buf = NULL;
	size_t           len = 0;
	sq_writer_t      w = NULL;

	if (context==NULL || addr==NULL || ret_public_key==NULL || ret_private_key==NULL) {
		goto cleanup;
	}

	/* Generate User ID.
	By convention, this is the e-mail-address in angle brackets.

	As the user-id is only decorative in Autocrypt and not needed for Delta Chat,
	so we _could_ just use sth. that looks like an e-mail-address.
	This would protect the user's privacy if someone else uploads the keys to keyservers.

	However, as eg. Enigmail displayes the user-id in "Good signature from <user-id>,
	for now, we decided to leave the address in the user-id */
	#if 0
		user_id = dc_mprintf("<%08X@%08X.org>", (int)random(), (int)random());
	#else
		user_id = dc_mprintf("<%s>", addr);
	#endif

	/* First, we generate a secret key and save it in
	   ret_private_key.  */
	tsk = sq_tsk_new(context->sq, user_id);
	if (tsk==NULL) {
		goto cleanup;
	}

	w = sq_writer_alloc(&buf, &len);
	rc = sq_tsk_serialize(context->sq, tsk, w);
	if (rc!=SQ_STATUS_SUCCESS) {
		goto cleanup;
	}
	sq_writer_free(w);
	w = NULL;

	dc_key_set_from_binary(ret_private_key, buf, len, DC_KEY_PUBLIC);
	free(buf);
	buf = NULL;
	len = 0;

	/* Second, we get a reference to the public parts, and save
	   them to ret_public_key.  This is a reference that we don't
	   need to free.  */
	tpk = sq_tsk_tpk(tsk);

	w = sq_writer_alloc(&buf, &len);
	rc = sq_tpk_serialize(context->sq, tpk, w);
	if (rc!=SQ_STATUS_SUCCESS) {
		goto cleanup;
	}
	sq_writer_free(w);
	w = NULL;

	dc_key_set_from_binary(ret_public_key, buf, len, DC_KEY_PRIVATE);
	success = 1;

cleanup:
	sq_writer_free(w);
	free(buf);
	sq_tsk_free(tsk);
	free(user_id);
	return success;
}


/*******************************************************************************
 * Check keys
 ******************************************************************************/


int dc_pgp_is_valid_key(dc_context_t* context, const dc_key_t* raw_key)
{
	int             key_is_valid = 0;
	sq_tpk_t        tpk;

	if (context==NULL || raw_key==NULL
	 || raw_key->binary==NULL || raw_key->bytes <= 0) {
		goto cleanup;
	}

	tpk = sq_tpk_from_bytes(context->sq, raw_key->binary, raw_key->bytes);
	key_is_valid = tpk != NULL;
	sq_tpk_free(tpk);

cleanup:
	return key_is_valid;
}


int dc_pgp_calc_fingerprint(const dc_key_t* raw_key, uint8_t** ret_fingerprint, size_t* ret_fingerprint_bytes)
{
	int             success = 0;
	sq_context_t    ctx;
	sq_tpk_t        tpk;
	sq_fingerprint_t fp;
	uint8_t*         fp_bytes;

	if (raw_key==NULL || ret_fingerprint==NULL || *ret_fingerprint!=NULL || ret_fingerprint_bytes==NULL || *ret_fingerprint_bytes!=0
	 || raw_key->binary==NULL || raw_key->bytes <= 0) {
		goto cleanup;
	}

	ctx = sq_context_new("delta.chat", NULL);
	tpk = sq_tpk_from_bytes(ctx, raw_key->binary, raw_key->bytes);
	sq_context_free(ctx);
	if (tpk==NULL) {
		goto cleanup;
	}

	fp = sq_tpk_fingerprint(tpk);
	sq_tpk_free(tpk);
	if (fp==NULL) {
		goto cleanup;
	}

	fp_bytes = sq_fingerprint_as_bytes(fp, ret_fingerprint_bytes);
	*ret_fingerprint = malloc(*ret_fingerprint_bytes);
	memcpy(*ret_fingerprint, fp_bytes, *ret_fingerprint_bytes);
	sq_fingerprint_free(fp);
	success = 1;

cleanup:
	return success;
}


int dc_pgp_split_key(dc_context_t* context, const dc_key_t* private_in, dc_key_t* ret_public_key)
{
	int             success = 0;
	sq_tpk_t        tpk;
	void*           buf = NULL;
	size_t          len = 0;
	sq_writer_t	w;

	if (context==NULL || private_in==NULL || ret_public_key==NULL) {
		goto cleanup;
	}

	tpk = sq_tpk_from_bytes(context->sq, private_in->binary, private_in->bytes);
	if (tpk==NULL) {
		goto cleanup;
	}

	w = sq_writer_alloc(&buf, &len);
	/* When we serialize a TPK, even if it originally contained
	   secret keys, we only get the public parts.  */
	sq_tpk_serialize(context->sq, tpk, w);
	sq_tpk_free(tpk);
	sq_writer_free(w);

	dc_key_set_from_binary(ret_public_key, buf, len, DC_KEY_PUBLIC);
	free(buf);

	success = 1;

cleanup:
	return success;
}


/*******************************************************************************
 * Public key encrypt/decrypt
 ******************************************************************************/


int dc_pgp_pk_encrypt( dc_context_t*       context,
                       const void*         plain_text,
                       size_t              plain_bytes,
                       const dc_keyring_t* raw_public_keys_for_encryption,
                       const dc_key_t*     raw_private_key_for_signing,
                       int                 use_armor,
                       void**              ret_ctext,
                       size_t*             ret_ctext_bytes)
{
	int             i = 0;
	int             success = 0;
	sq_status_t     rc;
	sq_writer_t     sink;
	sq_writer_stack_t writer = NULL;
	size_t          recipients_len = 0;
	sq_tpk_t*       recipients = NULL;
	sq_tpk_t        signing_key = NULL;

	if (context==NULL || plain_text==NULL || plain_bytes==0 || ret_ctext==NULL || ret_ctext_bytes==NULL
	 || raw_public_keys_for_encryption==NULL || raw_public_keys_for_encryption->count<=0) {
		goto cleanup;
	}

	*ret_ctext       = NULL;
	*ret_ctext_bytes = 0;
	sink = sq_writer_alloc(ret_ctext, ret_ctext_bytes);

	if (use_armor) {
		sink = sq_armor_writer_new(sink, SQ_ARMOR_KIND_MESSAGE);
	}

	recipients = calloc(raw_public_keys_for_encryption->count, sizeof(sq_tpk_t));
	if (!recipients) {
		exit(40);
	}

	for (i = 0; i < raw_public_keys_for_encryption->count; i++) {
		sq_tpk_t tpk;
		tpk = sq_tpk_from_bytes(context->sq,
					raw_public_keys_for_encryption->keys[i]->binary,
					raw_public_keys_for_encryption->keys[i]->bytes);
		if (tpk) {
			recipients[recipients_len] = tpk;
			recipients_len += 1;
		} else {
			/* XXX: What should happen if parsing the TPK fails?  */
		}
	}

	writer = sq_writer_stack_wrap(sink);
	writer = sq_encryptor_new(context->sq,
				  writer,
				  NULL, 0, /* no passwords */
				  recipients, recipients_len,
				  SQ_ENCRYPTION_MODE_FOR_TRANSPORT);
	if (writer==NULL) {
		goto cleanup;
	}

	if (raw_private_key_for_signing) {
		signing_key = sq_tpk_from_bytes(context->sq,
						raw_private_key_for_signing->binary,
						raw_private_key_for_signing->bytes);
		if (signing_key) {
			writer = sq_signer_new(context->sq,
					       writer,
					       &signing_key, 1);
			if (writer==NULL) {
				goto cleanup;
			}
		} else {
			/* XXX: What should happen if parsing the TPK fails?  */
		}
	}

	writer = sq_literal_writer_new(context->sq, writer);
	if (writer==NULL) {
		goto cleanup;
	}

	while (plain_bytes) {
		ssize_t written;
		written = sq_writer_stack_write(context->sq, writer, plain_text, plain_bytes);
		if (written < 0) {
			goto cleanup;
		}
		plain_text += written;
		plain_bytes -= written;
	}

	rc = sq_writer_stack_finalize(context->sq, writer);
	writer = NULL;
	if (rc) {
		goto cleanup;
	}

	success = 1;

cleanup:
	for (i = 0; i < recipients_len; i++) {
		sq_tpk_free(recipients[i]);
	}
	free(recipients);
	sq_tpk_free(signing_key);
	sq_writer_stack_finalize(context->sq, writer);
	return success;
}


int dc_pgp_pk_decrypt( dc_context_t*       context,
                       const void*         ctext,
                       size_t              ctext_bytes,
                       const dc_keyring_t* raw_private_keys_for_decryption,
                       const dc_keyring_t* raw_public_keys_for_validation,
                       int                 use_armor,
                       void**              ret_plain,
                       size_t*             ret_plain_bytes,
                       dc_hash_t*          ret_signature_fingerprints)
{
	pgp_keyring_t*    public_keys = calloc(1, sizeof(pgp_keyring_t)); /*should be 0 after parsing*/
	pgp_keyring_t*    private_keys = calloc(1, sizeof(pgp_keyring_t));
	pgp_keyring_t*    dummy_keys = calloc(1, sizeof(pgp_keyring_t));
	pgp_validation_t* vresult = calloc(1, sizeof(pgp_validation_t));
	key_id_t*         recipients_key_ids = NULL;
	unsigned          recipients_cnt = 0;
	pgp_memory_t*     keysmem = pgp_memory_new();
	int               i = 0;
	int               success = 0;

	if (context==NULL || ctext==NULL || ctext_bytes==0 || ret_plain==NULL || ret_plain_bytes==NULL
	 || raw_private_keys_for_decryption==NULL || raw_private_keys_for_decryption->count<=0
	 || vresult==NULL || keysmem==NULL || public_keys==NULL || private_keys==NULL) {
		goto cleanup;
	}

	*ret_plain             = NULL;
	*ret_plain_bytes       = 0;

	/* setup keys (the keys may come from pgp_filter_keys_fileread(), see also pgp_keyring_add(rcpts, key)) */
	for (i = 0; i < raw_private_keys_for_decryption->count; i++) {
		pgp_memory_clear(keysmem); /* a simple concatenate of private binary keys fails (works for public keys, however, we don't do it there either) */
		pgp_memory_add(keysmem, raw_private_keys_for_decryption->keys[i]->binary, raw_private_keys_for_decryption->keys[i]->bytes);
		pgp_filter_keys_from_mem(&s_io, dummy_keys/*should stay empty*/, private_keys, NULL, 0, keysmem);
	}

	if (private_keys->keyc<=0) {
		dc_log_warning(context, 0, "Decryption-keyring contains unexpected data (%i/%i)", public_keys->keyc, private_keys->keyc);
		goto cleanup;
	}

	if (raw_public_keys_for_validation) {
		for (i = 0; i < raw_public_keys_for_validation->count; i++) {
			pgp_memory_clear(keysmem);
			pgp_memory_add(keysmem, raw_public_keys_for_validation->keys[i]->binary, raw_public_keys_for_validation->keys[i]->bytes);
			pgp_filter_keys_from_mem(&s_io, public_keys, dummy_keys/*should stay empty*/, NULL, 0, keysmem);
		}
	}

	/* decrypt */
	{
		pgp_memory_t* outmem = pgp_decrypt_and_validate_buf(&s_io, vresult, ctext, ctext_bytes, private_keys, public_keys,
			use_armor, &recipients_key_ids, &recipients_cnt);
		if (outmem==NULL) {
			dc_log_warning(context, 0, "Decryption failed.");
			goto cleanup;
		}
		*ret_plain       = outmem->buf;
		*ret_plain_bytes = outmem->length;
		free(outmem); /* do not use pgp_memory_free() as we took ownership of the buffer */

		// collect the keys of the valid signatures
		if (ret_signature_fingerprints)
		{
			for (i = 0; i < vresult->validc; i++)
			{
				unsigned from = 0;
				pgp_key_t* key0 = pgp_getkeybyid(&s_io, public_keys, vresult->valid_sigs[i].signer_id, &from, NULL, NULL, 0, 0);
				if (key0) {
					pgp_pubkey_t* pubkey0 = &key0->key.pubkey;
					if (!pgp_fingerprint(&key0->pubkeyfpr, pubkey0, 0)) {
						goto cleanup;
					}

					char* fingerprint_hex = dc_binary_to_uc_hex(key0->pubkeyfpr.fingerprint, key0->pubkeyfpr.length);
					if (fingerprint_hex) {
						dc_hash_insert(ret_signature_fingerprints, fingerprint_hex, strlen(fingerprint_hex), (void*)1);
					}
					free(fingerprint_hex);
				}
			}
		}
	}

	success = 1;

cleanup:
	if (keysmem)            { pgp_memory_free(keysmem); }
	if (public_keys)        { pgp_keyring_purge(public_keys); free(public_keys); } /*pgp_keyring_free() frees the content, not the pointer itself*/
	if (private_keys)       { pgp_keyring_purge(private_keys); free(private_keys); }
	if (dummy_keys)         { pgp_keyring_purge(dummy_keys); free(dummy_keys); }
	if (vresult)            { pgp_validate_result_free(vresult); }
	free(recipients_key_ids);
	return success;
}
