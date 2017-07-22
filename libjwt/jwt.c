/* Copyright (C) 2015-2017 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the JWT Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <jwt.h>

#include "jwt-private.h"
#include "base64.h"
#include "config.h"


static const char *jwt_alg_str(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return "none";
	case JWT_ALG_HS256:
		return "HS256";
	case JWT_ALG_HS384:
		return "HS384";
	case JWT_ALG_HS512:
		return "HS512";
	case JWT_ALG_RS256:
		return "RS256";
	case JWT_ALG_RS384:
		return "RS384";
	case JWT_ALG_RS512:
		return "RS512";
	case JWT_ALG_ES256:
		return "ES256";
	case JWT_ALG_ES384:
		return "ES384";
	case JWT_ALG_ES512:
		return "ES512";
	default:
		return NULL;
	}
}

static int jwt_str_alg(jwt_t *jwt, const char *alg)
{
	if (alg == NULL)
		return EINVAL;

	if (!strcasecmp(alg, "none"))
		jwt->alg = JWT_ALG_NONE;
	else if (!strcasecmp(alg, "HS256"))
		jwt->alg = JWT_ALG_HS256;
	else if (!strcasecmp(alg, "HS384"))
		jwt->alg = JWT_ALG_HS384;
	else if (!strcasecmp(alg, "HS512"))
		jwt->alg = JWT_ALG_HS512;
	else if (!strcasecmp(alg, "RS256"))
		jwt->alg = JWT_ALG_RS256;
	else if (!strcasecmp(alg, "RS384"))
		jwt->alg = JWT_ALG_RS384;
	else if (!strcasecmp(alg, "RS512"))
		jwt->alg = JWT_ALG_RS512;
	else if (!strcasecmp(alg, "ES256"))
		jwt->alg = JWT_ALG_ES256;
	else if (!strcasecmp(alg, "ES384"))
		jwt->alg = JWT_ALG_ES384;
	else if (!strcasecmp(alg, "ES512"))
		jwt->alg = JWT_ALG_ES512;
	else
		return EINVAL;

	return 0;
}

static void jwt_scrub_key(jwt_t *jwt)
{
	if (jwt->key) {
		/* Overwrite it so it's gone from memory. */
		memset(jwt->key, 0, jwt->key_len);

		free(jwt->key);
		jwt->key = NULL;
	}

	jwt->key_len = 0;
	jwt->alg = JWT_ALG_NONE;
}

int jwt_set_alg(jwt_t *jwt, jwt_alg_t alg, const unsigned char *key, int len)
{
	/* No matter what happens here, we do this. */
	jwt_scrub_key(jwt);

	if (alg < JWT_ALG_NONE || alg >= JWT_ALG_TERM)
		return EINVAL;

	switch (alg) {
	case JWT_ALG_NONE:
		if (key || len)
			return EINVAL;
		break;

	default:
		if (!key || len <= 0)
			return EINVAL;

		jwt->key = (unsigned char*)malloc(len);
		if (!jwt->key)
			return ENOMEM;

		memcpy(jwt->key, key, len);
	}

	jwt->alg = alg;
	jwt->key_len = len;

	return 0;
}

jwt_alg_t jwt_get_alg(jwt_t *jwt)
{
	return jwt->alg;
}

int jwt_new(jwt_t **jwt)
{
	if (!jwt)
		return EINVAL;

	*jwt = (jwt_t*)malloc(sizeof(jwt_t));
	if (!*jwt)
		return ENOMEM;

	memset(*jwt, 0, sizeof(jwt_t));

	(*jwt)->grants = new rapidjson::Document();
	if (!(*jwt)->grants) {
		free(*jwt);
		*jwt = NULL;
		return ENOMEM;
	}

	return 0;
}

void jwt_free(jwt_t *jwt)
{
	if (!jwt)
		return;

	jwt_scrub_key(jwt);

	delete jwt->grants;

	free(jwt);
}

jwt_t *jwt_dup(jwt_t *jwt)
{
	jwt_t *newJwt = NULL;

	rapidjson::StringBuffer sb;
	rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

	if (!jwt) {
		errno = EINVAL;
		goto dup_fail;
	}

	errno = 0;

	newJwt = (jwt_t*)malloc(sizeof(jwt_t));
	if (!newJwt) {
		errno = ENOMEM;
		return NULL;
	}

	memset(newJwt, 0, sizeof(jwt_t));

	if (jwt->key_len) {
		newJwt->alg = jwt->alg;
		newJwt->key = (unsigned char*)malloc(jwt->key_len);
		if (!newJwt->key) {
			errno = ENOMEM;
			goto dup_fail;
		}
		memcpy(newJwt->key, jwt->key, jwt->key_len);
		newJwt->key_len = jwt->key_len;
	}

	jwt->grants->Accept(writer);

	newJwt->grants = new rapidjson::Document();
	if (!newJwt->grants) {
		errno = ENOMEM;
		goto dup_fail;
	}

	newJwt->grants->Parse( sb.GetString() );

dup_fail:
	if (errno) {
		jwt_free(newJwt);
		newJwt = NULL;
	}

	return newJwt;
}

static const char *get_js_string(rapidjson::Document *js, const char *key)
{
	const char *val = NULL;
	if( js->HasMember( key ) ) {
		val = (*js)[ key ].GetString();
	}

	return val;
}

static long get_js_int(rapidjson::Document *js, const char *key)
{
	long val = -1;
	if( js->HasMember( key ) ) {
		val = (*js)[ key ].GetInt64();
	}

	return val;
}

char *jwt_b64_decode(const char *src, int *ret_len)
{
	char *buf;
	char *decoded;
	int len, i, z;

	/* Decode based on RFC-4648 URI safe encoding. */
	len = strlen(src);
	decoded = (char*)alloca(len + 4);
	if (!decoded)
		return NULL;

	for (i = 0; i < len; i++) {
		switch (src[i]) {
		case '-':
			decoded[i] = '+';
			break;
		case '_':
			decoded[i] = '/';
			break;
		default:
			decoded[i] = src[i];
		}
	}
	z = 4 - (i % 4);
	if (z < 4) {
		while (z--)
			decoded[i++] = '=';
	}
	decoded[i] = '\0';

	buf = (char*)malloc(i);
	if (buf == NULL)
		return NULL;

	*ret_len = jwt_Base64decode(buf, decoded);

	return buf;
}


static rapidjson::Document *jwt_b64_decode_json(char *src)
{
	char *buf;
	int len;

	buf = jwt_b64_decode(src, &len);

	if (buf == NULL)
		return NULL;

	buf[len] = '\0';

	rapidjson::Document *doc = new rapidjson::Document();
	doc->Parse( buf );

	free(buf);

	return doc;
}

void jwt_base64uri_encode(char *str)
{
	int len = strlen(str);
	int i, t;

	for (i = t = 0; i < len; i++) {
		switch (str[i]) {
		case '+':
			str[t++] = '-';
			break;
		case '/':
			str[t++] = '_';
			break;
		case '=':
			break;
		default:
			str[t++] = str[i];
		}
	}

	str[t] = '\0';
}

static int jwt_sign(jwt_t *jwt, char **out, unsigned int *len, const char *str)
{
	switch (jwt->alg) {
	/* HMAC */
	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		return jwt_sign_sha_hmac(jwt, out, len, str);

	/* RSA */
	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:

	/* ECC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES384:
	case JWT_ALG_ES512:
		return jwt_sign_sha_pem(jwt, out, len, str);

	/* You wut, mate? */
	default:
		return EINVAL;
	}
}

static int jwt_verify(jwt_t *jwt, const char *head, const char *sig)
{
	switch (jwt->alg) {
	/* HMAC */
	case JWT_ALG_HS256:
	case JWT_ALG_HS384:
	case JWT_ALG_HS512:
		return jwt_verify_sha_hmac(jwt, head, sig);

	/* RSA */
	case JWT_ALG_RS256:
	case JWT_ALG_RS384:
	case JWT_ALG_RS512:

	/* ECC */
	case JWT_ALG_ES256:
	case JWT_ALG_ES384:
	case JWT_ALG_ES512:
		return jwt_verify_sha_pem(jwt, head, sig);

	/* You wut, mate? */
	default:
		return EINVAL;
	}
}

static int jwt_parse_body(jwt_t *jwt, char *body)
{
	if (jwt->grants) {
		delete jwt->grants;
		jwt->grants = NULL;
	}

	jwt->grants = jwt_b64_decode_json(body);
	if (!jwt->grants)
		return EINVAL;

	return 0;
}

static int jwt_verify_head(jwt_t *jwt, char *head)
{
	const char *val;
	int ret;

	rapidjson::Document *doc = jwt_b64_decode_json(head);
	if (!doc)
		return EINVAL;

	val = get_js_string(doc, "alg");
	ret = jwt_str_alg(jwt, val);
	if (ret)
		goto verify_head_done;

	if (jwt->alg != JWT_ALG_NONE) {
		/* If alg is not NONE, there may be a typ. */
		val = get_js_string(doc, "typ");
		if (val && strcasecmp(val, "JWT"))
			ret = EINVAL;

		if (jwt->key) {
			if (jwt->key_len <= 0)
				ret = EINVAL;
		} else {
			jwt_scrub_key(jwt);
		}
	} else {
		/* If alg is NONE, there should not be a key */
		if (jwt->key){
			ret = EINVAL;
		}
	}

verify_head_done:
	if (doc)
		delete doc;

	return ret;
}

int jwt_decode(jwt_t **jwt, const char *token, const unsigned char *key,
	       int key_len)
{
	char *head = strdup(token);
	jwt_t *jwtoken = NULL;
	char *body, *sig;
	int ret = EINVAL;

	if (!jwt)
		return EINVAL;

	*jwt = NULL;

	if (!head)
		return ENOMEM;

	/* Find the components. */
	for (body = head; body[0] != '.'; body++) {
		if (body[0] == '\0')
			goto decode_done;
	}

	body[0] = '\0';
	body++;

	for (sig = body; sig[0] != '.'; sig++) {
		if (sig[0] == '\0')
			goto decode_done;
	}

	sig[0] = '\0';
	sig++;

	/* Now that we have everything split up, let's check out the
	 * header. */
	ret = jwt_new(&jwtoken);
	if (ret) {
		goto decode_done;
	}

	/* Copy the key over for verify_head. */
	if (key_len) {
		jwtoken->key = (unsigned char*)malloc(key_len);
		if (jwtoken->key == NULL)
			goto decode_done;
		memcpy(jwtoken->key, key, key_len);
		jwtoken->key_len = key_len;
	}

	ret = jwt_verify_head(jwtoken, head);
	if (ret)
		goto decode_done;

	ret = jwt_parse_body(jwtoken, body);
	if (ret)
		goto decode_done;

	/* Check the signature, if needed. */
	if (jwtoken->alg != JWT_ALG_NONE) {
		/* Re-add this since it's part of the verified data. */
		body[-1] = '.';
		ret = jwt_verify(jwtoken, head, sig);
	} else {
		ret = 0;
	}

decode_done:
	if (ret)
		jwt_free(jwtoken);
	else
		*jwt = jwtoken;

	free(head);

	return ret;
}

const char *jwt_get_grant(jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return NULL;
	}

	errno = 0;

	return get_js_string(jwt->grants, grant);
}

long jwt_get_grant_int(jwt_t *jwt, const char *grant)
{
	if (!jwt || !grant || !strlen(grant)) {
		errno = EINVAL;
		return 0;
	}

	errno = 0;

	return get_js_int(jwt->grants, grant);
}

char *jwt_get_grants_json(jwt_t *jwt, const char *grant)
{
	rapidjson::Value *js_val = nullptr;

	errno = EINVAL;

	if (!jwt)
		return NULL;

	rapidjson::StringBuffer sb;
	rapidjson::Writer<rapidjson::StringBuffer> writer( sb );

	if (grant && strlen(grant)) {
		if( jwt->grants->HasMember( grant ) ) {
			(*jwt->grants)[ grant ].Accept( writer );
		} else {
			return NULL;
		}
	} else {
		jwt->grants->Accept( writer );
	}

	errno = 0;

	return strdup( sb.GetString() );
}

int jwt_add_grant(jwt_t *jwt, const char *grant, const char *val)
{
	if (!jwt || !grant || !strlen(grant) || !val)
		return EINVAL;

	if( jwt->grants->HasMember( grant ) ) {
		return EEXIST;
	}

	jwt->grants->AddMember( rapidjson::Value(grant, jwt->grants->GetAllocator() ), rapidjson::Value(val, jwt->grants->GetAllocator() ), jwt->grants->GetAllocator() );

	return 0;
}

int jwt_add_grant_int(jwt_t *jwt, const char *grant, long val)
{
	if (!jwt || !grant || !strlen(grant))
		return EINVAL;

	if( jwt->grants->HasMember( grant ) ) {
		return EEXIST;
	}

	jwt->grants->AddMember( rapidjson::Value(grant, jwt->grants->GetAllocator() ), rapidjson::Value((int64_t)val), jwt->grants->GetAllocator() );

	return 0;
}

int jwt_add_grants_json(jwt_t *jwt, const char *json)
{
	int ret = -1;

	if (!jwt) {
		return EINVAL;
	}

	rapidjson::Document dNew;
	dNew.Parse( json );

	for( auto iter = dNew.MemberBegin(); iter != dNew.MemberEnd(); ++iter ) {
		if( jwt->grants->HasMember( iter->name ) ) {
			jwt->grants->RemoveMember( iter->name );
		}

		jwt->grants->AddMember( iter->name, iter->value, jwt->grants->GetAllocator() );
	}

	return 0;
}

int jwt_del_grants(jwt_t *jwt, const char *grant)
{
	if (!jwt)
		return EINVAL;

	if (grant == NULL || !strlen(grant)) {
		jwt->grants->SetObject();
	} else {
		jwt->grants->RemoveMember( grant );
	}

	return 0;
}

#ifdef NO_WEAK_ALIASES
int jwt_del_grant(jwt_t *jwt, const char *grant)
{
	return jwt_del_grants(jwt, grant);
}
#else
int jwt_del_grant(jwt_t *jwt, const char *grant)
	__attribute__ ((weak, alias ("jwt_del_grants")));
#endif

static int __append_str(char **buf, const char *str)
{
	char *newStr;

	if (*buf == NULL) {
		newStr = (char*)calloc(1, strlen(str) + 1);
	} else {
		newStr = (char*)realloc(*buf, strlen(*buf) + strlen(str) + 1);
	}

	if (newStr == NULL)
		return ENOMEM;

	strcat(newStr, str);

	*buf = newStr;

	return 0;
}

#define APPEND_STR(__buf, __str) do {		\
	int ret = __append_str(__buf, __str);	\
	if (ret)				\
		return ret;			\
} while(0)

static int jwt_write_head(jwt_t *jwt, char **buf, int pretty)
{
	APPEND_STR(buf, "{");

	if (pretty)
		APPEND_STR(buf, "\n");

	/* An unsecured JWT is a JWS and provides no "typ".
	 * -- draft-ietf-oauth-json-web-token-32 #6. */
	if (jwt->alg != JWT_ALG_NONE) {
		if (pretty)
			APPEND_STR(buf, "    ");

		APPEND_STR(buf, "\"typ\":");
		if (pretty)
			APPEND_STR(buf, " ");
		APPEND_STR(buf, "\"JWT\",");

		if (pretty)
			APPEND_STR(buf, "\n");
	}

	if (pretty)
		APPEND_STR(buf, "    ");

	APPEND_STR(buf, "\"alg\":");
	if (pretty)
		APPEND_STR(buf, " ");
	APPEND_STR(buf, "\"");
	APPEND_STR(buf, jwt_alg_str(jwt->alg));
	APPEND_STR(buf, "\"");

	if (pretty)
		APPEND_STR(buf, "\n");

	APPEND_STR(buf, "}");

	if (pretty)
		APPEND_STR(buf, "\n");

	return 0;
}

static int jwt_write_body(jwt_t *jwt, char **buf, int pretty) {
	rapidjson::StringBuffer sb;

	if (pretty) {
		rapidjson::PrettyWriter<rapidjson::StringBuffer> writer( sb );
		jwt->grants->Accept( writer );
	} else {
		rapidjson::Writer<rapidjson::StringBuffer> writer( sb );
		jwt->grants->Accept( writer );
	}

	if (pretty) {
		APPEND_STR( buf, "\n" );
	}

	APPEND_STR(buf, sb.GetString());

	if (pretty) {
		APPEND_STR( buf, "\n" );
	}

	return 0;
}

static int jwt_dump(jwt_t *jwt, char **buf, int pretty)
{
	int ret;

	ret = jwt_write_head(jwt, buf, pretty);

	if (ret == 0)
		ret = __append_str(buf, ".");

	if (ret == 0)
		ret = jwt_write_body(jwt, buf, pretty);

	return ret;
}

int jwt_dump_fp(jwt_t *jwt, FILE *fp, int pretty)
{
	char *out = NULL;
	int ret = 0;

	ret = jwt_dump(jwt, &out, pretty);

	if (ret == 0)
		fputs(out, fp);

	if (out)
		free(out);

	return ret;
}

char *jwt_dump_str(jwt_t *jwt, int pretty)
{
	char *out = NULL;
	int err;

	err = jwt_dump(jwt, &out, pretty);

	if (err) {
		errno = err;
		if (out)
			free(out);
		out = NULL;
	} else {
		errno = 0;
	}

	return out;
}

static int jwt_encode(jwt_t *jwt, char **out)
{
	char *buf = NULL, *head, *body, *sig;
	int ret, head_len, body_len;
	unsigned int sig_len;

	/* First the header. */
	ret = jwt_write_head(jwt, &buf, 0);
	if (ret) {
		if (buf)
			free(buf);
		return ret;
	}

	head = (char*)alloca(strlen(buf) * 2);
	if (head == NULL) {
		free(buf);
		return ENOMEM;
	}
	jwt_Base64encode(head, buf, strlen(buf));
	head_len = strlen(head);

	free(buf);
	buf = NULL;

	/* Now the body. */
	ret = jwt_write_body(jwt, &buf, 0);
	if (ret) {
		if (buf)
			free(buf);
		return ret;
	}

	body = (char*)alloca(strlen(buf) * 2);
	if (body == NULL) {
		free(buf);
		return ENOMEM;
	}
	jwt_Base64encode(body, buf, strlen(buf));
	body_len = strlen(body);

	free(buf);
	buf = NULL;

	jwt_base64uri_encode(head);
	jwt_base64uri_encode(body);

	/* Allocate enough to reuse as b64 buffer. */
	buf = (char*)malloc(head_len + body_len + 2);
	if (buf == NULL)
		return ENOMEM;
	strcpy(buf, head);
	strcat(buf, ".");
	strcat(buf, body);

	ret = __append_str(out, buf);
	if (ret == 0)
		ret = __append_str(out, ".");
	if (ret) {
		if (buf)
			free(buf);
		return ret;
	}

	if (jwt->alg == JWT_ALG_NONE) {
		free(buf);
		return 0;
	}

	/* Now the signature. */
	ret = jwt_sign(jwt, &sig, &sig_len, buf);
	free(buf);

	if (ret)
		return ret;

	buf = (char*)malloc(sig_len * 2);
	if (buf == NULL) {
		free(sig);
		return ENOMEM;
	}

	jwt_Base64encode(buf, sig, sig_len);

	free(sig);

	jwt_base64uri_encode(buf);
	ret = __append_str(out, buf);
	free(buf);

	return ret;
}

int jwt_encode_fp(jwt_t *jwt, FILE *fp)
{
	char *str = NULL;
	int ret;

	ret = jwt_encode(jwt, &str);
	if (ret) {
		if (str)
			free(str);
		return ret;
	}

	fputs(str, fp);
	free(str);

	return 0;
}

char *jwt_encode_str(jwt_t *jwt)
{
	char *str = NULL;

	errno = jwt_encode(jwt, &str);
	if (errno) {
		if (str)
			free(str);
		str = NULL;
	}

	return str;
}
