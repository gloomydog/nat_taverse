#define _POSIX_C_SOURCE 200809L

#include "nostr.h"
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>

/* ---------------------------- helpers ----------------------------- */

static void bin2hex(const uint8_t *in, size_t len, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = H[in[i] >> 4];
        out[i * 2 + 1] = H[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int b64_enc(const uint8_t *in, size_t len, char *out, size_t outlen) {
    if (((len + 2) / 3) * 4 + 1 > outlen) return -1;
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)len);
    return n < 0 ? -1 : 0;
}

static int b64_dec(const char *in, uint8_t *out, size_t maxlen) {
    size_t inlen = strlen(in);
    if (inlen % 4 != 0) return -1;
    size_t need = inlen / 4 * 3;
    if (need > maxlen + 2) return -1;

    uint8_t *tmp = malloc(need + 4);
    if (!tmp) return -1;
    int n = EVP_DecodeBlock(tmp, (const unsigned char *)in, (int)inlen);
    if (n < 0) { free(tmp); return -1; }

    /* EVP_DecodeBlock does not strip padding; adjust by hand */
    size_t real = (size_t)n;
    if (inlen >= 1 && in[inlen - 1] == '=') real--;
    if (inlen >= 2 && in[inlen - 2] == '=') real--;

    if (real > maxlen) { free(tmp); return -1; }
    memcpy(out, tmp, real);
    free(tmp);
    return (int)real;
}

/* one shared libsecp256k1 context */
static secp256k1_context *get_ctx(void) {
    static secp256k1_context *ctx = NULL;
    if (!ctx) ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                              SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

/* ------------------------- identity ------------------------------- */

int nostr_identity_from_keys(const nt_keys_t *keys, nostr_identity_t *out) {
    memset(out, 0, sizeof(*out));
    memcpy(out->seckey, keys->nostr_seed, NOSTR_SECKEY_LEN);
    memcpy(out->enckey, keys->nostr_content_key, sizeof(out->enckey));

    secp256k1_context *ctx = get_ctx();
    if (!ctx) return -1;

    /* The odds of the derived value falling outside the curve order are
     * negligible, but check and re-hash rather than produce a broken key. */
    for (int attempt = 0; attempt < 8; attempt++) {
        if (secp256k1_ec_seckey_verify(ctx, out->seckey) == 1) break;
        uint8_t tmp[32];
        SHA256(out->seckey, 32, tmp);
        memcpy(out->seckey, tmp, 32);
        nt_wipe(tmp, sizeof(tmp));
        if (attempt == 7) return -1;
    }

    secp256k1_keypair kp;
    if (secp256k1_keypair_create(ctx, &kp, out->seckey) != 1) return -1;

    secp256k1_xonly_pubkey xpk;
    if (secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp) != 1) {
        nt_wipe(&kp, sizeof(kp));
        return -1;
    }
    int rc = secp256k1_xonly_pubkey_serialize(ctx, out->pubkey, &xpk);
    nt_wipe(&kp, sizeof(kp));
    return rc == 1 ? 0 : -1;
}

void nostr_identity_wipe(nostr_identity_t *id) {
    nt_wipe(id, sizeof(*id));
}

/* ---------------------- payload encryption ------------------------ */

/* Wire format: base64( nonce(12) || ciphertext || tag(16) ) */

int nostr_encrypt_payload(const nostr_identity_t *id,
                           const void *plain, size_t plen,
                           char *out_b64, size_t outlen) {
    uint8_t nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) return -1;

    size_t buflen = sizeof(nonce) + plen + 16;
    uint8_t *buf = malloc(buflen);
    if (!buf) return -1;
    memcpy(buf, nonce, sizeof(nonce));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(buf); return -1; }

    int ok = 0, len = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, id->enckey, nonce) != 1) break;

        int clen = 0;
        if (EVP_EncryptUpdate(ctx, buf + 12, &clen, plain, (int)plen) != 1) break;
        len = clen;
        if (EVP_EncryptFinal_ex(ctx, buf + 12 + clen, &clen) != 1) break;
        len += clen;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, buf + 12 + len) != 1) break;
        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(buf); return -1; }

    int rc = b64_enc(buf, 12 + (size_t)len + 16, out_b64, outlen);
    free(buf);
    return rc;
}

int nostr_decrypt_payload(const nostr_identity_t *id,
                           const char *b64, void *out, size_t maxlen) {
    uint8_t raw[512];
    int rawlen = b64_dec(b64, raw, sizeof(raw));
    if (rawlen < 12 + 16) return -1;

    const uint8_t *nonce = raw;
    const uint8_t *ct = raw + 12;
    size_t ctlen = (size_t)rawlen - 12 - 16;
    const uint8_t *tag = raw + 12 + ctlen;

    if (ctlen > maxlen) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 0, outlen_i = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, id->enckey, nonce) != 1) break;

        int l = 0;
        if (EVP_DecryptUpdate(ctx, out, &l, ct, (int)ctlen) != 1) break;
        outlen_i = l;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag) != 1) break;
        /* fails here if the tag does not match, i.e. tampering */
        if (EVP_DecryptFinal_ex(ctx, (uint8_t *)out + l, &l) != 1) break;
        outlen_i += l;
        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok ? outlen_i : -1;
}

/* ------------------------ event construction ---------------------- */

/* NIP-01: the id is SHA-256 over the JSON array
 * [0, pubkey_hex, created_at, kind, tags, content] */
static int serialize_for_id(const char *pubkey_hex, int64_t created_at, int kind,
                             const char *content, char *out, size_t outlen) {
    int n = snprintf(out, outlen, "[0,\"%s\",%lld,%d,[],\"%s\"]",
                     pubkey_hex, (long long)created_at, kind, content);
    return (n < 0 || (size_t)n >= outlen) ? -1 : 0;
}

int nostr_build_event(const nostr_identity_t *id, int kind,
                       const char *content_b64, char *out_json, size_t outlen) {
    secp256k1_context *ctx = get_ctx();
    if (!ctx) return -1;

    char pubkey_hex[NOSTR_PUBKEY_LEN * 2 + 1];
    bin2hex(id->pubkey, NOSTR_PUBKEY_LEN, pubkey_hex);

    int64_t created_at = (int64_t)time(NULL);

    char ser[2048];
    if (serialize_for_id(pubkey_hex, created_at, kind, content_b64,
                         ser, sizeof(ser)) != 0) return -1;

    uint8_t id_bin[NOSTR_ID_LEN];
    SHA256((const unsigned char *)ser, strlen(ser), id_bin);
    char id_hex[NOSTR_ID_LEN * 2 + 1];
    bin2hex(id_bin, NOSTR_ID_LEN, id_hex);

    /* BIP-340 Schnorr signature */
    secp256k1_keypair kp;
    if (secp256k1_keypair_create(ctx, &kp, id->seckey) != 1) return -1;

    uint8_t aux[32];
    if (RAND_bytes(aux, sizeof(aux)) != 1) return -1;

    uint8_t sig[NOSTR_SIG_LEN];
    if (secp256k1_schnorrsig_sign32(ctx, sig, id_bin, &kp, aux) != 1) return -1;

    char sig_hex[NOSTR_SIG_LEN * 2 + 1];
    bin2hex(sig, NOSTR_SIG_LEN, sig_hex);

    int n = snprintf(out_json, outlen,
        "{\"id\":\"%s\",\"pubkey\":\"%s\",\"created_at\":%lld,\"kind\":%d,"
        "\"tags\":[],\"content\":\"%s\",\"sig\":\"%s\"}",
        id_hex, pubkey_hex, (long long)created_at, kind, content_b64, sig_hex);
    return (n < 0 || (size_t)n >= outlen) ? -1 : 0;
}

int nostr_build_publish(const char *event_json, char *out, size_t outlen) {
    int n = snprintf(out, outlen, "[\"EVENT\",%s]", event_json);
    return (n < 0 || (size_t)n >= outlen) ? -1 : 0;
}

int nostr_build_req(const nostr_identity_t *id, int kind, const char *subid,
                     int64_t since, char *out, size_t outlen) {
    char pubkey_hex[NOSTR_PUBKEY_LEN * 2 + 1];
    bin2hex(id->pubkey, NOSTR_PUBKEY_LEN, pubkey_hex);

    int n = snprintf(out, outlen,
        "[\"REQ\",\"%s\",{\"kinds\":[%d],\"authors\":[\"%s\"],\"since\":%lld}]",
        subid, kind, pubkey_hex, (long long)since);
    return (n < 0 || (size_t)n >= outlen) ? -1 : 0;
}

/* ------------------------ inbound messages ------------------------ */

/* Extract the value of a "key": "value" pair.
 *
 * Relays differ in how they format JSON -- some emit compact output,
 * others put a space after the colon.  Skipping whitespace here is not
 * pedantry: a parser that only matched the compact form failed against a
 * relay that did not use it.
 *
 * Deliberately minimal, not a general JSON parser. */
static int json_find_string(const char *json, const char *key,
                             char *out, size_t outlen) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);

    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);

    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return -1;
    p++;

    /* content is base64, so escapes never appear; skip them anyway */
    size_t n = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        if (n + 1 >= outlen) return -1;
        out[n++] = *p++;
    }
    if (*p != '"') return -1;
    out[n] = '\0';
    return 0;
}

int nostr_extract_content(const char *msg, char *out_content, size_t outlen) {
    /* expects ["EVENT", subid, {..., "content": "...", ...}] */
    const char *p = msg;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '[') return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (strncmp(p, "\"EVENT\"", 7) != 0) return -1;

    return json_find_string(msg, "content", out_content, outlen);
}
