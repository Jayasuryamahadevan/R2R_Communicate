#include "fasp_wire.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

/* Restricted ASCII values only: untrusted JSON, arbitrary Unicode and
 * extension fields REQUIRE a complete RFC 8785 implementation. Never sign
 * arbitrary payload strings by concatenating them into these templates. */
static int token(const char *s, size_t maximum) {
    size_t i;
    if (!s) return 0;
    for (i = 0; i <= maximum && s[i]; ++i) {
        const unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    return i > 0 && i <= maximum;
}

static int iso_utc(const char *s) {
    size_t i;
    if (!s || strlen(s) != 20) return 0;
    for (i = 0; i < 20; i++) {
        const char c = s[i];
        if (i == 4 || i == 7) { if (c != '-') return 0; }
        else if (i == 10) { if (c != 'T') return 0; }
        else if (i == 13 || i == 16) { if (c != ':') return 0; }
        else if (i == 19) { if (c != 'Z') return 0; }
        else if (c < '0' || c > '9') return 0;
    }
    return 1;
}

static int b64url(const unsigned char *raw, int size, char *out, size_t cap) {
    unsigned char padded[128];
    int length, i;
    size_t trimmed;
    if (!raw || !out || size < 0 || size > 64) return 0;
    length = 4 * ((size + 2) / 3);
    if ((size_t)length + 1 > sizeof(padded)) return 0;
    if (EVP_EncodeBlock(padded, raw, size) != length) return 0;
    trimmed = (size_t)length;
    while (trimmed && padded[trimmed - 1] == '=') --trimmed;
    if (trimmed + 1 > cap) return 0;
    for (i = 0; i < (int)trimmed; ++i) {
        if (padded[i] == '+') padded[i] = '-';
        else if (padded[i] == '/') padded[i] = '_';
    }
    memcpy(out, padded, trimmed);
    out[trimmed] = '\0';
    return 1;
}

int fasp_identity_from_seed(fasp_identity *out, const unsigned char seed[32]) {
    EVP_PKEY *pkey = NULL;
    unsigned char pub[32], digest[32];
    size_t size = sizeof(pub);
    char suffix[44];
    int ok = 0;
    if (!out || !seed) return 0;
    memset(out, 0, sizeof(*out));
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    if (!pkey || EVP_PKEY_get_raw_public_key(pkey, pub, &size) != 1 || size != 32 ||
        EVP_Digest(pub, sizeof(pub), digest, NULL, EVP_sha256(), NULL) != 1 ||
        !b64url(pub, 32, out->public_key, sizeof(out->public_key)) ||
        !b64url(digest, 32, suffix, sizeof(suffix))) goto finish;
    if (snprintf(out->system_id, sizeof(out->system_id), "fasp:system:%s", suffix) != 55 ||
        snprintf(out->kid, sizeof(out->kid), "ed25519-%.8s", out->public_key) != 16) goto finish;
    memcpy(out->seed, seed, 32);
    ok = 1;
finish:
    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(pub, sizeof(pub));
    OPENSSL_cleanse(digest, sizeof(digest));
    if (!ok) fasp_identity_clear(out);
    return ok;
}

static int signed_output(const fasp_identity *id, const char *canonical,
                         char *output, size_t cap) {
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char sig[64];
    size_t sig_len = sizeof(sig), n;
    char encoded[88];
    int ok = 0, written;
    if (!id || !canonical || !output || cap == 0) return 0;
    output[0] = '\0';
    n = strlen(canonical);
    if (n == 0 || n > 1024 || canonical[n-1] != '}') return 0;
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, id->seed, 32);
    ctx = EVP_MD_CTX_new();
    if (!key || !ctx || EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1 ||
        EVP_DigestSign(ctx, sig, &sig_len, (const unsigned char *)canonical, n) != 1 ||
        sig_len != 64 || !b64url(sig, 64, encoded, sizeof(encoded))) goto finish;
    /* Any property ordering is valid on the wire; RFC 8785 is applied to the
     * UNSIGNED record before signing, and the receiver canonicalizes again. */
    written = snprintf(output, cap, "%.*s,\"signature\":{\"alg\":\"Ed25519\",\"kid\":\"%s\",\"value\":\"%s\"}}",
                       (int)n - 1, canonical, id->kid, encoded);
    ok = written >= 0 && (size_t)written < cap;
finish:
    if (!ok) output[0] = '\0';
    OPENSSL_cleanse(sig, sizeof(sig));
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

int fasp_signed_card(const fasp_identity *id, const char *issued_utc,
                     const char *expires_utc, char *output, size_t output_cap) {
    char canonical[1024];
    int n;
    if (!id || !iso_utc(issued_utc) || !iso_utc(expires_utc) ||
        strcmp(issued_utc, expires_utc) >= 0) return 0;
    /* Strict RFC 8785 key order, with no arbitrary JSON interpolation. */
    n = snprintf(canonical, sizeof(canonical),
        "{\"capabilities\":[],\"display_name\":\"native-c-peer\","
        "\"endpoints\":{\"envelopes\":null,\"profile\":null},"
        "\"expires_at\":\"%s\",\"fasp\":\"fasp/1.0\","
        "\"issued_at\":\"%s\",\"key_id\":\"%s\",\"public_key\":\"%s\","
        "\"system_id\":\"%s\",\"type\":\"id_card\"}",
        expires_utc, issued_utc, id->kid, id->public_key, id->system_id);
    return n >= 0 && (size_t)n < sizeof(canonical) && signed_output(id, canonical, output, output_cap);
}

int fasp_signed_heartbeat(const fasp_identity *id, const char *recipient,
                          const char *issued_utc, const char *expires_utc,
                          const char *message_id, const char *nonce,
                          char *output, size_t output_cap) {
    char canonical[1024];
    int n;
    if (!id || !recipient || strlen(recipient) != 55 ||
        strncmp(recipient, "fasp:system:", 12) != 0 ||
        !token(recipient + 12, 43) || strlen(recipient + 12) != 43 ||
        !iso_utc(issued_utc) || !iso_utc(expires_utc) ||
        strcmp(issued_utc, expires_utc) >= 0 ||
        !token(message_id, 128) || !token(nonce, 128)) return 0;
    /* Only observation-only heartbeat with {}. A general intent client must
     * add full JSON/JCS canonicalization, schemas, permissions and state. */
    n = snprintf(canonical, sizeof(canonical),
        "{\"expires_at\":\"%s\",\"fasp\":\"fasp/1.0\","
        "\"from\":\"%s\",\"issued_at\":\"%s\",\"kind\":\"heartbeat\","
        "\"message_id\":\"%s\",\"nonce\":\"%s\",\"payload\":{},\"to\":\"%s\"}",
        expires_utc, id->system_id, issued_utc, message_id, nonce, recipient);
    return n >= 0 && (size_t)n < sizeof(canonical) && signed_output(id, canonical, output, output_cap);
}

void fasp_identity_clear(fasp_identity *id) {
    if (id) OPENSSL_cleanse(id, sizeof(*id));
}
