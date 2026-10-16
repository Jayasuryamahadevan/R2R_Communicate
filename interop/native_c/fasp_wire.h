/* Minimal portable C signing profile for FASP JSON/Ed25519 v1.
 * No Python, JS, JSON parser, transport, or file I/O is required by this API.
 * This profile intentionally emits ONLY cards and heartbeat envelopes with
 * fixed, audited schemas and canonical JSON ordering. Not a general JSON signer.
 * Requires a crypto provider with OpenSSL's Ed25519 and SHA-256 API.
 */
#ifndef FASP_WIRE_H
#define FASP_WIRE_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FASP_SEED_BYTES 32
#define FASP_SIGNED_MAX 2048

typedef struct {
    unsigned char seed[FASP_SEED_BYTES]; /* Secret: wipe after use. */
    char public_key[44];                 /* Raw Ed25519 key, base64url. */
    char system_id[56];                  /* fasp:system:<43 base64url chars>. */
    char kid[17];                        /* ed25519-<8 chars>. */
} fasp_identity;

/* Return 1 on success and 0 on validation/crypto/buffer failure. */
int fasp_identity_from_seed(fasp_identity *out, const unsigned char seed[32]);
int fasp_signed_card(const fasp_identity *id, const char *issued_utc,
                     const char *expires_utc, char *output, size_t output_cap);
int fasp_signed_heartbeat(const fasp_identity *id, const char *recipient,
                          const char *issued_utc, const char *expires_utc,
                          const char *message_id, const char *nonce,
                          char *output, size_t output_cap);
void fasp_identity_clear(fasp_identity *id);

#ifdef __cplusplus
}
#endif

#endif
