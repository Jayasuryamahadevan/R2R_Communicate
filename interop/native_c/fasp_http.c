/* Bounded FASP 1.0 native transport. C11/POSIX, libcurl, json-c, OpenSSL.
 * A small HTTP(S) gateway companion to fasp-c-peer's standalone signed
 * JSON output. This client does NOT cryptographically verify the server's
 * FASP ID card: authenticate the HTTPS endpoint using TLS and optionally
 * pin its TLS public key. System ID checks prevent accidental misrouting,
 * but cannot prevent a TLS-authorized impostor claiming a copied public key.
 */
#define _POSIX_C_SOURCE 200809L
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PROFILE 65536u
#define MAX_REPLY 262144u
#define MAX_ENVELOPE 65536u

struct bounded {
    char *buf;
    size_t used;
    size_t limit;
    int overflow;
};

static size_t receive(char *ptr, size_t count, size_t width, void *userdata) {
    struct bounded *dest = userdata;
    if (width && count > SIZE_MAX / width) return 0;
    size_t n = count * width;
    if (n > dest->limit - dest->used) { dest->overflow = 1; return 0; }
    memcpy(dest->buf + dest->used, ptr, n);
    dest->used += n;
    dest->buf[dest->used] = '\0';
    return n;
}

static int valid_id(const char *text) {
    if (!text || strlen(text) != 55 || memcmp(text, "fasp:system:", 12) != 0) return 0;
    for (size_t i = 12; i < 55; i++) {
        char c = text[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    return 1;
}

static int decode_public(const char *value, unsigned char raw[32]) {
    /* A 32-byte Ed25519 public key is 43 URL-safe unpadded base64 chars. */
    if (!value || strlen(value) != 43) return 0;
    char encoded[45];
    for (size_t i = 0; i < 43; i++) {
        char c = value[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
        encoded[i] = c == '-' ? '+' : c == '_' ? '/' : c;
    }
    encoded[43] = '='; encoded[44] = '\0';
    unsigned char decoded[33];
    if (EVP_DecodeBlock(decoded, (const unsigned char *)encoded, 44) != 33) return 0;
    memcpy(raw, decoded, 32);
    /* Last decoded byte is the padding artifact; validate unused bits and
     * canonical encoding by round-tripping the exact original 32 bytes. */
    char recoded[48];
    if (EVP_EncodeBlock((unsigned char *)recoded, raw, 32) != 44) return 0;
    for (size_t i = 0; i < 43; i++) {
        if ((recoded[i] == '+' ? '-' : recoded[i] == '/' ? '_' : recoded[i]) != value[i]) return 0;
    }
    return 1;
}

static int card_matches(struct json_object *card, const char *expected) {
    struct json_object *field = NULL;
    if (!json_object_is_type(card, json_type_object)) return 0;
    if (!json_object_object_get_ex(card, "fasp", &field) ||
        !json_object_is_type(field, json_type_string) ||
        strcmp(json_object_get_string(field), "fasp/1.0") != 0) return 0;
    if (!json_object_object_get_ex(card, "type", &field) ||
        !json_object_is_type(field, json_type_string) ||
        strcmp(json_object_get_string(field), "id_card") != 0) return 0;
    if (!json_object_object_get_ex(card, "system_id", &field) ||
        !json_object_is_type(field, json_type_string) ||
        strcmp(json_object_get_string(field), expected) != 0) return 0;
    if (!json_object_object_get_ex(card, "public_key", &field) ||
        !json_object_is_type(field, json_type_string)) return 0;
    unsigned char pub[32], digest[32];
    const char *keytext = json_object_get_string(field);
    if (!decode_public(keytext, pub) || !SHA256(pub, sizeof(pub), digest)) return 0;
    char b64[45];
    if (EVP_EncodeBlock((unsigned char *)b64, digest, 32) != 44) return 0;
    for (size_t i = 0; i < 43; i++) {
        char c = b64[i] == '+' ? '-' : b64[i] == '/' ? '_' : b64[i];
        if (expected[i + 12] != c) return 0;
    }
    return 1;
}

static struct json_object *parse_object(const char *bytes, size_t n) {
    if (n == 0 || n > INT32_MAX) return NULL;
    struct json_tokener *parser = json_tokener_new_ex(32);
    if (!parser) return NULL;
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *value = json_tokener_parse_ex(parser, bytes, (int)n);
    int valid = json_tokener_get_error(parser) == json_tokener_success &&
        json_tokener_get_parse_end(parser) == n &&
        json_object_is_type(value, json_type_object);
    json_tokener_free(parser);
    if (!valid) { if (value) json_object_put(value); return NULL; }
    return value;
}

static int safe_url(const char *base, char *result, size_t cap, int *is_https) {
    CURLU *url = curl_url();
    if (!url) return 0;
    int ok = 0;
    char *scheme = NULL, *host = NULL, *path = NULL, *query = NULL, *fragment = NULL, *user = NULL, *password = NULL;
    if (curl_url_set(url, CURLUPART_URL, base, 0) != CURLUE_OK) goto finish;
    if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
        curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK) goto finish;
    *is_https = strcmp(scheme, "https") == 0;
    if (!*is_https && (strcmp(scheme, "http") != 0 ||
         !(strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0 || strcmp(host, "[::1]") == 0))) goto finish;
    /* No credentials, query, fragment or path in base URLs. They would make
     * both /profile and /fasp/v1/envelopes ambiguous. */
    if (curl_url_get(url, CURLUPART_USER, &user, 0) == CURLUE_OK ||
        curl_url_get(url, CURLUPART_PASSWORD, &password, 0) == CURLUE_OK ||
        curl_url_get(url, CURLUPART_QUERY, &query, 0) == CURLUE_OK ||
        curl_url_get(url, CURLUPART_FRAGMENT, &fragment, 0) == CURLUE_OK) goto finish;
    if (curl_url_get(url, CURLUPART_PATH, &path, 0) != CURLUE_OK) goto finish;
    if (strcmp(path, "/") != 0) goto finish;
    if (strlen(base) + 1 >= cap) goto finish;
    strcpy(result, base);
    while (strlen(result) > 0 && result[strlen(result) - 1] == '/') result[strlen(result) - 1] = '\0';
    ok = 1;
finish:
    curl_free(scheme); curl_free(host); curl_free(path); curl_free(user);
    curl_free(password); curl_free(query); curl_free(fragment); curl_url_cleanup(url);
    return ok;
}

static int request(CURL *curl, const char *url, const char *body,
                   char *data, size_t maximum, long *status, const char *ca, const char *pin) {
    struct bounded dest = { .buf = data, .used = 0, .limit = maximum, .overflow = 0 };
    dest.buf[0] = '\0';
    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https,http");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    /* Prevent environment-proxy redirects of loopback HTTP traffic. */
    if (strncmp(url, "http://", 7) == 0 || strstr(url, "://localhost:") || strstr(url, "://127.0.0.1:")) curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &dest);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "fasp-native-http/1.0");
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "identity");
    if (ca && curl_easy_setopt(curl, CURLOPT_CAINFO, ca) != CURLE_OK) return 0;
    if (pin && curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pin) != CURLE_OK) return 0;
    struct curl_slist *headers = NULL;
    if (body) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    }
    CURLcode result = curl_easy_perform(curl);
    if (result == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    curl_slist_free_all(headers);
    if (result != CURLE_OK) {
        fprintf(stderr, "Transport failure: %s%s\n", curl_easy_strerror(result), dest.overflow ? " (body too large)" : "");
        return 0;
    }
    return 1;
}

static int read_message(char *out, size_t cap) {
    size_t n = fread(out, 1, cap, stdin);
    if (ferror(stdin) || n == 0 || n == cap || (n && out[n - 1] != '\n' && !feof(stdin))) return 0;
    /* Reject a message over the FASP 64KiB ingress maximum, plus trailing LF. */
    if (n && out[n - 1] == '\n') --n;
    out[n] = '\0';
    return n > 0 && n <= MAX_ENVELOPE;
}

int main(int argc, char **argv) {
    if (argc < 4 || argc > 8 || (strcmp(argv[1], "profile") && strcmp(argv[1], "send"))) {
        fprintf(stderr, "Usage: fasp-c-http profile|send BASE_URL EXPECTED_SYSTEM_ID [--ca FILE] [--pin TLS_SPKI]\n");
        return 2;
    }
    const char *ca = NULL, *pin = NULL;
    for (int i = 4; i < argc; i += 2) {
        if (i + 1 >= argc) return 2;
        if (!strcmp(argv[i], "--ca") && !ca) ca = argv[i + 1];
        else if (!strcmp(argv[i], "--pin") && !pin) pin = argv[i + 1];
        else return 2;
    }
    int https = 0;
    char base[2048], target[2160];
    if (!valid_id(argv[3]) || !safe_url(argv[2], base, sizeof(base), &https)) {
        fputs("Invalid peer identity or URL (HTTP is loopback-only)\n", stderr);
        return 2;
    }
    if (!https && (ca || pin)) { fputs("TLS options on an HTTP URL\n", stderr); return 2; }
    /* This transport does not verify the signed FASP card; require an
     * independently confirmed TLS SPKI pin on remote HTTPS connections. */
    if (https) {
        if (!pin || strlen(pin) != 52 || strncmp(pin, "sha256//", 8) != 0 || pin[51] != '=') {
            fputs("HTTPS requires an independently verified --pin sha256//... TLS SPKI fingerprint\n", stderr);
            return 2;
        }
        for (size_t k = 8; k < 51; ++k) {
            char c = pin[k];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '+' || c == '/')) {
                fputs("Malformed TLS pin\n", stderr); return 2;
            }
        }
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 2;
    CURL *curl = curl_easy_init();
    if (!curl) { curl_global_cleanup(); return 2; }
    int code = 1;
    char profile[MAX_PROFILE + 1], reply[MAX_REPLY + 1];
    long status = 0;
    snprintf(target, sizeof(target), "%s/profile", base);
    if (!request(curl, target, NULL, profile, MAX_PROFILE, &status, ca, pin) || status != 200) {
        fprintf(stderr, "Cannot fetch profile (HTTP %ld)\n", status); goto done;
    }
    struct json_object *card = parse_object(profile, strlen(profile));
    if (!card || !card_matches(card, argv[3])) {
        fprintf(stderr, "Peer identity mismatch or invalid profile\n");
        if (card) json_object_put(card);
        goto done;
    }
    if (!strcmp(argv[1], "profile")) {
        struct json_object *capabilities = NULL;
        json_object_object_get_ex(card, "protocol_support", &capabilities);
        if (capabilities) printf("%s\n", json_object_to_json_string_ext(capabilities, JSON_C_TO_STRING_PLAIN));
        else puts("{}");
        json_object_put(card);
        code = 0;
        goto done;
    }
    json_object_put(card);
    char payload[MAX_ENVELOPE + 2];
    if (!read_message(payload, sizeof(payload))) { fputs("Invalid or oversized input envelope\n", stderr); goto done; }
    struct json_object *envelope = parse_object(payload, strlen(payload));
    if (!envelope) { fputs("Input is not one JSON object\n", stderr); goto done; }
    struct json_object *field = NULL;
    int valid = json_object_object_get_ex(envelope, "to", &field) && json_object_is_type(field, json_type_string) &&
        strcmp(json_object_get_string(field), argv[3]) == 0;
    valid = valid && json_object_object_get_ex(envelope, "fasp", &field) && json_object_is_type(field, json_type_string) &&
        strcmp(json_object_get_string(field), "fasp/1.0") == 0;
    json_object_put(envelope);
    if (!valid) { fputs("Envelope recipient/version mismatch\n", stderr); goto done; }
    snprintf(target, sizeof(target), "%s/fasp/v1/envelopes", base);
    if (!request(curl, target, payload, reply, MAX_REPLY, &status, ca, pin)) goto done;
    struct json_object *response = parse_object(reply, strlen(reply));
    if (!response) { fputs("Invalid JSON response\n", stderr); goto done; }
    struct json_object *semantic_type = NULL;
    int is_protocol_error = json_object_object_get_ex(response, "type", &semantic_type) &&
        json_object_is_type(semantic_type, json_type_string) &&
        strcmp(json_object_get_string(semantic_type), "protocol.error") == 0;
    if (status < 200 || status > 299 || is_protocol_error) {
        fprintf(stderr, "FASP request failed (HTTP %ld): %s\n", status, json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN));
    } else {
        puts(json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN));
        code = 0;
    }
    json_object_put(response);
done:
    curl_easy_cleanup(curl); curl_global_cleanup();
    return code;
}