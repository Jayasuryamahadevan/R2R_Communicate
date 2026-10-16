/* Minimal FASP 1.0 native C sender: Ed25519 identity, signed card, heartbeat.
 * Requires C11/POSIX and OpenSSL libcrypto, not Python/Node/WASM/JSON libraries.
 * JSON is deliberately limited to fixed, ASCII-only message templates.
 * Do not extend to arbitrary payloads without a complete RFC 8785 encoder.
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdarg.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BUF 8192
#define ID_SIZE 64

static void die(const char *message) {
    fprintf(stderr, "fasp-c: %s\n", message);
    exit(1);
}

static void formatted(char *dest, size_t length, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int count = vsnprintf(dest, length, fmt, args);
    va_end(args);
    if (count < 0 || (size_t)count >= length) die("Message too long");
}

static void base64url(const unsigned char *raw, size_t length, char *dest, size_t size) {
    if (length > 1024 || size < 4 * ((length + 2) / 3) + 1) die("Invalid encoding bounds");
    int count = EVP_EncodeBlock((unsigned char *)dest, raw, (int)length);
    if (count <= 0) die("Base64 encoding failed");
    for (int k = 0; k < count; ++k) {
        if (dest[k] == '+') dest[k] = '-';
        if (dest[k] == '/') dest[k] = '_';
    }
    while (count && dest[count - 1] == '=') --count;
    dest[count] = '\0';
}

static int decode_hex(unsigned char *output, const char *hex, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        unsigned int value = 0;
        char pair[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
        if (sscanf(pair, "%2x", &value) != 1) return 0;
        for (int k = 0; k < 2; ++k)
            if (!((pair[k] >= '0' && pair[k] <= '9') ||
                  (pair[k] >= 'a' && pair[k] <= 'f'))) return 0;
        output[i] = (unsigned char)value;
    }
    return 1;
}

static void write_identity(const char *path) {
    unsigned char secret[32];
    char hex[66];
    if (RAND_bytes(secret, sizeof(secret)) != 1) die("Secure random generation failed");
    for (size_t i = 0; i < 32; ++i) snprintf(hex + i * 2, 3, "%02x", secret[i]);
    hex[64] = '\n'; hex[65] = '\0';
    umask(077);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
    if (fd < 0) die("Cannot create identity file (will not overwrite)");
    ssize_t n = write(fd, hex, 65);
    int persisted = n == 65 && fsync(fd) == 0;
    if (close(fd) != 0) persisted = 0;
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(hex, sizeof(hex));
    if (!persisted) {
        /* Do not strand a partial private-key file that blocks re-init. */
        unlink(path);
        die("Cannot persist identity");
    }
    puts("Identity created. Protect this file: it contains the signing secret.");
}

static EVP_PKEY *load_identity(const char *path, unsigned char public_key[32]) {
    unsigned char secret[32];
    char hex[68];
    struct stat info;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        (info.st_mode & 077) != 0 || info.st_uid != geteuid())
        die("Identity file must be a private regular file owned by this user");
    ssize_t n = read(fd, hex, sizeof(hex));
    if (close(fd) != 0 || n != 65 || hex[64] != '\n' || !decode_hex(secret, hex, 32))
        die("Identity file is invalid");
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, secret, 32);
    OPENSSL_cleanse(secret, sizeof(secret));
    if (!key) die("Failed to load Ed25519 identity");
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(key, public_key, &len) != 1 || len != 32)
        die("Failed to derive Ed25519 public key");
    return key;
}

static void timestamp(time_t when, char result[21]) {
    struct tm t;
    if (!gmtime_r(&when, &t) || strftime(result, 21, "%Y-%m-%dT%H:%M:%SZ", &t) != 20)
        die("Could not format UTC timestamp");
}

static void signature(EVP_PKEY *key, const char *message, char out[89]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char raw[64];
    size_t raw_size = sizeof(raw);
    if (!ctx || EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1 ||
        EVP_DigestSign(ctx, raw, &raw_size, (const unsigned char *)message, strlen(message)) != 1 ||
        raw_size != 64) die("Ed25519 signing failed");
    EVP_MD_CTX_free(ctx);
    base64url(raw, raw_size, out, 89);
}

static void random_id(char output[37]) {
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1) die("Secure random generation failed");
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    snprintf(output, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
             raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
}

static int valid_recipient(const char *id) {
    if (strncmp(id, "fasp:system:", 12) != 0 || strlen(id) != 55) return 0;
    for (const char *p = id + 12; *p; ++p)
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return 0;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) die("Usage: fasp-c-peer init|id|card|heartbeat KEYFILE [RECIPIENT_SYSTEM_ID]");
    if (strcmp(argv[1], "init") == 0 && argc == 3) { write_identity(argv[2]); return 0; }
    if (argc != 3 && argc != 4) die("Invalid arguments");
    unsigned char pub[32], hash[SHA256_DIGEST_LENGTH], nonce[12];
    EVP_PKEY *key = load_identity(argv[2], pub);
    SHA256(pub, 32, hash);
    char pub64[45], hash64[45], system_id[ID_SIZE], kid[18], now[21], expires[21];
    base64url(pub, 32, pub64, sizeof(pub64));
    base64url(hash, sizeof(hash), hash64, sizeof(hash64));
    snprintf(system_id, sizeof(system_id), "fasp:system:%s", hash64);
    snprintf(kid, sizeof(kid), "ed25519-%.8s", pub64);
    time_t current = time(NULL);
    timestamp(current, now);
    if (strcmp(argv[1], "id") == 0 && argc == 3) { puts(system_id); EVP_PKEY_free(key); return 0; }
    char unsigned_record[BUF], sig[89], output[BUF];
    if (strcmp(argv[1], "card") == 0 && argc == 3) {
        timestamp(current + 30 * 86400, expires);
        formatted(unsigned_record, sizeof(unsigned_record),
          "{\"capabilities\":[],\"display_name\":\"native-c-peer\",\"endpoints\":{\"envelopes\":null,\"profile\":null},\"expires_at\":\"%s\",\"fasp\":\"fasp/1.0\",\"issued_at\":\"%s\",\"key_id\":\"%s\",\"public_key\":\"%s\",\"system_id\":\"%s\",\"type\":\"id_card\"}",
          expires, now, kid, pub64, system_id);
        signature(key, unsigned_record, sig);
        formatted(output, sizeof(output),
          "{\"capabilities\":[],\"display_name\":\"native-c-peer\",\"endpoints\":{\"envelopes\":null,\"profile\":null},\"expires_at\":\"%s\",\"fasp\":\"fasp/1.0\",\"issued_at\":\"%s\",\"key_id\":\"%s\",\"public_key\":\"%s\",\"signature\":{\"alg\":\"Ed25519\",\"kid\":\"%s\",\"value\":\"%s\"},\"system_id\":\"%s\",\"type\":\"id_card\"}",
          expires, now, kid, pub64, kid, sig, system_id);
    } else if (strcmp(argv[1], "heartbeat") == 0 && argc == 4) {
        if (!valid_recipient(argv[3])) die("Invalid FASP recipient system ID");
        timestamp(current + 120, expires);
        char uuid[37], nonce64[32];
        random_id(uuid);
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) die("Secure random generation failed");
        base64url(nonce, sizeof(nonce), nonce64, sizeof(nonce64));
        formatted(unsigned_record, sizeof(unsigned_record),
          "{\"expires_at\":\"%s\",\"fasp\":\"fasp/1.0\",\"from\":\"%s\",\"issued_at\":\"%s\",\"kind\":\"heartbeat\",\"message_id\":\"%s\",\"nonce\":\"%s\",\"payload\":{},\"to\":\"%s\"}",
          expires, system_id, now, uuid, nonce64, argv[3]);
        signature(key, unsigned_record, sig);
        formatted(output, sizeof(output),
          "{\"expires_at\":\"%s\",\"fasp\":\"fasp/1.0\",\"from\":\"%s\",\"issued_at\":\"%s\",\"kind\":\"heartbeat\",\"message_id\":\"%s\",\"nonce\":\"%s\",\"payload\":{},\"signature\":{\"alg\":\"Ed25519\",\"kid\":\"%s\",\"value\":\"%s\"},\"to\":\"%s\"}",
          expires, system_id, now, uuid, nonce64, kid, sig, argv[3]);
    } else die("Unknown command");
    puts(output);
    EVP_PKEY_free(key);
    return 0;
}
