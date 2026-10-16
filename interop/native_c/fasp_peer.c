/* Minimal POSIX command-line wrapper around the C-only FASP signing API.
 * Build: cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -o fasp-c \
 *        fasp_peer.c fasp_wire.c -lcrypto
 * Usage: fasp-c init identity.seed | id identity.seed | card identity.seed |
 *        fasp-c heartbeat identity.seed fasp:system:<recipient-id>
 * No runtime requirement on Python, Node or WASM. OpenSSL 1.1.1+ required.
 */
#define _POSIX_C_SOURCE 200809L
#include "fasp_wire.h"
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int read_seed(const char *path, unsigned char seed[32]) {
    char file[66];
    struct stat info;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 0;
    int valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        (info.st_mode & 0077) == 0 && info.st_uid == geteuid();
    ssize_t len = valid ? read(fd, file, sizeof(file)) : -1;
    if (close(fd) != 0 || len != 65 || file[64] != '\n') return 0;
    for (size_t i = 0; i < 32; ++i) {
        unsigned char a = (unsigned char)file[i * 2];
        unsigned char b = (unsigned char)file[i * 2 + 1];
        if (!((a >= '0' && a <= '9') || (a >= 'a' && a <= 'f')) ||
            !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f'))) {
            OPENSSL_cleanse(seed, 32);
            return 0;
        }
        unsigned int high = a >= 'a' ? a - 'a' + 10 : a - '0';
        unsigned int low = b >= 'a' ? b - 'a' + 10 : b - '0';
        seed[i] = (unsigned char)(high * 16 + low);
    }
    OPENSSL_cleanse(file, sizeof(file));
    return 1;
}

static int save_seed(const char *path, const unsigned char seed[32]) {
    const char digits[] = "0123456789abcdef";
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return 0;
    char content[65];
    for (size_t i = 0; i < 32; ++i) {
        content[2 * i] = digits[seed[i] >> 4];
        content[2 * i + 1] = digits[seed[i] & 15];
    }
    content[64] = '\n';
    int ok = write(fd, content, sizeof(content)) == (ssize_t)sizeof(content) && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    OPENSSL_cleanse(content, sizeof(content));
    if (!ok) unlink(path);
    return ok;
}

static int utc(char out[21], time_t delta) {
    time_t instant = time(NULL);
    struct tm moment;
    if (instant == (time_t)-1 || !gmtime_r(&(time_t){instant + delta}, &moment)) return 0;
    return strftime(out, 21, "%Y-%m-%dT%H:%M:%SZ", &moment) == 20;
}

static int random_hex_uuid(char out[37]) {
    unsigned char raw[16];
    int n;
    if (RAND_bytes(raw, 16) != 1) return 0;
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    n = snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
    OPENSSL_cleanse(raw, sizeof(raw));
    return n == 36;
}

int main(int argc, char **argv) {
    unsigned char seed[32] = {0};
    fasp_identity identity;
    char output[FASP_SIGNED_MAX], issued[21], expires[21], message_id[37], nonce[25];
    int ok = 0;
    memset(&identity, 0, sizeof(identity));
    if (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[1], "heartbeat") != 0)) goto finish;
    if (!strcmp(argv[1], "init")) {
        if (argc != 3 || RAND_bytes(seed, sizeof(seed)) != 1 ||
            !fasp_identity_from_seed(&identity, seed) || !save_seed(argv[2], seed)) goto finish;
        puts("Identity created. Protect this file: it contains the signing secret.");
        ok = 1;
        goto finish;
    }
    if (!read_seed(argv[2], seed) || !fasp_identity_from_seed(&identity, seed) || !utc(issued, 0)) goto finish;
    if (!strcmp(argv[1], "id") && argc == 3) {
        puts(identity.system_id);
        ok = 1;
    } else if (!strcmp(argv[1], "card") && argc == 3) {
        ok = utc(expires, 30 * 86400) && fasp_signed_card(&identity, issued, expires, output, sizeof(output));
    } else if (!strcmp(argv[1], "heartbeat") && argc == 4) {
        unsigned char nonce_raw[12];
        if (!utc(expires, 120) || !random_hex_uuid(message_id) || RAND_bytes(nonce_raw, 12) != 1) goto finish;
        /* A nonce is a 12-byte cryptographically random value encoded as 16
         * unpadded Base64URL chars. Use hex here instead to avoid additional
         * decoding requirements: wire nonce is an opaque bounded string. */
        if (snprintf(nonce, sizeof(nonce), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             nonce_raw[0], nonce_raw[1], nonce_raw[2], nonce_raw[3], nonce_raw[4], nonce_raw[5],
             nonce_raw[6], nonce_raw[7], nonce_raw[8], nonce_raw[9], nonce_raw[10], nonce_raw[11]) != 24) goto finish;
        OPENSSL_cleanse(nonce_raw, sizeof(nonce_raw));
        ok = fasp_signed_heartbeat(&identity, argv[3], issued, expires, message_id, nonce, output, sizeof(output));
    }
    if (ok && strcmp(argv[1], "id") != 0) puts(output);
finish:
    fasp_identity_clear(&identity);
    OPENSSL_cleanse(seed, sizeof(seed));
    if (!ok) {
        fputs("Usage: fasp-c init|id|card <identity-file> OR fasp-c heartbeat <identity-file> <recipient-system-id>\n", stderr);
        return 1;
    }
    return 0;
}
