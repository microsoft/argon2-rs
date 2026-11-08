#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "argon2.h"

int main(void) {
    static const struct {
        uint32_t lanes, memory_kib, iterations, password_len, secret_len, ad_len;
    } cases[] = {
        {1, 8, 1, 0, 0, 0},
        {2, 67, 3, 32, 8, 12},
        {3, 100, 2, 300, 0, 0},
        {4, 256, 2, 32, 8, 12}
    };
    static const uint32_t lengths[] = {4, 16, 32, 63, 64, 65, 96};
    static const uint32_t versions[] = {ARGON2_VERSION_10, ARGON2_VERSION_13};
    uint8_t password[300], salt[16], secret[8], ad[12], out[96];
    unsigned algorithm;
    size_t v, c, n, byte;

    memset(password, 1, sizeof(password));
    memset(salt, 2, sizeof(salt));
    memset(secret, 3, sizeof(secret));
    memset(ad, 4, sizeof(ad));
    puts("# P-H-C/phc-winner-argon2 62358ba2123abd17fccf2a108a301d4b52c01a7c (20190702)");
    puts("# algorithm version lanes memory_kib iterations password_len secret_len ad_len tag_hex");
    for (algorithm = 0; algorithm < 3; ++algorithm) {
        for (v = 0; v < sizeof(versions) / sizeof(versions[0]); ++v) {
            for (c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
                for (n = 0; n < sizeof(lengths) / sizeof(lengths[0]); ++n) {
                    argon2_context ctx = {
                        out, lengths[n],
                        password, cases[c].password_len,
                        salt, sizeof(salt),
                        secret, cases[c].secret_len,
                        ad, cases[c].ad_len,
                        cases[c].iterations, cases[c].memory_kib,
                        cases[c].lanes, 1,
                        versions[v],
                        NULL, NULL, ARGON2_DEFAULT_FLAGS
                    };
                    int result = argon2_ctx(&ctx, (argon2_type)algorithm);
                    if (result != ARGON2_OK) {
                        fprintf(stderr, "reference case failed: %s\n",
                                argon2_error_message(result));
                        return 1;
                    }
                    printf("%u %u %u %u %u %u %u %u ",
                           algorithm, (unsigned)versions[v],
                           (unsigned)cases[c].lanes,
                           (unsigned)cases[c].memory_kib,
                           (unsigned)cases[c].iterations,
                           (unsigned)cases[c].password_len,
                           (unsigned)cases[c].secret_len,
                           (unsigned)cases[c].ad_len);
                    for (byte = 0; byte < lengths[n]; ++byte) {
                        printf("%02x", (unsigned)out[byte]);
                    }
                    putchar('\n');
                }
            }
        }
    }
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fputs("failed to write reference vectors\n", stderr);
        return 1;
    }
    return 0;
}
