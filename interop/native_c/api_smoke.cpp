// Independent C++ consumer of the C11 FASP signing API (no Python/Node).
#include "fasp_wire.h"
#include <cstdio>
#include <cstring>

int main() {
    unsigned char seed[32] = {0};
    fasp_identity id{};
    char card[FASP_SIGNED_MAX], hb[FASP_SIGNED_MAX];
    if (!fasp_identity_from_seed(&id, seed)) return 1;
    if (!fasp_signed_card(&id, "2026-10-16T10:00:00Z", "2026-10-17T10:00:00Z", card, sizeof(card))) return 2;
    if (!fasp_signed_heartbeat(&id, id.system_id, "2026-10-16T10:00:00Z", "2026-10-16T10:01:00Z", "static-test", "nonce-1", hb, sizeof(hb))) return 3;
    if (fasp_signed_heartbeat(&id, "../bad", "2026-10-16T10:00:00Z", "2026-10-16T10:01:00Z", "static-test", "nonce-1", hb, sizeof(hb))) return 4;
    if (fasp_signed_card(&id, "2026-10-17T10:00:00Z", "2026-10-16T10:00:00Z", card, sizeof(card))) return 5;
    if (std::strlen(card) == 0) return 6;
    if (fasp_signed_card(&id, "2026-10-16T10:00:00Z", "2026-10-17T10:00:00Z", card, 12)) return 7;
    fasp_identity_clear(&id);
    for (auto byte : id.seed) if (byte != 0) return 8;
    std::puts("FASP native C++ ABI smoke: OK");
    return 0;
}
