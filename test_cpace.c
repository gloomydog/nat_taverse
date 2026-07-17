#include <stdio.h>
#include <string.h>
#include "cpace.h"

static void hexdump(const char *label, const uint8_t *buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int run_case(const char *room_code_a, const char *room_code_b, const char *room_id, int expect_match) {
    cpace_ctx a, b;
    uint8_t mac_a[CPACE_MACBYTES], mac_b[CPACE_MACBYTES];

    if (cpace_init(&a, room_code_a, strlen(room_code_a), room_id, strlen(room_id), 1) != 0) {
        printf("FAIL: cpace_init(A)\n"); return 1;
    }
    if (cpace_init(&b, room_code_b, strlen(room_code_b), room_id, strlen(room_id), 0) != 0) {
        printf("FAIL: cpace_init(B)\n"); return 1;
    }

    /* Confirm the generator differs depending on room_code */
    if (memcmp(a.generator, b.generator, CPACE_POINTBYTES) == 0 && strcmp(room_code_a, room_code_b) != 0) {
        printf("FAIL: generators matched despite different room_codes (unexpected)\n"); return 1;
    }

    /* Exchange public points and have each side derive its session key */
    if (cpace_derive_session_key(&a, b.my_point) != 0) { printf("FAIL: derive(A)\n"); return 1; }
    if (cpace_derive_session_key(&b, a.my_point) != 0) { printf("FAIL: derive(B)\n"); return 1; }

    int key_match = (memcmp(a.session_key, b.session_key, CPACE_SESSIONKEYBYTES) == 0);

    cpace_compute_confirmation(&a, "A", mac_a);
    cpace_compute_confirmation(&b, "A", mac_b); /* B computes the confirmation MAC "as if it were A" */
    int mac_match = (sodium_memcmp(mac_a, mac_b, CPACE_MACBYTES) == 0);

    printf("--- room_code_a=%s room_code_b=%s ---\n", room_code_a, room_code_b);
    hexdump("generator(A)", a.generator, CPACE_POINTBYTES);
    hexdump("session_key(A)", a.session_key, CPACE_SESSIONKEYBYTES);
    hexdump("session_key(B)", b.session_key, CPACE_SESSIONKEYBYTES);
    printf("key_match=%d mac_match=%d (expect_match=%d)\n\n", key_match, mac_match, expect_match);

    if (key_match != expect_match || mac_match != expect_match) {
        printf("FAIL: result did not match expectation\n");
        return 1;
    }
    return 0;
}

int main(void) {
    int failures = 0;

    /* Case 1: same room_code, same room_id -> keys should match */
    failures += run_case("X7K9QP2M", "X7K9QP2M", "room:abc123", 1);

    /* Case 2: different room_code -> keys should NOT match (equivalent to one guess at brute force) */
    failures += run_case("X7K9QP2M", "DIFFERENT", "room:abc123", 0);

    /* Case 3: passing an invalid point (all zero) should make derive_session_key fail */
    {
        cpace_ctx a;
        uint8_t zero_point[CPACE_POINTBYTES];
        memset(zero_point, 0, sizeof(zero_point));
        cpace_init(&a, "X7K9QP2M", 8, "room:abc123", 11, 1);
        int rc = cpace_derive_session_key(&a, zero_point);
        printf("--- invalid point test --- rc=%d (expected: -1)\n\n", rc);
        if (rc == 0) { printf("FAIL: an invalid point was accepted\n"); failures++; }
    }

    if (failures == 0) {
        printf("=== all tests passed ===\n");
    } else {
        printf("=== %d test(s) failed ===\n", failures);
    }
    return failures;
}
