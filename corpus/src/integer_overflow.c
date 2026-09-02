/*
 * VULNERABILITY: Integer Overflow → Heap Buffer Overflow
 * CLASS: integer-overflow
 *
 * The allocation size is computed as  count * ELEM_SIZE  using unsigned
 * 16-bit arithmetic.  When count is large enough (e.g. 0x1001 with ELEM_SIZE
 * 64), the product wraps to a small value, so malloc() returns a
 * much-smaller-than-expected buffer.  The subsequent memcpy then overflows
 * that buffer.
 *
 * Exploit primitive: controlled heap overflow after size miscalculation.
 *
 * CWE-190: Integer Overflow or Wraparound
 * CWE-122: Heap-based Buffer Overflow (consequence)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ELEM_SIZE 64

void vulnerable(uint16_t count, const char *data, size_t data_len) {
    /* VULN: 16-bit multiplication wraps when count > 0x3FF (for ELEM_SIZE=64) */
    uint16_t alloc_size = count * ELEM_SIZE;

    printf("Allocating %u bytes for %u elements\n", alloc_size, count);
    char *buf = malloc(alloc_size ? alloc_size : 1);
    if (!buf) { perror("malloc"); exit(1); }

    /* VULN: copies data_len bytes into a possibly much smaller buffer */
    memcpy(buf, data, data_len);
    printf("Stored %zu bytes\n", data_len);
    free(buf);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <element_count>\n", argv[0]);
        return 1;
    }

    uint16_t count = (uint16_t)atoi(argv[1]); /* user-controlled count */

    /* Simulate reading count*ELEM_SIZE bytes of data from stdin */
    size_t data_len = (size_t)count * ELEM_SIZE;
    char *data = malloc(data_len + 1);
    if (!data) { perror("malloc"); exit(1); }
    size_t n = fread(data, 1, data_len, stdin);
    data[n] = '\0';

    vulnerable(count, data, n);
    free(data);
    return 0;
}
