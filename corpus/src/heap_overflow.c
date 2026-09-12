/*
 * VULNERABILITY: Heap Buffer Overflow via memcpy
 * CLASS: heap-buffer-overflow
 *
 * A 64-byte buffer is allocated on the heap.  The user supplies both the
 * data (via stdin) and the number of bytes to copy (via the first line of
 * stdin).  The copy length is not validated against the allocation size, so
 * a value greater than 64 writes past the end of the heap chunk, corrupting
 * heap metadata or adjacent allocations.
 *
 * Exploit primitive: heap metadata corruption -> write-what-where primitive.
 *
 * CWE-122: Heap-based Buffer Overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HEAP_SIZE 64

int main(void) {
    size_t copy_len = 0;
    char staging[512];

    printf("Bytes to copy: ");
    if (scanf("%zu", &copy_len) != 1) return 1;

    /* Read raw data into a staging buffer */
    printf("Enter data: ");
    ssize_t n = read(STDIN_FILENO, staging, sizeof(staging) - 1);
    if (n <= 0) return 1;

    char *buf = malloc(HEAP_SIZE);   /* VULN: fixed 64-byte heap allocation */
    if (!buf) { perror("malloc"); exit(1); }

    /* VULN: copy_len is not clamped to HEAP_SIZE */
    memcpy(buf, staging, copy_len);

    size_t safe_len = copy_len < HEAP_SIZE ? copy_len : HEAP_SIZE - 1;
    buf[safe_len] = '\0';
    printf("Stored: %s\n", buf);
    free(buf);
    return 0;
}
