/*
 * VULNERABILITY: Heap Buffer Overflow
 * CLASS: heap-buffer-overflow
 *
 * A 64-byte buffer is allocated on the heap with malloc().  The user-supplied
 * length (argv[1]) is passed directly to read(), allowing more bytes to be
 * written than the allocation can hold.  This corrupts heap metadata and/or
 * adjacent heap objects.
 *
 * Exploit primitive: heap metadata corruption → arbitrary write (House of
 * Force / unsorted-bin attack), or adjacent-object overwrite.
 *
 * CWE-122: Heap-based Buffer Overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALLOC_SIZE 64

void vulnerable(size_t user_len) {
    char *buf = malloc(ALLOC_SIZE); /* VULN: fixed allocation */
    if (!buf) { perror("malloc"); exit(1); }

    printf("Enter up to %zu bytes: ", user_len);
    /* VULN: user_len is not clamped to ALLOC_SIZE */
    ssize_t n = read(STDIN_FILENO, buf, user_len);
    if (n > 0) buf[n - 1] = '\0';
    printf("Read: %s\n", buf);
    free(buf);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bytes_to_read>\n", argv[0]);
        return 1;
    }
    size_t len = (size_t)atol(argv[1]); /* user-controlled length */
    vulnerable(len);
    return 0;
}
