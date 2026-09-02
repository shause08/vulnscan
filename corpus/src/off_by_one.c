/*
 * VULNERABILITY: Off-by-One (stack)
 * CLASS: off-by-one
 *
 * The copy loop uses `i <= len` instead of `i < len`, writing len+1 bytes
 * (including the NUL terminator at input[len]) into a BUF_SIZE-byte stack
 * buffer.  When len == BUF_SIZE - 1 (the maximum valid fill), the NUL lands
 * at buf[BUF_SIZE] — one byte past the end — overwriting the low byte of the
 * saved RBP on the stack.
 *
 * This single-byte overwrite can corrupt the frame pointer, enabling a
 * frame-pointer attack to redirect execution after the next function return.
 *
 * Exploit primitive: saved-RBP low-byte overwrite → frame-pointer pivot.
 *
 * CWE-193: Off-by-One Error
 */

#include <stdio.h>
#include <string.h>

#define BUF_SIZE 64

void vulnerable(const char *input, size_t len) {
    char buf[BUF_SIZE];

    /* VULN: `i <= len` copies len+1 bytes — writes buf[len] when len >= BUF_SIZE,
     *       or writes the NUL at buf[BUF_SIZE] when len == BUF_SIZE - 1 is NOT
     *       the issue — re-reading: when len == BUF_SIZE, buf[BUF_SIZE] is written.
     *       No bounds guard here so the off-by-one is not suppressed. */
    for (size_t i = 0; i <= len; i++) {
        buf[i] = input[i];  /* VULN: buf[BUF_SIZE] written when i == BUF_SIZE */
    }
    printf("Received: %s\n", buf);
}

int main(void) {
    /* Input buffer is one byte larger so fgets doesn't truncate the triggering input */
    char input[BUF_SIZE + 2];
    printf("Enter input (max %d chars): ", BUF_SIZE - 1);
    if (fgets(input, sizeof(input), stdin) == NULL) return 1;

    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') { input[--len] = '\0'; }

    vulnerable(input, len);
    return 0;
}
