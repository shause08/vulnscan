/*
 * VULNERABILITY: Format String
 * CLASS: format-string
 *
 * User input is passed directly as the format argument to printf().
 * An attacker can supply format specifiers (%x, %s, %n …) to:
 *   - read arbitrary stack/memory values (%x, %p, %s)
 *   - write arbitrary values to arbitrary addresses (%n)
 *
 * Exploit primitive: arbitrary read → info leak; %n → arbitrary write.
 *
 * CWE-134: Use of Externally-Controlled Format String
 */

#include <stdio.h>
#include <string.h>

#define BUF_SIZE 256

void vulnerable(const char *input) {
    char buf[BUF_SIZE];
    strncpy(buf, input, BUF_SIZE - 1);
    buf[BUF_SIZE - 1] = '\0';
    printf(buf);   /* VULN: user-controlled format string — no format argument */
    putchar('\n');
}

int main(void) {
    char input[BUF_SIZE];
    printf("Enter message: ");
    if (fgets(input, sizeof(input), stdin) == NULL) return 1;
    /* Strip trailing newline */
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') input[len - 1] = '\0';
    vulnerable(input);
    return 0;
}
