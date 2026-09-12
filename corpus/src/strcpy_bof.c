/*
 * VULNERABILITY: Stack Buffer Overflow via strcpy
 * CLASS: stack-buffer-overflow
 *
 * User input is read into a 256-byte staging buffer, then copied into a
 * 32-byte stack buffer with strcpy(), which performs no bounds check.
 * Any input longer than 31 characters overflows the destination buffer,
 * corrupting adjacent stack variables and the saved return address.
 *
 * Exploit primitive: saved RIP overwrite -> arbitrary code execution / ROP.
 *
 * CWE-121: Stack-based Buffer Overflow
 */

#include <stdio.h>
#include <string.h>

#define INPUT_SIZE 256
#define BUF_SIZE    32

void vulnerable(const char *src) {
    char buf[BUF_SIZE];   /* VULN: fixed 32-byte stack buffer */
    strcpy(buf, src);     /* VULN: no bounds check — overwrites stack if src > 31 bytes */
    printf("Stored: %s\n", buf);
}

int main(void) {
    char input[INPUT_SIZE];
    printf("Enter text: ");
    if (fgets(input, sizeof(input), stdin) == NULL) return 1;
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') input[len - 1] = '\0';
    vulnerable(input);
    return 0;
}
