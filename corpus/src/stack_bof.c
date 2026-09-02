/*
 * VULNERABILITY: Stack Buffer Overflow
 * CLASS: stack-buffer-overflow
 *
 * gets() reads an unbounded number of bytes into a fixed 64-byte stack buffer.
 * An input longer than 63 bytes overwrites adjacent stack data, including the
 * saved RBP and the saved return address (RIP), giving an attacker control of
 * the instruction pointer.
 *
 * Exploit primitive: EIP/RIP control → arbitrary code execution (if NX off)
 *                    or ROP chain (if NX on).
 *
 * CWE-121: Stack-based Buffer Overflow
 */

#include <stdio.h>
#include <string.h>

void vulnerable(void) {
    char buf[64];  /* VULN: fixed-size stack buffer */
    printf("Enter name: ");
    gets(buf);     /* VULN: no bounds check — overwrites stack on long input */
    printf("Hello, %s!\n", buf);
}

int main(void) {
    vulnerable();
    return 0;
}
