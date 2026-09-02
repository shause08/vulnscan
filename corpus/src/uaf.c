/*
 * VULNERABILITY: Use-After-Free
 * CLASS: use-after-free
 *
 * A heap object is freed but the pointer is not cleared.  A subsequent call
 * re-uses the dangling pointer to read from / write to the freed memory.
 * In a real allocator the freed chunk can be reclaimed and its contents
 * replaced, leading to type confusion or controlled-data dereference.
 *
 * Exploit primitive: type confusion, function-pointer hijack, info leak.
 *
 * CWE-416: Use After Free
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];
    void (*greet)(const char *);   /* function pointer — interesting target */
} User;

static void default_greet(const char *name) {
    printf("Hello, %s!\n", name);
}

static void admin_greet(const char *name) {
    printf("[ADMIN] Welcome back, %s!\n", name);
}

int main(void) {
    User *u = malloc(sizeof(User));
    if (!u) { perror("malloc"); return 1; }

    strncpy(u->name, "Alice", sizeof(u->name) - 1);
    u->greet = default_greet;
    u->greet(u->name);   /* first use — OK */

    free(u);             /* VULN: object freed, pointer not set to NULL */

    /* Simulate an attacker reclaiming the freed chunk and overwriting it. */
    char *attacker_buf = malloc(sizeof(User));
    if (!attacker_buf) { perror("malloc"); return 1; }
    /* Write a fake function pointer into the slot where greet used to be. */
    memset(attacker_buf, 0, sizeof(User));
    memcpy(attacker_buf + 32, &(void *){admin_greet}, sizeof(void *));

    /* VULN: dangling use — u->greet now points to attacker-controlled value */
    u->greet(u->name);

    free(attacker_buf);
    return 0;
}
