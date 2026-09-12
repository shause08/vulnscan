CC      := gcc
SRCDIR  := src
BINDIR  := bin

SRCS := stack_bof heap_bof format_string integer_overflow strcpy_bof heap_overflow

# ── Compiler flags ────────────────────────────────────────────────────────────

# Standard build (default protections — for reference)
CFLAGS_NORMAL := -O0 -g -Wall -Wextra

# Vulnerability-demo build: all mitigations disabled so the bug is reliably
# reachable and the scanner can observe unobscured behaviour.
CFLAGS_VULN := \
    -O0 -g \
    -fno-stack-protector \
    -z execstack \
    -no-pie \
    -Wl,-z,norelro \
    -D_FORTIFY_SOURCE=0 \
    -w

# AddressSanitizer build: debug info + ASan instrumentation for reliable
# dynamic triage (crash type, location, call stack).
CFLAGS_ASAN := -O0 -g -fsanitize=address -fno-omit-frame-pointer -w

# ── Targets ───────────────────────────────────────────────────────────────────

.PHONY: all normal vuln asan clean

all: normal vuln asan

normal: $(patsubst %,$(BINDIR)/%_normal,$(SRCS))
vuln:   $(patsubst %,$(BINDIR)/%_vuln,$(SRCS))
asan:   $(patsubst %,$(BINDIR)/%_asan,$(SRCS))

$(BINDIR):
	mkdir -p $(BINDIR)

# Normal builds
$(BINDIR)/%_normal: $(SRCDIR)/%.c | $(BINDIR)
	$(CC) $(CFLAGS_NORMAL) -o $@ $<

# Vuln builds (no protections)
$(BINDIR)/stack_bof_vuln: $(SRCDIR)/stack_bof.c | $(BINDIR)
	$(CC) $(CFLAGS_VULN) -o $@ $< -Wno-implicit-function-declaration

$(BINDIR)/%_vuln: $(SRCDIR)/%.c | $(BINDIR)
	$(CC) $(CFLAGS_VULN) -o $@ $<

# ASan builds
$(BINDIR)/%_asan: $(SRCDIR)/%.c | $(BINDIR)
	$(CC) $(CFLAGS_ASAN) -o $@ $<

clean:
	rm -rf $(BINDIR)
