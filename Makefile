# Build, test and sanitizer targets.
#
#   make              build the monitor and the tunnel
#   make test         build and run the unit tests
#   make sanitize     run the same tests under AddressSanitizer and UBSan
#   make check        both of the above
#   make analyze      run cppcheck over the sources
#   make run          run the monitor (needs root; pass IFACE= to choose one)
#   make clean        remove the build directory and any captured CSVs
#
# Useful variables:
#   STRICT=1          turn warnings into errors (CI always sets this)
#   CC=clang          build with the other compiler
#   LEAK_CHECK=1      also report leaks; see the note further down
#
# Each binary is compiled from sources in one command rather than through
# per-file object rules. The whole program is under 2000 lines, so a full
# rebuild is faster than the bookkeeping needed to avoid one, and the sanitizer
# build gets its own binary for free instead of fighting over stale objects.

CC ?= gcc

# gnu11 rather than c11: the code uses AF_PACKET and the Linux headers, so it
# is not portable ISO C anyway, and gnu11 implies the feature macros glibc
# needs to expose the BSD names in struct tcphdr.
STD := -std=gnu11

WARNINGS := -Wall -Wextra -Wshadow -Wstrict-prototypes -Wpointer-arith -Wvla

# CI builds with STRICT=1, so a new warning fails the run instead of scrolling
# past in the log. Local builds stay warning-only, so work in progress still
# compiles and runs.
ifeq ($(STRICT),1)
WARNINGS += -Werror
endif

OPT ?= -O2
CPPFLAGS += -Isrc -Itests

# -fsanitize=address catches reads past the end of a packet buffer;
# -fsanitize=undefined catches the misaligned loads and shifts a hand-written
# parser invites. Both need frame pointers and -g to say where the problem is.
SANITIZE := -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1

# The sanitizer build is pinned to gcc rather than following CC.
#
# clang is still worth building with -- it is the second compiler the warnings
# are checked against -- but LLVM 14's AddressSanitizer cannot reliably place
# its shadow memory on a kernel that randomises mmap with 32 bits of entropy,
# which is the default on 6.x. The binary then segfaults at random, roughly one
# run in three, with every test having already passed. The usual workarounds
# (lowering vm.mmap_rnd_bits, or setarch -R) both need privileges a container
# does not have, and a test suite that fails a third of the time for reasons
# outside the code is worse than no second sanitizer. gcc's runtime does not
# have the problem.
SANITIZE_CC ?= gcc

# Leak checking is opt-in, and defaults off because of where this usually runs.
#
# LeakSanitizer suspends the process with ptrace so it can walk the heap. A
# container does not get CAP_SYS_PTRACE by default, and instead of failing,
# LSan's stop-the-world spins in the kernel and never returns -- the suite
# reports every test passing and then hangs forever. Since the container is the
# normal way to run this on a non-Linux machine, the default has to be the one
# that terminates.
#
# CI runs the sanitizers directly on the runner rather than in a container, so
# it passes LEAK_CHECK=1 and does get the leak report.
LEAK_CHECK ?= 0

BUILD := build

# The classifier, the accounting and the file writing: everything the tests
# link against. main.c is left out because it opens a socket.
LIB_SOURCES := src/packet.c src/stats.c src/csv.c

MONITOR_SOURCES := $(LIB_SOURCES) src/main.c
TUNNEL_SOURCES := tunnel/tunnel.c tunnel/traffic_tunnel.c
TEST_SOURCES := $(LIB_SOURCES) \
	tests/harness.c \
	tests/frames.c \
	tests/test_packet.c \
	tests/test_stats.c \
	tests/test_csv.c \
	tests/main.c

IFACE ?= tun0

.PHONY: all monitor tunnel test sanitize check analyze run clean

all: monitor tunnel

monitor: $(BUILD)/monitor
tunnel: $(BUILD)/traffic_tunnel

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/monitor: $(MONITOR_SOURCES) $(wildcard src/*.h) | $(BUILD)
	$(CC) $(STD) $(WARNINGS) $(OPT) $(CPPFLAGS) $(MONITOR_SOURCES) -o $@

$(BUILD)/traffic_tunnel: $(TUNNEL_SOURCES) tunnel/tunnel.h | $(BUILD)
	$(CC) $(STD) $(WARNINGS) $(OPT) -Itunnel $(TUNNEL_SOURCES) -o $@

$(BUILD)/tests: $(TEST_SOURCES) $(wildcard src/*.h) $(wildcard tests/*.h) | $(BUILD)
	$(CC) $(STD) $(WARNINGS) $(OPT) $(CPPFLAGS) $(TEST_SOURCES) -o $@

$(BUILD)/tests-sanitize: $(TEST_SOURCES) $(wildcard src/*.h) $(wildcard tests/*.h) | $(BUILD)
	$(SANITIZE_CC) $(STD) $(WARNINGS) $(SANITIZE) $(CPPFLAGS) $(TEST_SOURCES) -o $@

test: $(BUILD)/tests
	./$(BUILD)/tests

# halt_on_error makes the run stop at the first sanitizer report instead of
# continuing on undefined behaviour and reporting something misleading later.
sanitize: $(BUILD)/tests-sanitize
	ASAN_OPTIONS=detect_leaks=$(LEAK_CHECK) \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		./$(BUILD)/tests-sanitize

check: test sanitize

# cppcheck reads the code without running it, so it reaches paths the tests do
# not: a buffer indexed with a value it cannot prove is in range, a return value
# nobody checks. --error-exitcode is what makes it a gate rather than a report.
# `missingIncludeSystem` is suppressed because cppcheck does not have the glibc
# and Linux headers and would otherwise report one every time.
analyze:
	cppcheck --enable=warning,performance,portability \
		--error-exitcode=1 \
		--inline-suppr \
		--std=c11 \
		--quiet \
		--suppress=missingIncludeSystem \
		-Isrc -Itests -Itunnel \
		src tests tunnel

# AF_PACKET needs root or CAP_NET_RAW.
run: $(BUILD)/monitor
	sudo ./$(BUILD)/monitor $(IFACE)

clean:
	rm -rf $(BUILD)
	rm -f network_layer.csv transport_layer.csv application_layer.csv
