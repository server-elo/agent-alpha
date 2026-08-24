CC = clang
CFLAGS = -std=c11 -Wall -Wextra -Werror=return-type -O2 -Iinclude -Ideps -pthread
LDFLAGS = -lcurl -pthread

SRC = src/main.c src/agent_loop.c src/llm.c src/tools.c src/browser.c src/telegram.c \
      src/provider.c src/ui.c src/evolve.c src/warden.c deps/cJSON.c deps/sds.c
OBJ = $(SRC:.c=.o)
TARGET = alpha

MCP_SRC = src/mcp_main.c src/tools.c src/browser.c src/provider.c src/ui.c deps/cJSON.c deps/sds.c
MCP_OBJ = $(MCP_SRC:.c=.o)
MCP_TARGET = alpha-mcp

.PHONY: all clean run telegram repl install test alpha-mcp

all: $(TARGET) $(MCP_TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

$(MCP_TARGET): $(MCP_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

src/%.o: src/%.c include/alpha.h src/ui.h
	$(CC) $(CFLAGS) -c -o $@ $<

deps/%.o: deps/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Tests include the module under test directly to reach its static functions,
# so they compile their own copy -- and must therefore depend on that .c file.
# Without it make considers a test up to date after the module changed, and
# silently re-runs a stale binary (observed: a deliberately broken source
# still reported all checks passing).
TEST_SRC = tests/test_tools.c tests/test_session.c tests/test_telegram.c tests/test_llm.c \
           tests/test_provider.c tests/test_portable.c tests/test_config.c \
           tests/test_browser.c tests/test_evolve.c
TEST_BIN = $(TEST_SRC:tests/%.c=tests/bin/%)
# Core suite plus whatever the evolution agent dropped into tests/custom/.
# run-tests referenced ALL_TEST_BINS without it ever being defined, so make
# ran ZERO test binaries and still printed ALL TESTS PASSED — and the evolve
# gate (which requires the "=== tests/bin/" marker) reverted every generation.
ALL_TEST_BINS = $(TEST_BIN) $(patsubst tests/custom/%.c,tests/bin/%,$(wildcard tests/custom/test_*.c))
TEST_DEPS = src/browser.o src/provider.o deps/cJSON.o deps/sds.o
# tests/test_util.h holds the assertion macros: a change there alters what every
# CHECK means, yet nothing listed it as a prerequisite, so make reported the
# suite "up to date" and re-ran binaries built against the old definitions.
TEST_HDRS = tests/test_util.h include/alpha.h

tests/bin/test_tools: tests/test_tools.c src/tools.c $(TEST_DEPS) $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -DALPHA_SHELL_TIMEOUT_MS=2000 -o $@ $< $(TEST_DEPS) $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

tests/bin/test_session: tests/test_session.c src/agent_loop.c src/llm.o src/tools.o $(TEST_DEPS) $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -o $@ $< src/llm.o src/tools.o $(TEST_DEPS) $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

# The voice timeout is 3 minutes in production; the suite must not wait that
# long to prove a wedged transcriber gets killed, so it is compiled short.
tests/bin/test_telegram: tests/test_telegram.c src/telegram.c src/agent_loop.o src/llm.o src/tools.o $(TEST_DEPS) $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -DALPHA_VOICE_TIMEOUT_MS=3000 -DALPHA_LOG_MAX_BYTES=65536 -o $@ $< src/agent_loop.o src/llm.o src/tools.o $(TEST_DEPS) $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

tests/bin/test_llm: tests/test_llm.c src/llm.c src/tools.o $(TEST_DEPS) $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -o $@ $< src/tools.o $(TEST_DEPS) $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

# Includes provider.c and ui.c directly, so it must not also link them.
tests/bin/test_provider: tests/test_provider.c src/provider.c src/ui.c src/ui.h $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -o $@ $< deps/cJSON.o deps/sds.o $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

# Compiles the /proc branch of tools.c on any host and runs it against a
# synthetic /proc, so the Linux path is exercised rather than merely parsed.
tests/bin/test_portable: tests/test_portable.c src/tools.c $(TEST_DEPS) $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -o $@ $< $(TEST_DEPS) $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

# main.c has a main(); ALPHA_NO_MAIN suppresses it so the config helpers can be
# reached directly instead of being retyped into the test (a copy would pass
# while the shipped code was broken).
tests/bin/test_config: tests/test_config.c src/main.c src/ui.o src/provider.o $(TEST_DEPS) $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -DALPHA_NO_MAIN -o $@ $< src/ui.o src/provider.o deps/cJSON.o deps/sds.o $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

# Includes browser.c directly to reach the static WebSocket client, so it must
# not also link src/browser.o.
tests/bin/test_browser: tests/test_browser.c src/browser.c $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -o $@ $< src/provider.o deps/cJSON.o deps/sds.o $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

# Includes evolve.c directly to reach the static gate/log helpers; agent_run
# comes from the linked objects. The gate tests run a real make against a
# throwaway fixture, never against this tree.
tests/bin/test_evolve: tests/test_evolve.c src/evolve.c src/agent_loop.o src/llm.o src/tools.o src/warden.o $(TEST_DEPS) $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -o $@ $< src/agent_loop.o src/llm.o src/tools.o src/warden.o $(TEST_DEPS) $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

# Dynamic Custom & Adversarial Red-Team Tests
# -Itests so custom tests can include test_util.h like the core suite does.
tests/bin/%: tests/custom/%.c $(TEST_DEPS) $(TEST_HDRS) | tests/bin
	$(CC) $(CFLAGS) -Itests -o $@ $< src/agent_loop.o src/llm.o src/tools.o src/warden.o $(TEST_DEPS) $(LDFLAGS)
	@codesign -s - -f $@ 2>/dev/null || true

tests/bin:
	mkdir -p tests/bin

test:
	@rm -rf tests/bin
	@rm -f $(TARGET) $(OBJ)
	@$(MAKE) --no-print-directory run-tests

.PHONY: run-tests
run-tests: $(TARGET) $(ALL_TEST_BINS)
	@fail=0; for t in $(ALL_TEST_BINS); do \
		echo "=== $$t ==="; ./$$t || fail=1; \
	done; \
	if [ $$fail -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "TESTS FAILED"; exit 1; fi

clean:
	rm -f $(OBJ) $(TARGET)
	rm -rf tests/bin

run: $(TARGET)
	./$(TARGET) $(ARGS)

telegram: $(TARGET)
	./scripts/alpha-telegram.sh start

repl: $(TARGET)
	./$(TARGET) --repl
