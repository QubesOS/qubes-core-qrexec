
# Makefile for oss-fuzz. Test locally using 'make test'.

CFLAGS += -g -Werror
CFLAGS += -I. -I../libqrexec
CFLAGS += -std=c11 -D_GNU_SOURCE -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

.PHONY: all
all: qubesrpc_parse_fuzzer qubesrpc_parse_fuzzer_seed_corpus.zip

.PHONY: test
test: test-compile
	rm -rf qubesrpc_parse_fuzzer_seed_corpus
	unzip qubesrpc_parse_fuzzer_seed_corpus.zip
	./qubesrpc_parse_fuzzer qubesrpc_parse_fuzzer_seed_corpus

.PHONY: test-compile
test-compile:
	$(MAKE) CC=clang CFLAGS='-O1 -fno-omit-frame-pointer -gline-tables-only \
		-fsanitize=address \
		-fsanitize-address-use-after-scope -fsanitize=fuzzer'


qubesrpc_parse_fuzzer_seed_corpus.zip: gen-seed-corpus
	./gen-seed-corpus
	rm -f qubesrpc_parse_fuzzer_seed_corpus.zip
	zip -q -r qubesrpc_parse_fuzzer_seed_corpus.zip qubesrpc_parse_fuzzer_seed_corpus

qubesrpc_parse_fuzzer: qubesrpc_parse_fuzzer.o libqrexec-exec.o libqrexec-log.o libqrexec-buffer.o libqrexec-ioall.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIB_FUZZING_ENGINE)

qubesrpc_parse_fuzzer.o: qubesrpc_parse_fuzzer.c
	$(CC) $(CFLAGS) -o $@ -c $^

libqrexec-%.o: ../libqrexec/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

.PHONY: clean
clean:
	rm *.o *.zip *_fuzzer *_fuzzer_seed_corpus
