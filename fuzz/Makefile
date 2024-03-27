
# Makefile for oss-fuzz. Test locally using 'make test'.

CFLAGS += -g -Werror
CFLAGS += -I. -I../libqrexec
CFLAGS += -std=c11 -D_GNU_SOURCE -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

ifndef LIB_FUZZING_ENGINE
CC = clang
CXX = clang++
CFLAGS += -O1 -fno-omit-frame-pointer -gline-tables-only \
		-fsanitize=address \
		-fsanitize-address-use-after-scope -fsanitize=fuzzer
CXXFLAGS += -O1 -fno-omit-frame-pointer -gline-tables-only \
		-fsanitize=address \
		-fsanitize-address-use-after-scope -fsanitize=fuzzer
endif

_LIBQREXEC_OBJS = remote.o write-stdin.o ioall.o txrx-vchan.o buffer.o replace.o exec.o log.o unix-server.o toml.o process_io.o
LIBQREXEC_OBJS = $(patsubst %.o,libqrexec-%.o,$(_LIBQREXEC_OBJS))

FUZZERS = qubesrpc_parse_fuzzer qrexec_remote_fuzzer qrexec_daemon_fuzzer
SEEDS = $(patsubst %,%_seed_corpus.zip,$(FUZZERS))

.PHONY: all
all: $(FUZZERS) $(SEEDS)

$(SEEDS): gen-seed-corpus
	./gen-seed-corpus
	for fuzzer in $(FUZZERS); do \
		zip -q -r $${fuzzer}_seed_corpus.zip $${fuzzer}_seed_corpus; \
	done

test: $(patsubst %,test-%,$(FUZZERS))

test-%: % %_seed_corpus.zip
	rm -rf $<_seed_corpus
	unzip $<_seed_corpus.zip
	./$< $<_seed_corpus -runs=100000

qrexec_daemon_fuzzer: qrexec_daemon_fuzzer.o fuzz.o $(LIBQREXEC_OBJS) daemon-qrexec-daemon.o daemon-qrexec-daemon-common.o

%_fuzzer: %_fuzzer.o fuzz.o $(LIBQREXEC_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIB_FUZZING_ENGINE)

%_fuzzer.o: %_fuzzer.c
	$(CC) $(CFLAGS) -o $@ -c $^

fuzz.o: fuzz.c
	$(CC) $(CFLAGS) -o $@ -c $^

libqrexec-%.o: ../libqrexec/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

daemon-%.o: ../daemon/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

.PHONY: clean
clean:
	rm -f *.o *.zip *_fuzzer
	rm -rf *_fuzzer_seed_corpus
