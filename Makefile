NTESTS   := 2000      # number of random test cases to generate
NTHREADS := 4         # number of threads to use => degree of parallelization
NBYTES   := 128       # number of bytes to hash

CC       := gcc
CFLAGS   := -Os -Isrc -Wall -Wextra



all:
	@$(CC) $(CFLAGS) -o ./build/test_golden_sha1   ./src/sha1.c   ./tests/test_golden_sha1.c
	@$(CC) $(CFLAGS) -o ./build/test_random_sha1   ./src/sha1.c   ./tests/test_stdin_sha1.c
	@$(CC) $(CFLAGS) -o ./build/test_hmac_sha1     ./src/sha1.c   ./src/hmac.c ./tests/test_hmac_sha1.c


test:
	@echo
	@echo -------------------------------------------------------------------------------------------------------
	@./build/test_golden_sha1
	@#echo -------------------------------------------------------------------------------------------------------
	@python ./scripts/test_random_hash_sha1.py $(NTESTS) $(NTHREADS) $(NBYTES)
	@echo -------------------------------------------------------------------------------------------------------
	@python ./scripts/test_random_hmac_sha1.py $(NTESTS) $(NTHREADS) $(NBYTES)
	@echo -------------------------------------------------------------------------------------------------------
	@echo
	@echo Running `cat error_log.txt | wc -l` test cases from error log \(cases that failed during development\).
	@echo
	@bash error_log.txt
	@echo -------------------------------------------------------------------------------------------------------
	@echo


clean:
	@rm -f ./build/*
	@rm -f *.o
	@rm -f a.out


