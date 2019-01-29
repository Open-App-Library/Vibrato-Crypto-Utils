all: compile run

compile: vcrypto-test

vcrypto-test: main.c vibrato-crypto.c
	gcc main.c vibrato-crypto.c -lsodium -o vcrypto-test

run:
	./vcrypto-test
