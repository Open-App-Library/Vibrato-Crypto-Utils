all: compile run

compile: vcrypto-test

vcrypto-test: main.c vibrato-crypto.c
	gcc -g -o vcrypto-test main.c vibrato-crypto.c -lsodium -lm

run:
	./vcrypto-test
