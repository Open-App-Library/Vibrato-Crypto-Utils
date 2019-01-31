all: compile run

compile: vcrypto-test

vcrypto-test: main.c vibrato-crypto.c
	gcc -o vcrypto-test main.c vibrato-crypto.c -lsodium -lm

run:
	./vcrypto-test
