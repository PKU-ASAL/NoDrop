all: a.out attacker

a.out: test.c
	$(CC) test.c

attacker: attack.c
	$(CC) attack.c -o attacker

.PHONY: clean
clean:
	rm -f attacker a.out