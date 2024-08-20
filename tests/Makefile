CC = clang

.PHONY: all
all:
	$(CC) sysctl.c -o sysctl
	$(CC) ptrace.c -o ptrace
	$(CC) taskget.c -o taskget
	$(CC) taskset.c -o taskset

.PHONY: clean
clean:
	rm -f sysctl ptrace taskget taskset
