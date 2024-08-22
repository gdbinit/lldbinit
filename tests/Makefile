CC = clang

.PHONY: all
all:
	$(CC) sysctl.c -o sysctl
	$(CC) ptrace.c -o ptrace
	$(CC) taskget.c -o taskget
	$(CC) taskset.c -o taskset
	$(CC) -framework Foundation syscall.m -o syscall

.PHONY: clean
clean:
	rm -f sysctl ptrace taskget taskset syscall
