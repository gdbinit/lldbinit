CC = clang

.PHONY: all
all:
	$(CC) sysctlantidebug.c -o sysctlantidebug
	$(CC) ptrace.c -o ptrace
	$(CC) taskget.c -o taskget
	$(CC) taskset.c -o taskset

.PHONY: clean
clean:
	rm -f sysctlantidebug ptrace taskget taskset
