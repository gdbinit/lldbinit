CC = clang

.PHONY: all
all:
	$(CC) sysctlantidebug.c -o sysctlantidebug
	$(CC) ptrace.c -o ptrace

.PHONY: clean
clean:
	rm -f sysctlantidebug ptrace
