.PHONY: all clean

CPID ?= 0x7000

all:
	clang -Weverything -DCPID=$(CPID) eclipsa.c -o eclipsa -framework CoreFoundation -framework IOKit -O2

clean:
	$(RM) eclipsa