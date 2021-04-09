.PHONY: all clean

all:
	xcrun -sdk macosx clang -mmacosx-version-min=10.9 -Weverything eclipsa.c -o eclipsa -framework CoreFoundation -framework IOKit -O2

clean:
	$(RM) eclipsa
