CC=gcc
CFLAGS=-g -Wall
CCLIBS=-lpthread
BINS=udpflood

all: $(BINS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $^ $(CCLIBS)

clean:
	rm -rf *.dSYM $(BINS)
