CC		= gcc
CFLAGS	= -g -std=gnu99 -Wall -I. -fPIC
LD		= gcc
LDFLAGS = -L. -lcrypto -lz

TARGETS	= udpclient udpserver
SOURCES = client.o server.o

all: $(TARGETS)

%.o: %.c pg1lib.h
	@echo "Compiling $@"
	$(CC) $(CFLAGS) -c -o $@ $<

udpclient: client.o
	@echo "Linking $@"
	$(LD) -o $@ $^ $(LDFLAGS)

udpserver: server.o
	@echo "Linking $@"
	$(LD) -o $@ $^ $(LDFLAGS)

clean: 
	@echo "Removing objects"
	rm -f $(TARGETS) *.o *.a



