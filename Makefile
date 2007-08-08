CC=gcc
CFLAGS=-g -O2 -fPIC -Wall
LDFLAGS=-g -shared -lpam -lldap

all: pam_csc.so

pam_csc.so: pam_csc.o
	$(CC) -o $@ $(LDFLAGS) $<

clean:
	rm -f pam_csc.so pam_csc.o

install:
	cp pam_csc.so /lib/security/
