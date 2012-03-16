CC=gcc
CFLAGS=-std=c99 -g -O2 -fPIC -Wall -DLDAP_DEPRECATED
LDFLAGS=-g -shared

all: pam_csc.so

pam_csc.so: pam_csc.o
	$(CC) -o $@ $(LDFLAGS) $< -lpam -lldap

clean:
	rm -f pam_csc.so pam_csc.o

install:
	cp pam_csc.so /lib/security/
