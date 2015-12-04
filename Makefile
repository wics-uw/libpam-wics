CC=gcc
CFLAGS=-std=c99 -g -O2 -fPIC -Wall -DLDAP_DEPRECATED
LDFLAGS=-g -shared

all: pam_wics.so

pam_wics.so: pam_wics.o
	$(CC) -o $@ $(LDFLAGS) $< -lpam -lldap

clean:
	rm -f pam_wics.so pam_wics.o

install:
	cp pam_wics.so /lib/security/
