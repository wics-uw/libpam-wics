CC=gcc
CFLAGS=-O2 -fPIC -Wall
LDFLAGS=-shared -lpam -lldap
LD=ld

all: pam_csc.so

pam_csc.so: pam_csc.o
	$(LD) -o $@ $(LDFLAGS) $<

clean:
	rm -f pam_csc.so pam_csc.o

install:
	cp pam_csc.so /lib/security/
