#
# Build the SecurID api library.  (libsidapi)
#

CFLAGS = -c $(COPT) -DUNIX #-DSASL
OFILES = sidapi.o

.c.o :
	$(CC) $(CFLAGS) $<

all : libsidapi.a

libsidapi.a: $(OFILES)
	rm -f libsidapi.a
	ar cr libsidapi.a $(OFILES)
	ranlib libsidapi.a

clean :
	rm -f *.o libsidapi.a
 
install :
	echo "nothing to install"
