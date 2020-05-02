CC= gcc
CFLAGS= -g #-DDEBUG
INCLUDES= -I. -I/usr/local/include/pcap/
LIBS= -L/usr/local/lib -lpcap
LIBS= /usr/lib/x86_64-linux-gnu/libpcap.a

OBJS= buffer.o capture.o tcp_connection.o
EXEC= minisniff-synattk

all: buffer.o capture.o tcp_connection.o main.c Makefile
	$(CC) $(CFLAGS) $(INCLUDES) main.c $(OBJS) $(LIBS) -o $(EXEC)

buffer.o: buffer.h buffer.c Makefile
	$(CC) $(CFLAGS) $(INCLUDES) -c buffer.c

capture.o: capture.c capture.h Makefile
	$(CC) $(CFLAGS) $(INCLUDES) -c capture.c

tcp_connection.o: tcp_connection.c tcp_connection.h Makefile
	$(CC) $(CFLAGS) $(INCLUDES) -c tcp_connection.c	
clean:
	rm -rf *.o *~ $(EXEC) core
