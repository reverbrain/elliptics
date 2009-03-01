TARGET = libelliptics.so example

OBJS = log.o dnet.o rbtree.o node.o net.o trans.o history.o

CC = gcc
CFLAGS = -W -Wall -fPIC -g
LDFLAGS = -lcrypt -lssl -lpthread -L. -lelliptics

all: $(TARGET)

libelliptics.so: $(OBJS)
	$(CC) -fPIC -shared -rdynamic -Wl,-soname,$@ $^ -o $@

example: example.o libelliptics.so
	$(CC) $(LDFLAGS) $^ -o $@

$(OBJS): elliptics.h list.h Makefile packet.h interface.h core.h
rbtree.o: rbtree.h
net.o: packet.h
dnet.o: dnet.c
example.o: example.c Makefile packet.h interface.h core.h

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGET) *~ *.o
