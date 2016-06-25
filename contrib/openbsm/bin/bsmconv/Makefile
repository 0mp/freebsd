CC=clang
CFLAGS=-Wall -g -pedantic -Werror -ansi
LIBS=-lsbuf
TARGETS=conv.out

.PHONY=clean all

all: $(TARGETS)

conv.out: bsmconv.o pjdlog.o
	$(CC) $(LIBS) -o $@ bsmconv.o

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	@rm -f *.o
	@rm -f $(TARGETS)
	@rm -f *.core
