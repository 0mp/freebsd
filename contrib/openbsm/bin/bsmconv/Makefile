CC=clang
CFLAGS=-Wall -g
TARGETS=conv.out

.PHONY=clean all

all: $(TARGETS)

conv.out: bsmconv.o
	$(CC) -o $@ bsmconv.o

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	@rm *.o
	@rm $(TARGETS)
