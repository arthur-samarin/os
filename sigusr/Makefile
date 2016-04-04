all: sigusr
%.o: %.c
	gcc -c $< -o $@
sigusr: sigusr.o
	gcc -s $^ -o $@
clean:
	rm -f *.o sigusr
