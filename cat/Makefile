all: cat
%.o: %.c
	gcc -c $< -o $@
cat: cat.o
	gcc -s $^ -o $@
clean:
	rm -f *.o cat
