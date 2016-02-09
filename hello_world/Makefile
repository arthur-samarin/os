all: hello
%.o: %.c
	gcc -c $< -o $@
hello: hello.o
	gcc -s $^ -o $@
clean:
	rm *.o
