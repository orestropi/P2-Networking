
all:wireviewNotFunctional.o
	g++ wireviewNotFunctional.cpp -o wireviewNotFunctional -lpcap

clean:
	$(RM) wireviewNotFunctional wireviewNotFunctional.o