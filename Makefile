all:
	gcc *.m -o tpwn-bis -framework IOKit -framework Foundation -m32 -Wl,-pagezero_size,0 -O3
clean:
	rm -rf tpwn-bis
