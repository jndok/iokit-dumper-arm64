EXECUTABLE=iokit-dumper-arm64

all:
	clang main.c libdump/libdump.c parser/parser.c -o $(EXECUTABLE) -Llib/ -lmachoman -lcapstone.4 -Iinclude/
	install_name_tool $(EXECUTABLE) -change libmachoman.dylib lib/libmachoman.dylib 		# to be fixed
	install_name_tool $(EXECUTABLE) -change libcapstone.4.dylib lib/libcapstone.4.dylib		# to be fixed

clean:
	rm -rf $(EXECUTABLE)
