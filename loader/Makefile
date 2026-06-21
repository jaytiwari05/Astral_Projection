CC_64=x86_64-w64-mingw32-gcc
NASM=nasm

all: bin/loader.x64.o

bin:
	mkdir bin

bin/loader.x64.o: bin
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -Wno-array-bounds -Os -s -fno-jump-tables -fno-optimize-sibling-calls -c src/loader.c   -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -Os -s -fno-jump-tables -fno-optimize-sibling-calls -c src/services.c -o bin/services.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -Os -s -fno-jump-tables -fno-optimize-sibling-calls -c src/pico_sleepmask.c     -o bin/pico.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -Os -s -fno-jump-tables -fno-optimize-sibling-calls -c src/hooks.c    -o bin/hooks.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -Os -s -fno-jump-tables -fno-optimize-sibling-calls -c src/spoof.c    -o bin/spoof.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -Os -s -fno-jump-tables -fno-optimize-sibling-calls -c src/mask.c     -o bin/mask.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -Os -s -fno-jump-tables -fno-optimize-sibling-calls -c src/cfg.c      -o bin/cfg.x64.o
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -Os -s -fno-jump-tables -fno-optimize-sibling-calls -c src/cleanup.c  -o bin/cleanup.x64.o

	$(NASM) src/draugr.asm -o bin/draugr.x64.bin

clean:
	rm -f bin/*
