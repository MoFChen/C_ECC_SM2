gcc -c ecc.c -o ecc.o -m32 -DBUILDING_DLL=1
gcc -shared ecc.o -o ecc.dll -static-libgcc -m32 -Wl,--kill-at
pause