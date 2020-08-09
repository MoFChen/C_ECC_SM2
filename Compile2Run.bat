@echo off
title=RunTest - C_ECC_SM2
gcc -o ecc ecc.c -O2 -m32
ecc.exe
echo.
pause