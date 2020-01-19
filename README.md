# RaRop
Proof-of-Concept Automatic ROP

## Write-up of the problem
The below text is used to give some insight in the thought process of solving the problem automatically. While this solution is far from perfect, it helped understanding the concept and gaining the experience with the radare2 framework.
### Initial Information
Detailing the radare2 steps taken for analyzing ret2win32.

* Analyzing the binary:
```sh
 ~/RaROP ▓▒░ rabin2 -I ret2win32                                                                  
arch     x86
baddr    0x8048000
binsz    6442
bintype  elf
bits     32
canary   false
class    ELF32
compiler GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609
crypto   false
endian   little
havecode true
intrp    /lib/ld-linux.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  Intel 80386
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
```
The important part of the above output is that the NX bit is set, thus not allowing to execute code directly from stack. This is often the indicator that the solution is to look into building a ROP epxloit.

* Start radare2 in debugging mode to gain a basic understanding of the inner workings of the program:
```sh
~/RaROP ▓▒░ r2 -d ret2win32                                                                      
Process with PID 3077 started...
= attach 3077 3077
bin.baddr 0x08048000
Using 0x8048000
asm.bits 32
glibc.fc_offset = 0x00148
 -- Jingle sploits, jingle sploits, ropchain all the way.
[0xf7fa5c70]>
```

* Set a breakpoint on main and continue execution:
```sh
 ~/RaROP ▓▒░ r2 -d ret2win32                                                                        
Process with PID 3077 started...
= attach 3077 3077
bin.baddr 0x08048000
Using 0x8048000
asm.bits 32
glibc.fc_offset = 0x00148
 -- Jingle sploits, jingle sploits, ropchain all the way.
[0xf7fa5c70]> db main
[0xf7fa5c70]> dc
hit breakpoint at: 804857b
[0x0804857b]>
```

* Analyze the binary and print the functions of the program:
```sh
[0x0804857b]> aaa
[Cannot analyze at 0x08048470g with sym. and entry0 (aa)
[x] Analyze all flags starting with sym. and entry0 (aa)
[Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[TOFIX: aaft can't run in debugger mode.ions (aaft)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x0804857b]> afl
0x08048480    1 33           entry0
0x08048440    1 6            sym.imp.__libc_start_main
0x080484c0    4 43           sym.deregister_tm_clones
0x080484f0    4 53           sym.register_tm_clones
0x08048530    3 30           entry.fini0
0x08048550    4 43   -> 40   entry.init0
0x080485f6    1 99           sym.pwnme
0x08048460    1 6            sym.imp.memset
0x08048420    1 6            sym.imp.puts
0x08048400    1 6            sym.imp.printf
0x08048410    1 6            sym.imp.fgets
0x08048659    1 41           sym.ret2win
0x08048430    1 6            sym.imp.system
0x080486f0    1 2            sym.__libc_csu_fini
0x080484b0    1 4            sym.__x86.get_pc_thunk.bx
0x080486f4    1 20           sym._fini
0x08048690    4 93           sym.__libc_csu_init
0x0804857b    1 123          main
0x08048450    1 6            sym.imp.setvbuf
0x080483c0    3 35           sym._init
[0x0804857b]>
```

* The function sym.pwnme gives the hint that we should look into this
```sh
[0x0804857b]> pd @ 0x080485f6
```
This function also holds the print statement and takes the input with ```fgets``` at ```0x0804864e``` the ```fgets``` function is responsible for reading the user input and storing it in memory, by overwriting certain values we can overwrite EIP with our own value.

### The problem
There is no call or routine present in the program that calls the function sym.ret2win which prints out the flag.
to get to the sym.ret2win function we will need to overwrite the buffer so that it returns to the address of ```sym.ret2win``` 
that is located at ```0x08048659```.

## Using the radare2 framework to automate the process
Normally we would assimilate the right information to construct our payload and return into the function that we 
want to return in to complete the challenge.

My take on these kind of binaries in particular, where no special input values are needed to validate the call to this function
is to write a simple script that is able to leverage the radare2 framework to attempt all the different addresses of the 
functions which can be extracted with the ```afl``` command.

## Automation
The script works as follows:
1. The script takes a buffer which is used to crash the program 
2. With the pwn library a unique pattern is created that is used to locate the offset of the crash 
3. The EIP value is extracted when the program crashes and correlated against the pwn pattern to locate the offset 
4. The addresses of the different functions in the program are being retrieved 
	- The functions starting with 'sym.imp.' are not used because these are system specific functions 
5. The brute force starts checking every function address, using this as a return value which is added to the pattern of garbage that is used to generate a crash 
6. To execute the program with this pattern the radare2 profile option is being used to store the pattern and use this pattern the moment the program asks for user input. This is done with the radare2 debug profile because normally the stdout would be redirected to that process, the profile ensures that this output is piped to the radare2 process of the user.
7. A search for the string 'flag' is being done on the output after executing the function, if it holds this value it will output the program's output.
