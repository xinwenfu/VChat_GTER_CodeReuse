#! /bin/bash

for i in $(objdump -d shellcode.o -M intel | grep "^ " | cut -f2); do 
	echo -n '\x'$i;
done;
echo