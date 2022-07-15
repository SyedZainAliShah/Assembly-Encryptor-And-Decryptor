TITLE My First Program (test.asm)
INCLUDE Irvine32.inc

.data
temp dword ?
temp1 byte ?
keyselect dd ?
filehandle dd ?
file byte "data.txt",0
key1 byte "key1.txt",0
key2 byte "key2.txt",0
key3 byte "key3.txt",0
ekey byte "ekey.txt",0
file2 byte "encrypted.txt",0
file3 byte "decrypted.txt",0
prompt byte "Data encrypted and stored in encrypted.txt",0
prompt1 byte "Encrypting private key with public key and storing in ekey.txt",0
prompt2 byte "read encrypted private key and decrypt with public key",0
prompt3 byte "running decrypted key to decrypt message",0
prompt4 byte "decrypted message stored in decrypted.txt",0
prompt5 byte "Key1 used",0
prompt6 byte "Key2 used",0
prompt7 byte "Key3 used",0
buffer byte 300 dup(0),0
key byte 300 dup(0),0
publickey byte 2,-4,5,3,-5,12
privatekey byte 300 dup(?),0

.stack 4600

.code

Readf PROC
	push ebp
	mov ebp,esp

	mov edx,[ebp+8]
	call openinputfile
	mov filehandle,eax
	mov edx,[ebp+12]
	mov ecx,300
	call readfromfile
	cmp cx,1
	je exits
	mov edx,[ebp+12]
	exits:
	;call writestring
	mov eax,filehandle	
	call closefile
	pop ebp
	ret
Readf ENDP

encrypt1 proc
	push ebp
	mov ebp,esp
	
	mov esi,[ebp+8]
	mov ecx,[ebp+12]
	l1:
		mov eax,0
		mov al,[esi]
		cmp al,0
		je l2

		not al
		rol al,3
		add al,4
		xor al,1
		ror al,2
		stc
		rcr al,1

		l2:
		mov [esi],al
		inc esi
	loop l1

	pop ebp
	ret
encrypt1 endp

encrypt2 proc
	push ebp
	mov ebp,esp
	
	mov esi,[ebp+8]
	mov ecx,[ebp+12]
	l1:
		mov eax,0
		mov al,[esi]
		cmp al,0
		je l2

		stc                
		ror al, 3
		clc
		rol al, 2
		xor al, 2
		not al
		add al,3

		l2:
		mov [esi],al
		inc esi
	loop l1

	pop ebp
	ret
encrypt2 endp
encrypt3 proc
	push ebp
	mov ebp,esp
	
	mov esi,[ebp+8]
	mov ecx,[ebp+12]
	l1:
		mov eax,0
		mov al,[esi]
		cmp al,0
		je l2

		add al,8
		not al
		xor al,8
		sub al,8
		ror al,9
		rol al,1
		xor al,1
		neg al

		l2:
		mov [esi],al
		inc esi
	loop l1

	pop ebp
	ret
encrypt3 endp
		
encryptkey proc
	push ebp
	mov ebp,esp
	
	mov edi,offset publickey
	mov temp,0

	mov esi,[ebp+8]
	mov ecx,[ebp+12]
	l1:
		mov ebx,0
		mov bl,[edi]
		mov eax,0
		mov al,[esi]
		cmp al,0
		je l2
		cmp temp,6
		jl l4
			mov temp,0
			mov edi,offset publickey

		l4:

		cmp bl,0
		jl l3
			xchg cx,bx
			ror al,cl
			xchg cx,bx
			jmp l2
		l3:
			neg bl
			xchg cx,bx
			rol al,cl
			xchg cx,bx

		l2:
		inc edi
		inc temp
		mov [esi],al
		inc esi
	loop l1

	pop ebp
	ret
encryptkey endp
decryptkey proc
	push ebp
	mov ebp,esp
	
	mov edi,offset publickey
	mov temp,0

	mov esi,[ebp+8]
	mov ecx,[ebp+12]
	l1:
		mov ebx,0
		mov bl,[edi]
		mov eax,0
		mov al,[esi]
		cmp al,0
		je l2
		cmp temp,6
		jl l4
			mov temp,0
			mov edi,offset publickey

		l4:

		cmp bl,0
		jl l3
			xchg cx,bx
			rol al,cl
			xchg cx,bx
			jmp l2
		l3:
			neg bl
			xchg cx,bx
			ror al,cl
			xchg cx,bx

		l2:
		inc edi
		inc temp
		mov [esi],al
		inc esi
	loop l1

	pop ebp
	ret
decryptkey endp

pdecrypt proc uses esi
	push ebp
	mov ebp,esp

	mov esi,[ebp+12]
	mov edi,0
	mov al,[esi]
	l1:
		mov ebx,0
		cmp privatekey[edi],0
		jna exitt
		cmp al,0
		jna exitt
		cmp privatekey[edi],'1'
		jne a1
		cmp privatekey[edi+1],'#'
		je ins2
		
		a1:
		cmp privatekey[edi],'2'
		jne a2
		cmp privatekey[edi+1],'#'
		je ins1
		
		a2:
		cmp privatekey[edi],'3'
		jne a3
		cmp privatekey[edi+1],'#'
		je ins4
		
		a3:
		cmp privatekey[edi],'4'
		jne a4
		cmp privatekey[edi+1],'#'
		je ins3
		
		a4:
		cmp privatekey[edi],'5'
		jne a5
		cmp privatekey[edi+1],'#'
		je ins6
		
		a5:
		cmp privatekey[edi],'6'
		jne a6
		cmp privatekey[edi+1],'#'
		je ins5
		
		a6:
		cmp privatekey[edi],'7'
		jne a7
		cmp privatekey[edi+1],'#'
		je ins7
		
		a7:
		cmp privatekey[edi],'8'
		jne a8
		cmp privatekey[edi+1],'#'
		je ins8
		
		a8:
		cmp privatekey[edi],'9'
		jne a9
		cmp privatekey[edi+1],'#'
		je ins9
		
		a9:
		cmp privatekey[edi],'1'
		jne a10
		cmp privatekey[edi+1],'0'
		jne a10
		cmp privatekey[edi+2],'#'
		je ins10
		
		a10:
		cmp privatekey[edi],'1'
		jne a11
		cmp privatekey[edi+1],'1'
		jne a11
		cmp privatekey[edi+2],'#'
		je ins12
		
		a11:
		cmp privatekey[edi],'1'
		jne a12
		cmp privatekey[edi+1],'2'
		jne a12
		cmp privatekey[edi+2],'#'
		je ins11
		
		a12:
		jmp exitt
		
		ins1:
			add edi,2
			mov bl,privatekey[edi];
			sub bl,48
			xchg bl,cl
			rol al,cl
			xchg bl,cl
			add edi,2

			jmp l1
		ins2:
			add edi,2
			mov bl,privatekey[edi];
			sub bl,48
			xchg bl,cl
			ror al,cl
			xchg bl,cl
			add edi,2
			jmp l1
		ins3:
			add edi,2
			mov bl,privatekey[edi];
			sub bl,48
			xchg bl,cl
			rcl al,cl 
			xchg bl,cl
			add edi,2
			jmp l1
		ins4:
			add edi,2
			mov bl,privatekey[edi];
			sub bl,48
			xchg bl,cl
			rcr al,cl
			xchg bl,cl
			add edi,2
			jmp l1
		ins5:
			add edi,2
			stc
			jmp l1
		ins6:
			add edi,2
			clc

			jmp l1
		ins7:
			add edi,2
			not al
			jmp l1
		ins8:
			add edi,2
			neg al
			jmp l1
		ins9:
			add edi,2
			
			jmp l1
		ins10:
			add edi,3
			mov bl,privatekey[edi];
			sub bl,48
			xchg bl,cl
			xor al,cl
			xchg bl,cl
			add edi,2
			jmp l1
		ins11:
			add edi,3
			mov bl,privatekey[edi];
			sub bl,48
			xchg bl,cl
			add al,cl
			xchg bl,cl
			add edi,2
			jmp l1
		ins12:
			add edi,3
			mov bl,privatekey[edi];
			sub bl,48
			xchg bl,cl
			sub al,cl
			xchg bl,cl
			add edi,2
	jmp l1
	exitt:
	mov [esi],al
	pop ebp
	ret
pdecrypt endp
	

decrypt proc
	push ebp
	mov ebp,esp
	mov eax,0
	;mov al,buffer[20]
	;call writedec
	;call crlf
	mov esi,[ebp+8]
	mov ecx,[ebp+12]
	l1:
		push esi
		call pdecrypt
		add esp,4
		inc esi
	loop l1
	mov al,0
	mov [esi-1],al
	mov [esi],al
	;call crlf
	;call crlf
	;mov edx,offset buffer
	;call writestring
	pop ebp
	ret
decrypt endp


writef proc
	push ebp
	mov ebp,esp

	mov edx,[ebp+8]
	call createoutputfile
	mov filehandle,eax
	mov edx,[ebp+12]
	mov ecx,300
	call writetofile
	cmp cx,1
	je exits
	mov edx,[ebp+12]
	;call writestring
	exits:
	mov eax,filehandle
	call closefile
	pop ebp
	ret
writef endp

getinstruction proc
	push ebp
	mov ebp,esp

	mov ecx,[ebp+12]
	mov edi,[ebp+16]
	mov esi,[ebp+8]
	l1:
		mov eax,0
		mov al,[esi]
		cmp	al,10
		je l2
		cmp al,13
		je l2
		mov [edi],al
		inc esi
		inc edi
		mov al,[esi]
		cmp al,0
		je exitt
		loop l1
		l2:
			inc esi
	loop l1
	exitt:
	;mov edx,[ebp+16]
	;call writestring

	pop ebp
	ret
getinstruction endp

main PROC
	;reads data from file to be encrypted
	push offset buffer
	push offset file
	call readf
	add esp,8

	
	call randomize
	mov eax,4
	push lengthof buffer
	push offset buffer
	call randomrange
	cmp al,1
	jna l2
	cmp al,2
	jna l3
	jmp l1

	;encrypts the data in buffer using private key
	
	l1:
	call encrypt1
	mov keyselect,offset key1
	mov edx,offset prompt5
	call writestring
	call readchar
	call crlf
	jmp l
	l2:
	call encrypt2
	mov keyselect,offset key2
	mov edx,offset prompt6
	call writestring
	call readchar
	call crlf
	jmp l
	l3:
	call encrypt3
	mov keyselect,offset key3
	mov edx,offset prompt7
	call writestring
	call readchar
	call crlf
	l:
	add esp,8

	;stores encrypted data in new file encrypted.txt
	push offset buffer
	push offset file2
	call writef
	add esp,8
	
	;prompt 
	mov edx,offset prompt
	call writestring
	call readchar
	call crlf



	;reads key
	push offset key
	push keyselect
	call readf
	add esp,8


	;encrypts key
	push lengthof key
	push offset key
	call encryptkey
	add esp,8

	;stores encrypted  key in ekey.txt
	push offset key
	push offset ekey
	call writef
	add esp,8

	mov edx,offset prompt1
	call writestring
	call readchar
	call crlf

	;reads encrypted key from ekey
	push offset key
	push offset ekey
	call readf
	add esp,8

	;decrypts key using public key
	push lengthof key
	push offset key
	call decryptkey
	add esp,8

	;stores decrypted private key in ekey.txt
	push offset key
	push offset ekey
	call writef
	add esp,8

	mov edx,offset prompt2
	call writestring
	call readchar
	call crlf

	push offset privatekey
	push offset lengthof key
	push offset key
	call getinstruction
	add esp,12

	mov edx,offset prompt3
	call writestring
	call readchar
	call crlf

	;reads data from file to be encrypted
	push offset buffer
	push offset file2
	call readf
	add esp,8

	push lengthof buffer
	push offset buffer
	call decrypt
	add esp,8

	push offset buffer
	push offset file3
	call writef
	add esp,8

	mov edx,offset prompt4
	call writestring
	call readchar
	call crlf

	exit
main ENDP
END main
