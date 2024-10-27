.code

EXTERN Ke_GetSyscallNumber: PROC

KeNtAllocateVirtualMemory PROC
	mov [rsp +8], rcx         
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0CBD3E774h        
	call Ke_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                     
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                 
	ret
KeNtAllocateVirtualMemory ENDP

KeNtQueryVirtualMemory PROC
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0C192D11Bh       
	call Ke_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                     
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    
	ret
KeNtQueryVirtualMemory ENDP

KeNtFreeVirtualMemory PROC
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0831F8B8Fh        
	call Ke_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                      
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    
	ret
KeNtFreeVirtualMemory ENDP

KeNtReadVirtualMemory PROC
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00B930717h        
	call Ke_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                      
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    
	ret
KeNtReadVirtualMemory ENDP

KeNtDelayExecution PROC
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0FC483E19h        
	call Ke_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                    
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    
	ret
KeNtDelayExecution ENDP

KeNtQueryInformationProcess PROC
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0E280F928h      
	call Ke_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                      
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                 
	ret
KeNtQueryInformationProcess ENDP

KeNtClose PROC
	mov [rsp +8], rcx         
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 000951D2Dh        
	call Ke_GetSyscallNumber             
	add rsp, 28h
	mov rcx, [rsp+8]                  
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    
	ret
KeNtClose ENDP

KeNtOpenProcess PROC
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0752F54BAh       
	call Ke_GetSyscallNumber            
	add rsp, 28h
	mov rcx, [rsp+8]                      
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                
	ret
KeNtOpenProcess ENDP

end