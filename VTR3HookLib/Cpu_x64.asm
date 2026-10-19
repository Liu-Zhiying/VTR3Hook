.code
_vmcall Proc
push rcx
push rdx
push r8
push r9
mov rax, [rcx]
mov rbx, [rdx]
mov rcx, [r8]
mov rdx, [r9]
vmcall
pop r9
mov [r9], rdx
pop r8
mov [r8], rcx
pop rdx
mov [rdx], rbx
pop rcx
mov [rcx], rax
ret
_vmcall Endp

_vmmcall Proc
push rcx
push rdx
push r8
push r9
mov rax, [rcx]
mov rbx, [rdx]
mov rcx, [r8]
mov rdx, [r9]
vmmcall
pop r9
mov [r9], rdx
pop r8
mov [r8], rcx
pop rdx
mov [rdx], rbx
pop rcx
mov [rcx], rax
ret
_vmmcall Endp
End