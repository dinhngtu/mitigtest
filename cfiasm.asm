extern cfgcaller: proc

_text segment

cfgneighbor qword 0,0,0,0
cfginvalidtarget proc
    ret
cfginvalidtarget endp

cfgtest proc
    sub rsp, 40
    lea rcx, qword ptr [cfgneighbor]
    add rcx, 32
    call cfgcaller
    add rsp, 40
    ret
cfgtest endp

cettest proc
    mov rax, l
    push rax
    ret
l:
    xor eax, eax
    ret
cettest endp

_text ends
end
