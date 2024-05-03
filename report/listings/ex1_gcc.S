ex1(signed char*, signed char, unsigned long const*, unsigned int):
        mov     r9d, ecx
        mov     rax, rdi
        mov     r10, rdx
        mov     edi, esi
        test    r9d, r9d
        je      .L1
        mov     rcx, rax
        xor     r8d, r8d
.L4:
        mov     rsi, QWORD PTR [r10+r8*8]
        xor     eax, eax
.L3:
        bt      rsi, rax
        setc    dl
        neg     edx
        and     edx, edi
        add     BYTE PTR [rcx+rax], dl
        add     rax, 1
        cmp     rax, 64
        jne     .L3
        add     r8, 1
        add     rcx, 64
        cmp     r9, r8
        jne     .L4
.L1:
        ret