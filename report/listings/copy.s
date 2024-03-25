.L3:
    movq	(%rsi,%rax,8), %rcx    
    movq	%rcx, (%rdi,%rax,8)     
    addq	$1, %rax
    cmpq	%rax, %rdx
    jne	.L3