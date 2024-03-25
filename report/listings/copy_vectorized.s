.L4:
    movdqu  (%rsi,%rax), %xmm0  
    movups  %xmm0, (%rdi,%rax)     
    addq    $16, %rax             
    cmpq	  %rcx, %rax
    jne	    .L4