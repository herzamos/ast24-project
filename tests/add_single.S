.section .text
.globl _start

_start:
    subq $16, %rsp
    movq $5, (%rsp)
    movq $10, 8(%rsp)

    movq (%rsp), %rax
    movq 8(%rsp), %rbx

    addq %rbx, %rax

    ret