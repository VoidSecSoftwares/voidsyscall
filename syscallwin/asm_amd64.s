//go:build windows

#include "textflag.h"

// func Syscall(funcId uint32, arg1, arg2, arg3, arg4, arg5, arg6, arg7 uintptr) (uintptr, uintptr)
// Windows x64 convention: RCX=arg1, RDX=arg2, R8=arg3, R9=arg4, stack=arg5+,
// R10 = original RCX, EAX = syscall number.
TEXT ·Syscall(SB), NOSPLIT, $0-80
	MOVL funcId+0(FP), AX
	MOVQ arg1+8(FP), CX
	MOVQ arg2+16(FP), DX
	MOVQ arg3+24(FP), R8
	MOVQ arg4+32(FP), R9
	SUBQ $0x30, SP
	MOVQ arg5+40(FP), BX
	MOVQ BX, 0x28(SP)
	MOVQ arg6+48(FP), BX
	MOVQ BX, 0x30(SP)
	MOVQ arg7+56(FP), BX
	MOVQ BX, 0x38(SP)
	MOVQ CX, R10
	SYSCALL
	ADDQ $0x30, SP
	MOVQ AX, ret1+64(FP)
	MOVQ DX, ret2+72(FP)
	RET

// func Syscall9(funcId uint32, arg1..arg9 uintptr) (uintptr, uintptr)
// 9-argument variant for win32k-backed functions (NtGdiBitBlt etc).
// Kernel reads arg5+ from [RSP+0x28..] at SYSCALL time, so the stack frame
// must reserve the five spill slots below the call-site RSP.
TEXT ·Syscall9(SB), NOSPLIT, $0-88
	MOVL funcId+0(FP), AX
	MOVQ arg1+8(FP), CX
	MOVQ arg2+16(FP), DX
	MOVQ arg3+24(FP), R8
	MOVQ arg4+32(FP), R9
	SUBQ $0x50, SP
	MOVQ arg5+40(FP), BX
	MOVQ BX, 0x28(SP)
	MOVQ arg6+48(FP), BX
	MOVQ BX, 0x30(SP)
	MOVQ arg7+56(FP), BX
	MOVQ BX, 0x38(SP)
	MOVQ arg8+64(FP), BX
	MOVQ BX, 0x40(SP)
	MOVQ arg9+72(FP), BX
	MOVQ BX, 0x48(SP)
	MOVQ CX, R10
	SYSCALL
	ADDQ $0x50, SP
	MOVQ AX, ret1+80(FP)
	MOVQ DX, ret2+88(FP)
	RET

// func IndirectSyscall(stubAddr uintptr, funcId uint32, arg1, arg2, arg3, arg4, arg5, arg6 uintptr) (uintptr, uintptr)
// Jumps to a syscall;ret gadget inside ntdll. R10 = gadget address, EAX = SSN.
TEXT ·IndirectSyscall(SB), NOSPLIT, $0-80
	MOVQ stubAddr+0(FP), AX
	MOVQ AX, R10
	MOVL funcId+8(FP), AX
	MOVQ arg1+16(FP), CX
	MOVQ arg2+24(FP), DX
	MOVQ arg3+32(FP), R8
	MOVQ arg4+40(FP), R9
	SUBQ $0x38, SP
	MOVQ arg5+48(FP), BX
	MOVQ BX, 0x28(SP)
	MOVQ arg6+56(FP), BX
	MOVQ BX, 0x30(SP)
	MOVQ CX, R10
	CALL R10
	ADDQ $0x38, SP
	MOVQ AX, ret1+64(FP)
	MOVQ DX, ret2+72(FP)
	RET

TEXT ·GetCurrentProcHandle(SB), NOSPLIT, $0-8
	MOVQ $-1, AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·GetCurrentThreadId(SB), NOSPLIT, $0-8
	MOVQ 0x48(GS), AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·SetGSBase(SB), NOSPLIT, $0-8
	MOVQ newbase+0(FP), AX
	MOVQ AX, 0x30(GS)
	RET

TEXT ·ReadGSBase(SB), NOSPLIT, $0-8
	MOVQ 0x30(GS), AX
	MOVQ AX, ret+0(FP)
	RET

// func asm_cpuid(leaf uintptr, a *uintptr, b *uintptr, c *uintptr, d *uintptr)
TEXT ·asm_cpuid(SB), NOSPLIT, $0-40
	MOVQ leaf+0(FP), AX
	MOVQ d+32(FP), DI
	MOVQ 0(DI), DX
	CPUID
	MOVQ a+8(FP), DI
	MOVQ AX, 0(DI)
	MOVQ b+16(FP), DI
	MOVQ BX, 0(DI)
	MOVQ c+24(FP), DI
	MOVQ CX, 0(DI)
	MOVQ d+32(FP), DI
	MOVQ DX, 0(DI)
	RET

// func asm_rdtsc(lo *uint32, hi *uint32)
TEXT ·asm_rdtsc(SB), NOSPLIT, $0-16
	RDTSC
	MOVQ lo+0(FP), DI
	MOVL AX, 0(DI)
	MOVQ hi+8(FP), DI
	MOVL DX, 0(DI)
	RET
