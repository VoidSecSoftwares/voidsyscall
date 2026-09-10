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
