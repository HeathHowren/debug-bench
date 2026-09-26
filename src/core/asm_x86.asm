; x86 helper stubs for the exception checks, the 32-bit counterparts of
; asm_x64.asm. The leading underscores match the __cdecl decoration MSVC uses
; for extern "C" functions on x86.

.386
.model flat, c

.code

; Set the single-step trap flag (EFLAGS.TF). The RET runs with TF set, so the
; caller's next instruction single-steps and raises EXCEPTION_SINGLE_STEP.
db_set_trap_flag PROC
    pushfd
    or      dword ptr [esp], 100h
    popfd
    ret
db_set_trap_flag ENDP

; Execute the two-byte form of int 3 (0xCD 0x03).
db_int3_long PROC
    db      0CDh, 03h
    ret
db_int3_long ENDP

end
