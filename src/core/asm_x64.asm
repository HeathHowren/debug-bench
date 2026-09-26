; x64 helper stubs for the exception checks. These do only what cannot be
; written in MSVC C++ for x64 (there is no inline asm): set the trap flag, and
; emit a two-byte int 3. Each returns to its caller so the raised exception
; lands in the caller's __try block.

.code

; Set the single-step trap flag (EFLAGS.TF). The RET below executes with TF
; set, so the CPU single-steps the caller's next instruction and raises
; EXCEPTION_SINGLE_STEP there.
db_set_trap_flag PROC
    pushfq
    or      qword ptr [rsp], 100h
    popfq
    ret
db_set_trap_flag ENDP

; Execute the two-byte form of int 3 (0xCD 0x03). Some debuggers advance past
; only one byte and mishandle it.
db_int3_long PROC
    db      0CDh, 03h
    ret
db_int3_long ENDP

end
