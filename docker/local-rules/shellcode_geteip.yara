// Position-independent shellcode "GetEIP" prologue detection.
//
// Raw shellcode cannot reference absolute addresses, so it first recovers its own
// in-memory location (EIP). The two classic primitives are unmistakable byte
// sequences that have no benign analogue in a NON-PE mail attachment (a bare blob,
// a carved decode-pass payload, an OLE Package object):
//
//   - call/pop:  E8 00 00 00 00  (call $+5)  followed immediately by a pop reg
//     (58..5F) — the GuLoader / GuLoaderPrecursor staple, by far the most common.
//   - FPU trick: D9 EE (fldz) D9 74 24 F4 (fnstenv [esp-0Ch]) then a pop reg —
//     the Didier-Stevens fnstenv GetEIP, used to dodge call/pop signatures.
//
// FP-firewall: gated on `not uint16(0) == 0x5A4D`, i.e. the buffer is NOT a PE
// image at offset 0. A real PE legitimately carries such stubs inside packer/
// loader code, and PE shellcode is the pe module's domain; restricting to non-PE
// blobs targets the raw-shellcode mail vector with no benign collision. A minimum
// size keeps a coincidental short match from firing.

rule Shellcode_GetEIP : shellcode evasion heuristic suspicious
{
    meta:
        author      = "yarad"
        description = "Position-independent shellcode GetEIP prologue (call/pop E8 00000000 + pop, or Didier-Stevens fnstenv D9EE D97424F4 + pop) in a non-PE blob — a raw shellcode attachment or carved dropper payload"
        reference   = "https://www.virusbulletin.com/virusbulletin/2021/06/vb2021-paper-guloader-defeating-anti-analysis/"
        tier        = "suspicious"
        score       = "70"
    strings:
        // call $+5 ; pop reg  (E8 00 00 00 00 then pop EAX..EDI)
        $callpop = { E8 00 00 00 00 (58|59|5A|5B|5E|5F) }
        // fldz ; fnstenv [esp-0Ch] ; pop reg
        $fnstenv = { D9 EE D9 74 24 F4 (58|59|5A|5B|5E|5F) }
    condition:
        filesize >= 64 and not uint16(0) == 0x5A4D and any of them
}
