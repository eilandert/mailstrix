package oleparse

const (
	// Limit the size of the document
	MAX_SECTORS = 1024 * 1024

	sectorShiftV3   = 0x9
	sectorShiftV4   = 0xC
	miniSectorShift = 0x6

	// MAX_DECOMPRESSED bounds DecompressStream output. MS-OVBA copy tokens can
	// expand a 4096-byte chunk window repeatedly; a crafted input (capped at
	// 64MiB upstream) could otherwise amplify to tens of GiB and OOM the
	// process. Legit VBA dir/source streams are well under this. Defense-in-
	// depth on top of the yarad-side amplifier bounds.
	MAX_DECOMPRESSED = 32 * 1024 * 1024 // 32 MiB

	// MAX_TOTAL_DECOMPRESSED caps the CUMULATIVE decompressed VBA output across
	// all modules in one project. MAX_DECOMPRESSED bounds a single module, but a
	// crafted project with many modules could still sum to many GiB. The legacy
	// ExtractMacros/ExtractMacroBlobs compat APIs (which take no caller budget)
	// default to this so they are not unbounded; the *Limited variants let the
	// caller pass a tighter project budget. 128 MiB = 4× per-module, ample for
	// any legit project (real VBA totals are well under MAX_DECOMPRESSED).
	MAX_TOTAL_DECOMPRESSED = 128 * 1024 * 1024 // 128 MiB

	// MAX_MODULES caps the VBA project module count. The uint16 field is already
	// dir_stream-bounded, but a generous explicit cap stops a degenerate
	// high-count header from driving a long parse loop. Mirrors the yarad-side
	// maxModules intent (kept generous; real projects are <<4096 modules).
	MAX_MODULES = 4096
)
