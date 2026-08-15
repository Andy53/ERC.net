# Changelog

Notable changes to ERC.Net. Dates are ISO 8601.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - unreleased

This release brings the library in line with the copy that was modernised inside
[ERC.Xdbg](https://github.com/Andy53/ERC.Xdbg). The two had drifted into
near-identical siblings, and the fixes made on one side had never reached the
other.

The major version reflects breaking API changes, listed under Changed.

### Fixed

#### The build

- **The library could not be built by anyone but its author.** `Fasm.NET`,
  `Reloaded.Assembler`, `Reloaded.Memory` and `Reloaded.Memory.Buffers` were
  referenced by `HintPath` into `..\..\ConsoleApp1\ConsoleApp1\bin\Debug`, a
  folder on one machine, and a file was excluded by absolute path under
  `C:\Users\Andy`. These are ordinary `PackageReference`s now, and a CI job builds
  from an empty package folder so the problem cannot come back unnoticed.
- The `.gitignore` ignored `*ERC.net.sln`. Git matches ignore rules case
  insensitively on Windows, so it also swallowed the solution file itself; it also
  contained an absolute path from another machine, and left `bin` and `obj`
  tracked - about 1,270 build artefacts were committed.
- Architecture was selected by commenting a line in and out of `ERC_Core.cs`
  before a build. It is read from pointer width at run time.
- `docfx.console` regenerated the documentation site on every build, so compiling
  the library was tied to producing its website.

#### Correctness

- ASLR and NXCompat were reported as `false` for every module on a 32-bit target.
  The flag derivation was written out twice; the 32-bit copy assigned inside a
  plain `else`, so each iteration past the interesting bit reset the flag.
- SafeSEH was reported as `false` for every module on every target. The load
  config directory was read into a local variable and discarded.
- PE headers were parsed by casting a pointer over a fixed buffer inside an
  `unsafe` block, with no signature checks and no bounds check on the file's own
  `e_lfanew` field, so a malformed header read outside the buffer. Parsing is now
  bounds-checked, and unsafe code is disabled repository-wide.
- `PtrRemover` threw an `OverflowException` on 64-bit targets and silently removed
  too many pointers on 32-bit ones.
- Enumerating threads aborted entirely if any single thread failed, which a thread
  exiting mid-enumeration reliably caused.
- Handles were never closed, so a long-running consumer leaked steadily.
- The ROP gadget filter used a forward loop with `RemoveAt`, skipping every second
  match. The same block was copy-pasted 130 times.
- The generated VirtualAlloc chain loaded EDI and ESI with the wrong values: a
  chain executes by returning into each address in turn, so a `pop esi` consumes
  the slot after itself, but this chain placed the value first.
- The 32-bit VirtualProtect chain called VirtualAlloc.
- Zeroing EBX or EDX emitted an eight-byte entry into a 32-bit chain, shifting
  every stack slot after it.
- An empty gadget list or an unresolved API threw rather than reporting.
- Ten gadget listing sections were always empty because they searched for an
  instruction the list cannot contain - `popEdi` looked for `pop edo`.

#### Text handling

- `Encoding.UTF7` and `Encoding.UTF32` were transposed in the search type
  numbering: `5` meant UTF-32 while callers were told it meant UTF-8.

### Changed

- **Breaking.** `ProcessInfo.SearchMemory`, `SearchModules` and
  `SearchAllMemoryPPR` are one method each, sharing a parameter order with
  `ptrsToExclude` optional and last. The `SearchMemory` overloads previously
  differed only in whether they applied that filter, and their second positional
  parameter meant `searchBytes` in one and `ptrsToExclude` in the other.
- **Breaking.** `RopChainGenerator32.GenerateRopChain32` and its 64-bit
  counterpart are one method each. A no-argument call did not previously compile:
  it was ambiguous between the two overloads, which is worth noting because the
  README used one.
- **Breaking.** `ErcCore` takes its configuration, logging, native API and output
  through interfaces, and its constructor no longer touches the filesystem.
- **Breaking.** `X64Lists.xorRsp` and `xorRbp` are gone. They were declared and
  scanned for, but nothing ever populated them.
- The disassembler is now [Iced](https://github.com/icedland/iced) rather than
  SharpDisasm, a udis86 port last released in 2017.
- The library multi-targets `net472` and `net8.0-windows`.
- `WebClient` has been replaced by `HttpClient` behind an interface.

### Added

- A test suite: 535 tests across both architectures and both target frameworks,
  including tests that launch a real process and inspect it.
- `build.ps1` and `test.ps1`, and a GitHub Actions workflow that builds and tests
  both architectures and both configurations.
- Nullable reference types throughout, with warnings as errors.

## [2.0.3] and earlier

See the commit history.
