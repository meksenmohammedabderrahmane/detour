# Contributing to Detour

Thank you for your interest in contributing to Detour!

## Development Philosophy
Detour is designed to be completely safe alongside kernel anti-cheat engines (such as Riot Vanguard, Easy Anti-Cheat, and BattlEye). All code must strictly uphold these guarantees:
1. Never inject DLLs or hook functions in external processes.
2. Never acquire handles with write, memory read, or suspension privileges to other processes.
3. Every networking decision or Windows API trick must be documented with a concise comment explaining the "why".
4. Code and documentation must never contain em dashes (U+2014); use standard hyphens, colons, or parentheses instead.

## Prerequisites
- Windows 11 (64-bit)
- Go 1.22 or newer
- Inno Setup 6 (for packaging the installer)
- Git for Windows

## Building from Source

Clone the repository and build the executables:

```powershell
# Build the CLI / Service executable
go build -trimpath -o _dist\detour.exe .\cmd\detour

# Build the GUI application without console window
go build -trimpath -ldflags="-H=windowsgui" -o _dist\detour-ui.exe .\cmd\detour-ui
```

To fetch the official signed Wintun driver binary:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1 -OutDir _dist
```

## Running Tests

Run the test suite before submitting pull requests:

```powershell
# Run unit tests and static analysis
go vet ./...
go test -v ./...

# Verify repository hygiene and privacy compliance
powershell -ExecutionPolicy Bypass -File scripts\check-repo.ps1
```

## Submitting Pull Requests
1. Fork the repository and create your feature branch: `git checkout -b feature/my-feature`.
2. Ensure all tests pass and code complies with `scripts/check-repo.ps1`.
3. Keep commit messages clear, informative, and free of em dashes.
4. Submit a Pull Request targeting the `main` branch.
