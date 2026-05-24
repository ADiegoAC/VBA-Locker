VBA L°(k3r 🔐
Because standard VBA passwords are just suggestions.

🛑 The Problem with Standard VBA Protection
If you protect a VBA project using the built-in Excel dialog, you are just setting a flag in the vbaProject.bin file. Anyone with a hex editor can change DPB= to DPx= and bypass your password in 5 seconds. Worse, if you try to manually corrupt the project to hide the code, Excel detects the structural damage and deletes the entire VBA project upon recovery.

💡 The VBA L°(k3r Solution
VBA L°(k3r operates at the deepest structural level of the Excel file. Instead of faking a password, it implements the official MS-OVBA 2.4.3 / 2.4.4 cryptographic specifications to generate a genuine SHA-1 hash of your password and encrypts it using the OLE Data Encryption standard.

To prevent the dreaded "Removed Part: /xl/vbaProject.bin" error, VBA L°(k3r uses a Fixed-Size Byte Injection Algorithm. It locates the exact offsets of CMG, DPB, and GC in the binary stream and replaces them byte-by-byte, padding or truncating to ensure the file size remains identical.

The result? Macros run flawlessly, but the VBA Editor remains completely locked down and inaccessible.

⚙️ Key Features
MS-OVBA Cryptographic Engine: Implements standard DPB (Password Hash), CMG (Protection State), and GC (Visibility State) encryption.
Zero-Structure Corruption: Operates directly on byte arrays, never converting the binary to strings, preserving essential 0x00 CFB sector pointers.
Fixed-Size Byte Injection: Dynamically pads or truncates encrypted hashes to match the original stream size, preventing Excel from deleting the macros.
Project Hiding: Option to completely hide the VBA project from the Excel VBE tree.
WPF Dark-Mode Interface: Sleek, terminal-inspired UI with real-time hex-offset logging.
Drag & Drop: Drag your .xlsm / .xlsb files directly into the app.
Safe Workflow: Automatic timestamped backup creation before any binary modification occurs.
🚀 How to Use
Prerequisites: Windows OS with PowerShell 5.1+.
Download the latest VBA_L0ck3r.ps1 from the releases.
Right-click the file and select Run with PowerShell.
Drag and drop your Excel file into the window.
Enter and confirm your password.
Click ▶ PROTEGER PROJETO VBA.
Watch the real-time byte injection log.
🧠 Under the Hood (Technical Breakdown)
The core logic of VBA L°(k3r avoids the fatal flaw of string manipulation in CFB files:

# ❌ THE WRONG WAY (Breaks CFB sector sizes and 0x00 pointers) $rawStr  = $enc.GetString($raw) $rawStr  = $rawStr -replace "DPB=""$oldDpb""", "DPB=""$newDpb""" $newRaw  = $enc.GetBytes($rawStr)# ✅ THE VBA L°(k3r WAY (Preserves exact file structure and macro integrity) $newRaw  = $raw $search  = [System.Text.Encoding]::ASCII.GetBytes('DPB="') $startIdx = Find-ByteOffset $newRaw $search $paddedValue = Pad-Or-Truncate -newValue $newDpbBytes -oldLength $oldLength[Array]::Copy($paddedValue, 0, $newRaw, $startIdx, $oldLength)
By ensuring $newRaw.Length -eq $raw.Length, the OLE container remains structurally sound, and the Excel VBA compiler can still parse the macro modules, even though the security stream is locked.

📜 License
Copyright 2024 VBA L°(k3r Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

<div align="center">
<sub>Built with PowerShell, WPF, and byte-level obsession.</sub>
</div>
```
