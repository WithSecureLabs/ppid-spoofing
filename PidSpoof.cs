using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace dllinject
{
    public class PidSpoof
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo; public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000, Reserve = 0x2000, Decommit = 0x4000, Release = 0x8000, Reset = 0x80000, Physical = 0x400000, TopDown = 0x100000, WriteWatch = 0x200000, LargePages = 0x20000000
        }
        [Flags]

        public enum MemoryProtection
        {
            Execute = 0x10, ExecuteRead = 0x20, ExecuteReadWrite = 0x40, ExecuteWriteCopy = 0x80, NoAccess = 0x01, ReadOnly = 0x02, ReadWrite = 0x04, WriteCopy = 0x08, GuardModifierflag = 0x100, NoCacheModifierflag = 0x200, WriteCombineModifierflag = 0x400
        }
        public static class Kernel32
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenProcess(
             UInt32 processAccess,
             bool bInheritHandle,
             int processId);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool InitializeProcThreadAttributeList(
                  IntPtr lpAttributeList,
                  int dwAttributeCount,
                  int dwFlags,
                  ref IntPtr lpSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool UpdateProcThreadAttribute(
                IntPtr lpAttributeList,
                uint dwFlags,
                IntPtr Attribute,
                IntPtr lpValue,
                int cbSize,
                IntPtr lpPreviousValue,
                IntPtr lpReturnSize);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetProcessHeap();

            [DllImport("kernel32.dll", SetLastError = false)]
            public static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CreateProcess(
               string lpApplicationName,
               string lpCommandLine,
               ref SECURITY_ATTRIBUTES lpProcessAttributes,
               ref SECURITY_ATTRIBUTES lpThreadAttributes,
               bool bInheritHandles,
               uint dwCreationFlags,
               IntPtr lpEnvironment,
               string lpCurrentDirectory,
               [In] ref STARTUPINFOEX lpStartupInfo,
               out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr hHandle);

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            public static extern IntPtr VirtualAllocEx(
              IntPtr hProcess,
              IntPtr lpAddress,
              Int32 dwSize,
              uint flAllocationType,
              MemoryProtection flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(
              IntPtr hProcess,
              IntPtr lpBaseAddress,
              byte[] lpBuffer,
              Int32 nSize,
              out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtectEx(
              IntPtr hProcess,
              IntPtr lpAddress,
              Int32 dwSize,
              uint flNewProtect,
              out uint lpflOldProtect);

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateRemoteThread(
              IntPtr hProcess,
              IntPtr lpThreadAttributes,
              uint dwStackSize,
              IntPtr lpStartAddress,
              IntPtr lpParameter,
              uint dwCreationFlags,
              IntPtr lpThreadId);

            [DllImport("kernel32.dll")]
            public static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

            [DllImport("kernel32.dll")]
            public static extern uint GetCurrentProcessId();

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

            [DllImport("kernel32.dll")]
            public static extern uint GetLastError();

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            public static extern IntPtr GetProcAddress(
              IntPtr hModule,
              string procName);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(
              string lpModuleName);
        }

        public bool execute(uint ppid, string spawnto)
        {
            try
            {
                uint processSessionId = 0;
                uint parentSessionId = 0;


                uint currentPid = Kernel32.GetCurrentProcessId();
                bool result1 = Kernel32.ProcessIdToSessionId(currentPid, out processSessionId);
                bool result2 = Kernel32.ProcessIdToSessionId(ppid, out parentSessionId);

                STARTUPINFO sInfo = new STARTUPINFO();
                STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
                PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
                SECURITY_ATTRIBUTES secAttr = new SECURITY_ATTRIBUTES();
                secAttr.nLength = Marshal.SizeOf(secAttr);
                sInfo.cb = (uint)Marshal.SizeOf(sInfoEx);
                IntPtr lpSize = IntPtr.Zero;
                sInfoEx.StartupInfo = sInfo;
                IntPtr hSpoofParent = Kernel32.OpenProcess(0x1fffff, false, (int)ppid);
                IntPtr lpValue = IntPtr.Zero;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, hSpoofParent);

                string currentPath = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);

                result1 = Kernel32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);

                result1 = Kernel32.InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);
                result1 = Kernel32.UpdateProcThreadAttribute(sInfoEx.lpAttributeList, 0, (IntPtr)0x00020000, lpValue, IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

                return Kernel32.CreateProcess(spawnto, string.Empty, ref secAttr, ref secAttr, false, 0x00080010, IntPtr.Zero, currentPath, ref sInfoEx, out pInfo);

            }
            catch (Exception ex)
            {

                return false;
            }
            

            //incorrect injection to parent process
            //IntPtr loadLibAddress = Kernel32.GetProcAddress(Kernel32.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            //IntPtr lpBaseAddress = Kernel32.VirtualAllocEx(pInfo.hProcess, IntPtr.Zero, dllPath.Length, 0x00003000, MemoryProtection.ExecuteReadWrite);

            //IntPtr bytesLength = IntPtr.Zero;
            //result1 = Kernel32.WriteProcessMemory(pInfo.hProcess, lpBaseAddress, Encoding.ASCII.GetBytes(dllPath), dllPath.Length, out bytesLength);

            //IntPtr handle = Kernel32.CreateRemoteThread(pInfo.hProcess, IntPtr.Zero, 0, loadLibAddress, lpBaseAddress, 0, IntPtr.Zero);

        }
    }
}
