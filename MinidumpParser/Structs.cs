using System;


namespace MinidumpParser
{
    internal class Structs
    {
        public struct MinidumpHeader
        {
            public uint Signature;
            public ushort Version;
            public ushort ImplementationVersion;
            public ushort NumberOfStreams;
            public uint StreamDirectoryRva;
            public uint CheckSum;
            public IntPtr TimeDateStamp;
            // public ushort Reserved;
            // public ushort Flags;
        }

        public struct MinidumpStreamDirectoryEntry
        {
            public uint StreamType;
            public uint Size;
            public uint Location;
        }

        public struct SystemInfoStream
        {
            public ushort ProcessorArchitecture;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
            public byte NumberOfProcessors;
            public byte ProductType;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            public uint uint_unknown1;
            public uint uint_unknown2;
            public IntPtr ProcessorFeatures;
            public IntPtr ProcessorFeatures2;
            public uint uint_unknown3;
            public ushort ushort_unknown4;
            public byte byte_unknown5;
        }

        public struct ThreadListStream
        {
            public uint NumberOfThreads;
            public ThreadInfo[] Threads;
        }

        public struct ThreadInfo
        {
            public uint ThreadId;
            public uint SuspendCount;
            public uint PriorityClass;
            public uint Priority;
            public IntPtr Teb;
            public uint u1;
            public uint u2;
            public uint u3;
            public uint u4;
            public uint u5;
            public uint u6;
        }

        public struct ThreadInfoStream
        {
            public uint u1;
            public uint u2;
            public uint NumberOfThreads;
            public ThreadInfoStream_Element[] Threads;
        }

        public struct ThreadInfoStream_Element
        {
            public IntPtr ThreadId;
            public uint Dump;
            public uint ExitStatus;
            public IntPtr CreateTime;
            public IntPtr ExitTime;
            public IntPtr KernelTime;
            public IntPtr UserTime;
            public IntPtr StartAddress;
            public IntPtr Affinity;
        }

        public struct ModuleListStream
        {
            public uint NumberOfModules;
            public ModuleInfo[] Modules;
        }

        public struct ModuleInfo
        {
            public IntPtr BaseAddress;
            public uint Size;
            public uint u1;
            public uint Timestamp;
            public uint PointerName;
            public IntPtr u2;
            public IntPtr u3;
            public IntPtr u4;
            public IntPtr u5;
            public IntPtr u6;
            public IntPtr u7;
            public IntPtr u8;
            public IntPtr u9;
            public IntPtr u10;
            public IntPtr u11;
            public uint u12;
        }

        public struct MemoryInfoListStream
        {
            public uint u1;
            public uint u2;
            public ulong NumberOfEntries;
            public MemoryInfo[] MemoryInfoEntries;
        }

        public struct MemoryInfo
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public IntPtr AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public uint u1;
        }


        public struct Memory64ListStream
        {
            public ulong NumberOfEntries; 
            public uint u1;
            public Memory64Info[] MemoryInfoEntries;
        }

        public struct Memory64Info
        {
            public IntPtr Address;
            public IntPtr Size;
        }


        public struct UnloadedModuleListStream
        {
            public uint u1;
            public uint u2;
            public uint NumberOfModules;
        }


        public struct UnloadedModuleInfo
        {
            public IntPtr BaseAddress;
            public uint Size;
            public uint u1;
            public uint u2;
            public uint PointerName;
        }


        public struct MiscInfoStream
        {
            public uint MiscInfoStreamSize;
            public uint Flags;
            public uint ProcessId;
            public uint ProcessCreateTime;
            public uint ProcessUserTime;
            public uint ProcessKernelTime;
            public uint ProcessorMaxMhz;
            public uint ProcessorCurrentMhz;
            public uint ProcessorMhzLimit;
            public uint ProcessorMaxIdleState;
            public uint ProcessorCurrentIdleState;
            public uint ProcessIntegrityLevel;
            public uint ProcessExecuteFlags;
            public uint ProtectedProcess;
            public uint TimeZoneId;
            public uint TimeZoneBias;
            // public byte[] rest;
        }
    }
}