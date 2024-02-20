using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;


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
    public uint NumberOfThreads; // Número de hilos en el volcado
    public ThreadInfo[] Threads; // Array de información de cada hilo
}

public struct ThreadInfo
{
    public uint ThreadId; // Identificador único del hilo
    public uint SuspendCount; // Cantidad de veces que el hilo ha sido suspendido
    public uint PriorityClass; // Clase de prioridad del hilo
    public uint Priority; // Prioridad del hilo
    public IntPtr Teb; // Puntero al Bloque de Entrada de Hilo (Thread Environment Block)
    public uint unknown1;
    public uint unknown2;
    public uint unknown3;
    public uint unknown4;
    public uint unknown5;
    public uint unknown6;
}

public struct ThreadInfoStream
{
    public uint test1;
    public uint test2;
    public uint test3;
    public ThreadInfoStream_Element[] Threads;
}

public struct ThreadInfoStream_Element 
{
    public IntPtr ThreadId;
    public uint Dump;
    public uint ExitStatus;
    public IntPtr CreateTime;
    public IntPtr unknown3; // ExitTime
    public IntPtr unknown4; // KernelTime
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
    public ulong NumberOfEntries;  // Número de entradas en la lista de información de memoria
    public MemoryInfo[] MemoryInfoEntries;  // Array de información sobre cada región de memoria
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
    public ulong NumberOfEntries;  // Número de entradas en la lista de información de memoria
    public uint u1;
    public Memory64Info[] MemoryInfoEntries;  // Array de información sobre cada región de memoria
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


class test
{
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    private static T MarshalBytesTo<T>(byte[] bytes)
    {
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        handle.Free();
        return theStructure;
    }


    public static void ParseFunctionTableStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        
    }


    public static void ParseUnloadedModuleListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        fs.Seek(streamInfo.Location, SeekOrigin.Begin);
        byte[] uml_data = new byte[Marshal.SizeOf(typeof(UnloadedModuleListStream))];
        fs.Read(uml_data, 0, uml_data.Length);
        UnloadedModuleListStream uml_stream = MarshalBytesTo<UnloadedModuleListStream>(uml_data);
        int number_of_modules = (int)uml_stream.NumberOfModules;
        for (int i = 0; i < (int)number_of_modules; i++)
        {
            Console.WriteLine("[+]\tModule " + (i + 1));
            fs.Seek((streamInfo.Location + 12 + i * Marshal.SizeOf(typeof(UnloadedModuleInfo))), SeekOrigin.Begin);
            byte[] umi_data = new byte[Marshal.SizeOf(typeof(UnloadedModuleInfo))];
            fs.Read(umi_data, 0, umi_data.Length);
            UnloadedModuleInfo umi = MarshalBytesTo<UnloadedModuleInfo>(umi_data);
            Console.WriteLine("[+]\t   BaseAddress: \t0x" + umi.BaseAddress.ToString("X"));
            Console.WriteLine("[+]\t   Size: \t\t0x" + umi.Size.ToString("X"));
            Console.WriteLine("[+]\t   u1: \t\t\t0x" + umi.u1.ToString("X"));
            Console.WriteLine("[+]\t   u2: \t\t\t0x" + umi.u2.ToString("X"));
            Console.WriteLine("[+]\t   PointerName: \t0x" + umi.PointerName.ToString("X"));

            // Get unicode length from UNICODE_STRING struct
            fs.Seek(umi.PointerName, SeekOrigin.Begin);
            byte[] dll_name_length_data = new byte[2];
            fs.Read(dll_name_length_data, 0, dll_name_length_data.Length);
            int dll_name_length = BitConverter.ToInt16(dll_name_length_data, 0);
            Console.WriteLine("[+]\t   Name length:\t\t" + dll_name_length);
            // Get unicode buffer from UNICODE_STRING struct
            fs.Seek(umi.PointerName + 4, SeekOrigin.Begin);
            byte[] name_unicode_bytes = new byte[dll_name_length];
            fs.Read(name_unicode_bytes, 0, name_unicode_bytes.Length);
            string name_unicode = System.Text.Encoding.Unicode.GetString(name_unicode_bytes);
            Console.WriteLine("[+]\t   Name:\t\t" + name_unicode);
        }
    }


    public static void ParseCommentStreamW(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        fs.Seek(streamInfo.Location, SeekOrigin.Begin);
        byte[] csw_data = new byte[streamInfo.Size];
        fs.Read(csw_data, 0, csw_data.Length);
        string csw_stream = System.Text.Encoding.Unicode.GetString(csw_data);
        Console.WriteLine(csw_stream);
    }


    public static void ParseMemoryInfoListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        fs.Seek(streamInfo.Location, SeekOrigin.Begin);
        byte[] mil_data = new byte[16];
        fs.Read(mil_data, 0, mil_data.Length);
        MemoryInfoListStream mil_stream = MarshalBytesTo<MemoryInfoListStream>(mil_data);
        int number_of_entries = (int)mil_stream.NumberOfEntries;                
        Console.WriteLine("NumberOfEntries: \t" + number_of_entries);

        for (int i = 0; i < (int)number_of_entries; i++)
        {
            Console.WriteLine("[+]\tEntry " + (i + 1));
            fs.Seek((streamInfo.Location + 16 + i * Marshal.SizeOf(typeof(MemoryInfo))), SeekOrigin.Begin);
            // Memory64Info
            byte[] mi_data = new byte[Marshal.SizeOf(typeof(MemoryInfo))];
            fs.Read(mi_data, 0, mi_data.Length);
            MemoryInfo mi = MarshalBytesTo<MemoryInfo>(mi_data);
            Console.WriteLine("[+]\t   BaseAddress: \t0x" + mi.BaseAddress.ToString("X"));
            Console.WriteLine("[+]\t   AllocationBase: \t0x" + mi.AllocationBase.ToString("X"));
            Console.WriteLine("[+]\t   AllocationProtect: \t0x" + mi.AllocationProtect.ToString("X"));
            Console.WriteLine("[+]\t   RegionSize: \t\t0x" + mi.RegionSize.ToString("X"));
            Console.WriteLine("[+]\t   State: \t\t0x" + mi.State.ToString("X"));
            Console.WriteLine("[+]\t   Protect: \t\t0x" + mi.Protect.ToString("X"));
            Console.WriteLine("[+]\t   Type: \t\t0x" + mi.Type.ToString("X"));
            Console.WriteLine("[+]\t   u1: \t\t\t0x" + mi.u1.ToString("X"));

        }
        int last_address = (int)(streamInfo.Location + 16 + (int)number_of_entries * Marshal.SizeOf(typeof(MemoryInfo)) - 1);
        Console.WriteLine("[+] \tLast address: \t0x" + last_address.ToString("X"));
    }

    public static void ParseMemory64ListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        fs.Seek(streamInfo.Location, SeekOrigin.Begin);
        byte[] ml_data = new byte[12];
        fs.Read(ml_data, 0, ml_data.Length);
        Memory64ListStream ml_stream = MarshalBytesTo<Memory64ListStream>(ml_data);
        ulong number_of_entries = (ulong)ml_stream.NumberOfEntries;
        Console.WriteLine("NumberOfEntries: \t" + number_of_entries);
        Console.WriteLine("u1: \t\t" + ml_stream.u1.ToString("X"));

        for (int i = 0; i < (int)number_of_entries; i++)
        {
            Console.WriteLine("[+]\tEntry " + (i + 1));
            fs.Seek((streamInfo.Location + 16 + i * Marshal.SizeOf(typeof(Memory64Info))), SeekOrigin.Begin);
            // Memory64Info
            byte[] m64i_data = new byte[Marshal.SizeOf(typeof(Memory64Info))];
            fs.Read(m64i_data, 0, m64i_data.Length);
            Memory64Info m64i = MarshalBytesTo<Memory64Info>(m64i_data);
            Console.WriteLine("[+]\t   Address: \t0x" + m64i.Address.ToString("X"));
            Console.WriteLine("[+]\t   Size: \t0x" + m64i.Size.ToString("X"));
        }
        int last_address = (int)(streamInfo.Location + 16 + (int)number_of_entries * Marshal.SizeOf(typeof(Memory64Info)) - 1);
        Console.WriteLine("[+] \tLast address: \t0x" + last_address.ToString("X"));
    }


    public static void ParseModuleListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        int moduleinfo_size = 108;
        fs.Seek(streamInfo.Location, SeekOrigin.Begin);
        byte[] ml_data = new byte[4];
        fs.Read(ml_data, 0, ml_data.Length);
        ModuleListStream ml_stream = MarshalBytesTo<ModuleListStream>(ml_data);
        int number_of_modules = (int)ml_stream.NumberOfModules;
        Console.WriteLine("NumberOFModules: \t" + number_of_modules);

        for (int i = 0; i < number_of_modules; i++)
        {
            Console.WriteLine("[+]\tModule " + (i + 1));
            fs.Seek((streamInfo.Location + 4 + i * moduleinfo_size), SeekOrigin.Begin);
            byte[] mi_data = new byte[moduleinfo_size];
            fs.Read(mi_data, 0, mi_data.Length);
            ModuleInfo module_info = MarshalBytesTo<ModuleInfo>(mi_data);
            Console.WriteLine("[+]\t   BaseAddress:\t\t0x" + module_info.BaseAddress.ToString("X"));
            Console.WriteLine("[+]\t   Size:\t\t0x" + module_info.Size.ToString("X"));
            Console.WriteLine("[+]\t   u1:\t\t\t0x" + module_info.u1.ToString("X"));
            Console.WriteLine("[+]\t   Timestamp:\t\t0x" + module_info.Timestamp.ToString("X"));
            Console.WriteLine("[+]\t   PointerName:\t\t0x" + module_info.PointerName.ToString("X"));
            Console.WriteLine("[+]\t   u2:\t\t\t0x" + module_info.u2.ToString("X"));
            Console.WriteLine("[+]\t   u3:\t\t\t0x" + module_info.u3.ToString("X"));
            Console.WriteLine("[+]\t   u4:\t\t\t0x" + module_info.u4.ToString("X"));
            Console.WriteLine("[+]\t   u5:\t\t\t0x" + module_info.u5.ToString("X"));
            Console.WriteLine("[+]\t   u6:\t\t\t0x" + module_info.u6.ToString("X"));
            Console.WriteLine("[+]\t   u7:\t\t\t0x" + module_info.u7.ToString("X"));
            Console.WriteLine("[+]\t   u8:\t\t\t0x" + module_info.u8.ToString("X"));
            Console.WriteLine("[+]\t   u9:\t\t\t0x" + module_info.u9.ToString("X"));
            Console.WriteLine("[+]\t   u10:\t\t\t0x" + module_info.u10.ToString("X"));
            Console.WriteLine("[+]\t   u11:\t\t\t0x" + module_info.u11.ToString("X"));
            Console.WriteLine("[+]\t   u12:\t\t\t0x" + module_info.u12.ToString("X"));

            // Get unicode length from UNICODE_STRING struct
            fs.Seek(module_info.PointerName, SeekOrigin.Begin);
            byte[] dll_name_length_data = new byte[2];
            fs.Read(dll_name_length_data, 0, dll_name_length_data.Length);
            int dll_name_length = BitConverter.ToInt16(dll_name_length_data, 0);
            Console.WriteLine("[+]\t   Name length:\t\t" + dll_name_length);
            // Get unicode buffer from UNICODE_STRING struct
            fs.Seek(module_info.PointerName + 4, SeekOrigin.Begin);
            byte[] name_unicode_bytes = new byte[dll_name_length];
            fs.Read(name_unicode_bytes, 0, name_unicode_bytes.Length);
            string name_unicode = System.Text.Encoding.Unicode.GetString(name_unicode_bytes);
            Console.WriteLine("[+]\t   Name:\t\t" + name_unicode);

        }
    }


    public static void ParseThreadInfoListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        fs.Seek(streamInfo.Location, SeekOrigin.Begin);
        byte[] tis_data = new byte[12];
        fs.Read(tis_data, 0, tis_data.Length);
        ThreadInfoStream tis_stream = MarshalBytesTo<ThreadInfoStream>(tis_data);
        /*
        Console.WriteLine("test1: " + tis_stream.test1.ToString("X"));
        Console.WriteLine("test2: " + tis_stream.test2.ToString("X"));
        Console.WriteLine("test3: " + tis_stream.test3.ToString("X"));
        */
        //if (tis_stream.test1 == 12) {
        int number_threads = (int)tis_stream.test3;
        Console.WriteLine("[+]\tNumberOfThreads: \t" + number_threads);
        for (int i = 0; i < number_threads; i++)
        {
            Console.WriteLine("[+]\tThread " + (i + 1));
            fs.Seek((streamInfo.Location + 12 + i * Marshal.SizeOf(typeof(ThreadInfoStream_Element))), SeekOrigin.Begin);
            byte[] tis_element_data = new byte[Marshal.SizeOf(typeof(ThreadInfoStream_Element))];
            fs.Read(tis_element_data, 0, tis_element_data.Length);
            ThreadInfoStream_Element tis_element = MarshalBytesTo<ThreadInfoStream_Element>(tis_element_data);
            Console.WriteLine("[+]\t  ThreadId:\t\t0x" + tis_element.ThreadId.ToString("X"));
            Console.WriteLine("[+]\t  Dump:\t\t\t0x" + tis_element.Dump.ToString("X"));
            Console.WriteLine("[+]\t  ExitStatus:\t\t0x" + tis_element.ExitStatus.ToString("X"));
            Console.WriteLine("[+]\t  CreateTime:\t\t0x" + tis_element.CreateTime.ToString("X"));
            Console.WriteLine("[+]\t  ExitTime:\t\t0x" + tis_element.unknown3.ToString("X"));
            Console.WriteLine("[+]\t  KernelTime:\t\t0x" + tis_element.unknown4.ToString("X"));
            Console.WriteLine("[+]\t  UserTime:\t\t0x" + tis_element.UserTime.ToString("X"));
            Console.WriteLine("[+]\t  StartAddress:\t\t0x" + tis_element.StartAddress.ToString("X"));
            Console.WriteLine("[+]\t  Affinity:\t\t0x" + tis_element.Affinity.ToString("X"));
        }
        //}
    }


    public static void ParseThreadListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        fs.Seek(streamInfo.Location, SeekOrigin.Begin);
        // byte[] tl_data = new byte[Marshal.SizeOf(typeof(ThreadListStream))];
        // byte[] tl_data = new byte[streamInfo.Size];
        byte[] tl_data = new byte[4];
        fs.Read(tl_data, 0, tl_data.Length);
        ThreadListStream tl_stream = MarshalBytesTo<ThreadListStream>(tl_data);
        Console.WriteLine("[+] \tNumberOfThreads:\t" + tl_stream.NumberOfThreads);

        // Console.WriteLine(Marshal.SizeOf(typeof(ThreadInfo)));
        for (int i = 0; i < (int)tl_stream.NumberOfThreads; i++)
        {
            Console.WriteLine("[+]\tThread " + (i+1));
            fs.Seek((streamInfo.Location + 4 + i * Marshal.SizeOf(typeof(ThreadInfo))), SeekOrigin.Begin);
            tl_data = new byte[Marshal.SizeOf(typeof(ThreadInfo))];
            fs.Read(tl_data, 0, tl_data.Length);
            ThreadInfo t_info = MarshalBytesTo<ThreadInfo>(tl_data);
            Console.WriteLine("[+]\t  ThreadId:\t\t0x" + t_info.ThreadId.ToString("X"));
            Console.WriteLine("[+]\t  SuspendCount:\t\t" + t_info.SuspendCount);
            Console.WriteLine("[+]\t  PriorityClass:\t" + t_info.PriorityClass);
            Console.WriteLine("[+]\t  Priority:\t\t" + t_info.Priority);
            Console.WriteLine("[+]\t  Teb:\t\t\t0x" + t_info.Teb.ToString("X"));
            Console.WriteLine("[+]\t  unknown1:\t\t" + t_info.unknown1);
            Console.WriteLine("[+]\t  unknown2:\t\t" + t_info.unknown2);
            Console.WriteLine("[+]\t  unknown3:\t\t" + t_info.unknown3);
            Console.WriteLine("[+]\t  unknown4:\t\t" + t_info.unknown4);
            Console.WriteLine("[+]\t  unknown5:\t\t" + t_info.unknown5);
            Console.WriteLine("[+]\t  unknown6:\t\t" + t_info.unknown6);
        }
        // Console.WriteLine("Size: " + (4 + Marshal.SizeOf(typeof(ThreadInfo)) * 7));
    }


    public static void ParseSystemInfoStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
    {
        fs.Seek(streamInfo.Location, SeekOrigin.Begin);
        byte[] si_data = new byte[Marshal.SizeOf(typeof(SystemInfoStream))];
        fs.Read(si_data, 0, si_data.Length);
        SystemInfoStream si_stream = MarshalBytesTo<SystemInfoStream>(si_data);

        Console.WriteLine("[+] \tProcessorArchitecture:\t0x" + si_stream.ProcessorArchitecture.ToString("X"));
        Console.WriteLine("[+] \tProcessorLevel:\t\t0x" + si_stream.ProcessorLevel.ToString("X"));
        Console.WriteLine("[+] \tProcessorRevision:\t0x" + si_stream.ProcessorRevision.ToString("X"));
        Console.WriteLine("[+] \tNumberOfProcessors:\t0x" + si_stream.NumberOfProcessors.ToString("X"));
        Console.WriteLine("[+] \tProductType:\t\t0x" + si_stream.ProductType.ToString("X"));
        Console.WriteLine("[+] \tMajorVersion:\t\t0x" + si_stream.MajorVersion.ToString("X"));
        Console.WriteLine("[+] \tMinorVersion:\t\t0x" + si_stream.MinorVersion.ToString("X"));
        Console.WriteLine("[+] \tBuildNumber:\t\t0x" + si_stream.BuildNumber.ToString("X"));
        Console.WriteLine("[+] \tPlatformId:\t\t0x" + si_stream.PlatformId.ToString("X"));
        Console.WriteLine("[+] \tuint_unknown1:\t\t0x" + si_stream.uint_unknown1.ToString("X"));
        Console.WriteLine("[+] \tuint_unknown2:\t\t0x" + si_stream.uint_unknown2.ToString("X"));
        Console.WriteLine("[+] \tProcessorFeatures:\t0x" + si_stream.ProcessorFeatures.ToString("X"));
        Console.WriteLine("[+] \tProcessorFeatures2:\t0x" + si_stream.ProcessorFeatures2.ToString("X"));
        Console.WriteLine("[+] \tuint_unknown3:\t\t0x" + si_stream.uint_unknown3.ToString("X"));
        Console.WriteLine("[+] \tushort_unknown4:\t0x" + si_stream.ushort_unknown4.ToString("X"));
        Console.WriteLine("[+] \tbyte_unknown5:\t\t0x" + si_stream.byte_unknown5.ToString("X"));
    }


    public static void ParseHeader(MinidumpHeader header) {
        // Mostrar los valores de la cabecera
        Console.WriteLine("\n[+] Reading Header at 0x0");
        Console.WriteLine("[+]\t Signature: \t\t0x" + header.Signature.ToString("X"));
        Console.WriteLine("[+]\t Version: \t\t" + header.Version);
        Console.WriteLine("[+]\t ImplementationVersion:\t" + header.ImplementationVersion);
        Console.WriteLine("[+]\t NumberOfStreams: \t" + header.NumberOfStreams);
        Console.WriteLine("[+]\t StreamDirectoryRva: \t0x" + header.StreamDirectoryRva.ToString("X"));
        Console.WriteLine("[+]\t CheckSum: \t\t0x" + header.CheckSum.ToString("X"));
        Console.WriteLine("[+]\t TimeDateStamp: \t" + header.TimeDateStamp);
        //// Console.WriteLine("[+]\t Reserved: \t0x" + header.Reserved.ToString("X"));
        //// Console.WriteLine("[+]\t Flags: \t0x" + header.Flags.ToString("X"));
        //// Console.WriteLine("Size: \t" + Marshal.SizeOf(typeof(MinidumpHeader)));
    }


    static void Main(string[] args)
    {
        string minidumpFilePath = "C:\\Users\\ricardo\\Desktop\\Minidumps\\Dumb\\Dumb_procdump.dmp";
        // string minidumpFilePath = "C:\\Users\\ricardo\\Desktop\\Minidumps\\Dumb\\Dumb_processhacker.dmp";
        // string minidumpFilePath = "C:\\Users\\ricardo\\Desktop\\Minidumps\\Dumb\\Dumb_taskmanager.dmp";
        // string minidumpFilePath = "C:\\Users\\ricardo\\Desktop\\Minidumps\\lsass.exe.dmp";
        Console.WriteLine("[+] Minidump: \t" + minidumpFilePath);

        // Leer el archivo Minidump
        using (FileStream fs = new FileStream(minidumpFilePath, FileMode.Open, FileAccess.Read))
        {
            BinaryReader br = new BinaryReader(fs);
            // Leer la cabecera del Minidump
            MinidumpHeader header = ReadStruct<MinidumpHeader>(br);
            ParseHeader(header);

            // Mover el puntero al directorio de flujos
            fs.Seek((long)header.StreamDirectoryRva, SeekOrigin.Begin);

            // Crear una lista para almacenar la información de los flujos
            List<MinidumpStreamDirectoryEntry> streamInfoList = new List<MinidumpStreamDirectoryEntry>();

            // Leer el directorio de flujos
            for (int i = 0; i < header.NumberOfStreams; i++)
            {
                MinidumpStreamDirectoryEntry entry = ReadStruct<MinidumpStreamDirectoryEntry>(br);

                // Crear una estructura MinidumpStreamInfo y agregarla a la lista
                MinidumpStreamDirectoryEntry streamInfo = new MinidumpStreamDirectoryEntry
                {
                    StreamType = entry.StreamType,
                    Size = entry.Size,
                    Location = entry.Location
                };
                streamInfoList.Add(streamInfo);
            }

            // Ordenar la lista de flujos por dirección (Address)
            streamInfoList = streamInfoList.OrderBy(x => x.Location).ToList();

            // Mostrar la información de los flujos
            Console.WriteLine("\n[+] Reading Stream Directory content at 0x" + header.StreamDirectoryRva.ToString("X"));
            foreach (var streamInfo in streamInfoList)
            {
                if (streamInfo.Location != 0) {
                    string streamTypeName = GetStreamTypeName(streamInfo.StreamType);
                    Console.WriteLine("[+] \tAddress: 0x" + streamInfo.Location.ToString("X4") + " - 0x" + (streamInfo.Location + streamInfo.Size - 1).ToString("X4") + " \t Size: " + streamInfo.Size + " \t Stream Type: " + streamTypeName + " (" + streamInfo.StreamType + ")");
                }                
            }
            // Console.WriteLine("[+] Stream directory ends at: \t0x" + ((int)((int)header.StreamDirectoryRva + Marshal.SizeOf(typeof(MinidumpStreamDirectoryEntry)) * (int)header.NumberOfStreams)).ToString("X") );

            foreach (var streamInfo in streamInfoList)
            {
                if (streamInfo.Location != 0)
                {
                    string streamTypeName = GetStreamTypeName(streamInfo.StreamType);
                    /*
                    Console.WriteLine("[+] \tAddress: 0x" + streamInfo.Location.ToString("X4") + " - 0x" + (streamInfo.Location + streamInfo.Size - 1).ToString("X4") + " \t Size: " + streamInfo.Size + " \t Stream Type: " + streamTypeName + " (" + streamInfo.StreamType + ")");
                    if (streamTypeName == "SystemInfoStream")
                    {
                        Console.WriteLine("\n[+] Reading SystemInfoStream at 0x" + streamInfo.Location.ToString("X"));
                        ParseSystemInfoStream(fs, streamInfo);
                    }
                    else if (streamTypeName == "ThreadListStream")
                    {
                        Console.WriteLine("\n[+] Reading ThreadListStream at 0x" + streamInfo.Location.ToString("X"));
                        ParseThreadListStream(fs, streamInfo);
                    }
                    else if (streamTypeName == "ThreadInfoListStream")
                    {
                        Console.WriteLine("\n[+] Reading ThreadInfoListStream at 0x" + streamInfo.Location.ToString("X"));
                        ParseThreadInfoListStream(fs, streamInfo);
                    }
                    else if (streamTypeName == "UnloadedModuleListStream")
                    {
                        Console.WriteLine("\n[+] Reading UnloadedModuleListStream at 0x" + streamInfo.Location.ToString("X"));
                        ParseUnloadedModuleListStream(fs, streamInfo);
                    }
                    else if (streamTypeName == "ModuleListStream")
                    {
                        Console.WriteLine("\n[+] Reading ModuleListStream at 0x" + streamInfo.Location.ToString("X"));
                        ParseModuleListStream(fs, streamInfo);
                    }
                    else if (streamTypeName == "MemoryInfoListStream")
                    {
                        Console.WriteLine("\n[+] Reading MemoryInfoListStream at 0x" + streamInfo.Location.ToString("X"));
                        ParseMemoryInfoListStream(fs, streamInfo);
                    }
                    else if (streamTypeName == "Memory64ListStream")
                    {
                        Console.WriteLine("\n[+] Reading Memory64ListStream at 0x" + streamInfo.Location.ToString("X"));
                        ParseMemory64ListStream(fs, streamInfo);
                    }
                    else if (streamTypeName == "CommentStreamW")
                    {
                        Console.WriteLine("\n[+] Reading CommentStreamW at 0x" + streamInfo.Location.ToString("X"));
                        ParseCommentStreamW(fs, streamInfo);
                    }
                    */
                    if (streamTypeName == "MiscInfoStream")
                    { 
                    }
                    else if (streamTypeName == "FunctionTableStream")
                    {
                        // Console.WriteLine("\n[+] Reading FunctionTableStream at 0x" + streamInfo.Location.ToString("X"));
                        // ParseFunctionTableStream(fs, streamInfo);
                    }
                    else if (streamTypeName == "TokenStream")
                    {
                        // Console.WriteLine("\n[+] Reading TokenStream at 0x" + streamInfo.Location.ToString("X"));
                    }
                    else if (streamTypeName == "HandleOperationListStream")
                    {
                        // Console.WriteLine("\n[+] Reading HandleOperationListStream at 0x" + streamInfo.Location.ToString("X"));
                    }
                    else if (streamTypeName == "HandleDataStream")
                    {
                        Console.WriteLine("\n[+] Reading HandleDataStream at 0x" + streamInfo.Location.ToString("X"));
                    }
                    
                }
            }
        }
    }


    // Método genérico para leer una estructura desde un flujo binario
    static T ReadStruct<T>(BinaryReader br) where T : struct
    {
        byte[] buffer = br.ReadBytes(Marshal.SizeOf<T>());
        GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        T result = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
        handle.Free();
        return result;
    }


    // Obtener el nombre del tipo de flujo
    static string GetStreamTypeName(uint streamType)
    {
        switch (streamType)
        {
            case 0x0000:
                return "UnusedStream";
            case 0x0001:
                return "ReservedStream0";
            case 0x0002:
                return "ReservedStream1";
            case 0x0003:
                return "ThreadListStream";
            case 0x0004:
                return "ModuleListStream";
            case 0x0005:
                return "MemoryListStream";
            case 0x0006:
                return "ExceptionStream";
            case 0x0007:
                return "SystemInfoStream";
            case 0x0008:
                return "ThreadExListStream";
            case 0x0009:
                return "Memory64ListStream";
            case 0x000A:
                return "CommentStreamA";
            case 0x000B:
                return "CommentStreamW";
            case 0x000C:
                return "HandleDataStream";
            case 0x000D:
                return "FunctionTableStream";
            case 0x000E:
                return "UnloadedModuleListStream";
            case 0x000F:
                return "MiscInfoStream";
            case 0x0010:
                return "MemoryInfoListStream";
            case 0x0011:
                return "ThreadInfoListStream";
            case 0x0012:
                return "HandleOperationListStream";
            case 0x0013:
                return "TokenStream";
            case 0x0015:
                return "UNKNOWNThreadInfoListStream";
            case 0x0016:
                return "HandleOperationListStream";
            case 0x401F:
                return "JavaScriptDataStream";
            case 0x4020:
                return "SystemMemoryInfoStream";
            default:
                return "Unknown";
        }
    }
}
