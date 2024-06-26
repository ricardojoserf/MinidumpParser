﻿using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static MinidumpParser.Structs;


namespace MinidumpParser
{
    internal class Program
    {
        public static void ParseMiscInfoStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
        {
            fs.Seek(streamInfo.Location, SeekOrigin.Begin);
            byte[] miscinfo_data = new byte[streamInfo.Size];
            fs.Read(miscinfo_data, 0, miscinfo_data.Length);
            MiscInfoStream miscinfo_stream = MarshalBytesTo<MiscInfoStream>(miscinfo_data);
            Console.WriteLine("[+]\tMiscInfoStreamSize: \t\t0x" + miscinfo_stream.MiscInfoStreamSize.ToString("X") + " (" + miscinfo_stream.MiscInfoStreamSize + ")");
            Console.WriteLine("[+]\tFlags: \t\t\t\t0x" + miscinfo_stream.Flags.ToString("X") + " (" + miscinfo_stream.Flags + ")");
            Console.WriteLine("[+]\tProcessId: \t\t\t0x" + miscinfo_stream.ProcessId.ToString("X") + " (" + miscinfo_stream.ProcessId + ")");
            Console.WriteLine("[+]\tProcessCreateTime: \t\t0x" + miscinfo_stream.ProcessCreateTime.ToString("X") + " (" + miscinfo_stream.ProcessCreateTime + ")");
            Console.WriteLine("[+]\tProcessUserTime: \t\t0x" + miscinfo_stream.ProcessUserTime.ToString("X"));
            Console.WriteLine("[+]\tProcessKernelTime: \t\t0x" + miscinfo_stream.ProcessKernelTime.ToString("X"));
            Console.WriteLine("[+]\tProcessorMaxMhz: \t\t0x" + miscinfo_stream.ProcessorMaxMhz.ToString("X"));
            Console.WriteLine("[+]\tProcessorCurrentMhz: \t\t0x" + miscinfo_stream.ProcessorCurrentMhz.ToString("X"));
            Console.WriteLine("[+]\tProcessorMhzLimit: \t\t0x" + miscinfo_stream.ProcessorMhzLimit.ToString("X"));
            Console.WriteLine("[+]\tProcessorMaxIdleState: \t\t0x" + miscinfo_stream.ProcessorMaxIdleState.ToString("X"));
            Console.WriteLine("[+]\tProcessorCurrentIdleState: \t0x" + miscinfo_stream.ProcessorCurrentIdleState.ToString("X"));
            Console.WriteLine("[+]\tProcessIntegrityLevel: \t\t0x" + miscinfo_stream.ProcessIntegrityLevel.ToString("X"));
            Console.WriteLine("[+]\tProcessExecuteFlags: \t\t0x" + miscinfo_stream.ProcessExecuteFlags.ToString("X"));
            Console.WriteLine("[+]\tProtectedProcess: \t\t0x" + miscinfo_stream.ProtectedProcess.ToString("X"));
            Console.WriteLine("[+]\tTimeZoneId: \t\t\t0x" + miscinfo_stream.TimeZoneId.ToString("X"));
            Console.WriteLine("[+]\tTimeZoneBias: \t\t\t0x" + miscinfo_stream.TimeZoneBias.ToString("X"));

            fs.Seek(streamInfo.Location + Marshal.SizeOf(typeof(MiscInfoStream)), SeekOrigin.Begin);
            byte[] unicode_data = new byte[streamInfo.Size - Marshal.SizeOf(typeof(MiscInfoStream))];
            fs.Read(unicode_data, 0, unicode_data.Length);
            string other_strings = GetCleanString(unicode_data);
            Console.WriteLine("[+]\tOther strings:\t\t\t" + other_strings);
        }


        public static void ParseUnloadedModuleListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
        {
            fs.Seek(streamInfo.Location, SeekOrigin.Begin);
            byte[] uml_data = new byte[Marshal.SizeOf(typeof(UnloadedModuleListStream))];
            fs.Read(uml_data, 0, uml_data.Length);
            UnloadedModuleListStream uml_stream = MarshalBytesTo<UnloadedModuleListStream>(uml_data);
            int number_of_modules = (int)uml_stream.NumberOfModules;
            Console.WriteLine("[+] Field 1: \t\t0x" + uml_stream.u1.ToString("X"));
            Console.WriteLine("[+] Field 2: \t\t0x" + uml_stream.u2.ToString("X"));
            Console.WriteLine("[+] NumberOfModules: \t" + number_of_modules);
            Console.WriteLine(String.Format("|{0,15}|{1,20}|{2,15}|{3,15}|{4,15}|{5,40}|", centeredString("Module", 15), centeredString("BaseAddress", 20), centeredString("Size", 15), centeredString("u1", 15), centeredString("u2", 15), centeredString("Name", 40)));
            for (int i = 0; i < number_of_modules; i++)
            {
                fs.Seek((streamInfo.Location + 12 + i * Marshal.SizeOf(typeof(UnloadedModuleInfo))), SeekOrigin.Begin);
                byte[] umi_data = new byte[Marshal.SizeOf(typeof(UnloadedModuleInfo))];
                fs.Read(umi_data, 0, umi_data.Length);
                UnloadedModuleInfo umi = MarshalBytesTo<UnloadedModuleInfo>(umi_data);
                                
                // Get unicode length from UNICODE_STRING struct
                fs.Seek(umi.PointerName, SeekOrigin.Begin);
                byte[] dll_name_length_data = new byte[2];
                fs.Read(dll_name_length_data, 0, dll_name_length_data.Length);
                int dll_name_length = BitConverter.ToInt16(dll_name_length_data, 0);
                
                // Get unicode buffer from UNICODE_STRING struct
                fs.Seek(umi.PointerName + 4, SeekOrigin.Begin);
                byte[] name_unicode_bytes = new byte[dll_name_length];
                fs.Read(name_unicode_bytes, 0, name_unicode_bytes.Length);
                string name_unicode = Encoding.Unicode.GetString(name_unicode_bytes);

                // Console.WriteLine("[+]\tModule " + (i + 1) + "\t BaseAddress: 0x" + umi.BaseAddress.ToString("X") + "\tSize: 0x" + umi.Size.ToString("X") + "\t   u1: 0x" + umi.u1.ToString("X") + "\tu2: 0x" + umi.u2.ToString("X") + "\t   Name: " + name_unicode);
                Console.WriteLine(String.Format("|{0,15}|{1,20}|{2,15}|{3,15}|{4,15}|{5,40}|", centeredString((i + 1).ToString(), 15), centeredString("0x"+umi.BaseAddress.ToString("X"), 20), centeredString("0x"+umi.Size.ToString("X"), 15), centeredString("0x"+umi.u1.ToString("X"), 15), centeredString("0x"+umi.u2.ToString("X"), 15), centeredString(name_unicode, 40)));
            }
        }


        public static void ParseCommentStreamW(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
        {
            fs.Seek(streamInfo.Location, SeekOrigin.Begin);
            byte[] csw_data = new byte[streamInfo.Size];
            fs.Read(csw_data, 0, csw_data.Length);
            string csw_stream = Encoding.Unicode.GetString(csw_data);
            Console.WriteLine(csw_stream);
        }


        public static void ParseMemoryInfoListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
        {
            fs.Seek(streamInfo.Location, SeekOrigin.Begin);
            byte[] mil_data = new byte[16];
            fs.Read(mil_data, 0, mil_data.Length);
            MemoryInfoListStream mil_stream = MarshalBytesTo<MemoryInfoListStream>(mil_data);
            int number_of_entries = (int)mil_stream.NumberOfEntries;
            Console.WriteLine("[+] NumberOfEntries: \t" + number_of_entries);
            Console.WriteLine(String.Format("|{0,10}|{1,20}|{2,20}|{3,20}|{4,16}|{5,10}|{6,10}|{7,12}|", centeredString("Entry", 10), centeredString("BaseAddress", 20), centeredString("AllocationBase", 20), centeredString("AllocationProtect", 20), centeredString("RegionSize", 16), centeredString("State", 10), centeredString("Protect", 10), centeredString("Type", 12)));

            for (int i = 0; i < (int)number_of_entries; i++)
            {
                fs.Seek((streamInfo.Location + 16 + i * Marshal.SizeOf(typeof(MemoryInfo))), SeekOrigin.Begin);
                byte[] mi_data = new byte[Marshal.SizeOf(typeof(MemoryInfo))];
                fs.Read(mi_data, 0, mi_data.Length);
                MemoryInfo mi = MarshalBytesTo<MemoryInfo>(mi_data);
                // Console.WriteLine("[+]\tEntry " + (i + 1).ToString("00") + "\tBaseAddress: 0x" + mi.BaseAddress.ToString("X12") + "  AllocationBase: 0x" + mi.AllocationBase.ToString("X12") + "  AllocationProtect: 0x" + mi.AllocationProtect.ToString("X2") + "  RegionSize: 0x" + mi.RegionSize.ToString("X12") + "  State: 0x" + mi.State.ToString("X6") + "  Protect: 0x" + mi.Protect.ToString("X2") + "  Type: 0x" + mi.Type.ToString("X")); // + " u1: 0x" + mi.u1.ToString("X"));
                Console.WriteLine(String.Format("|{0,10}|{1,20}|{2,20}|{3,20}|{4,16}|{5,10}|{6,10}|{7,12}|", centeredString((i + 1).ToString(), 10), centeredString("0x"+mi.BaseAddress.ToString("X"), 20), centeredString("0x"+mi.AllocationBase.ToString("X"), 20), centeredString("0x"+mi.AllocationProtect.ToString("X"), 20), centeredString("0x" + mi.RegionSize.ToString("X"), 16), centeredString("0x" + mi.State.ToString("X"), 10), centeredString("0x" + mi.Protect.ToString("X"), 10), centeredString("0x" + mi.Type.ToString("X"), 12)));
            }
        }


        public static void ParseMemory64ListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
        {
            fs.Seek(streamInfo.Location, SeekOrigin.Begin);
            byte[] ml_data = new byte[12];
            fs.Read(ml_data, 0, ml_data.Length);
            Memory64ListStream ml_stream = MarshalBytesTo<Memory64ListStream>(ml_data);
            ulong number_of_entries = ml_stream.NumberOfEntries;
            Console.WriteLine("[+] NumberOfEntries: \t" + number_of_entries);
            Console.WriteLine("[+] Memory offset:   \t0x" + ml_stream.MemoryRegionsBaseAddress.ToString("X"));
            Console.WriteLine(String.Format("|{0,6}|{1,20}|{2,16}|{3,16}|", centeredString("Entry", 6), centeredString("Address", 20), centeredString("Size", 16), centeredString("Offset in file", 16)));

            int offset = (int)ml_stream.MemoryRegionsBaseAddress;
            for (int i = 0; i < (int)number_of_entries; i++)
            {
                fs.Seek((streamInfo.Location + 16 + i * Marshal.SizeOf(typeof(Memory64Info))), SeekOrigin.Begin);
                byte[] m64i_data = new byte[Marshal.SizeOf(typeof(Memory64Info))];
                fs.Read(m64i_data, 0, m64i_data.Length);
                Memory64Info m64i = MarshalBytesTo<Memory64Info>(m64i_data);
                // Console.WriteLine("[+]\tEntry " + (i + 1).ToString("00") + "\tAddress: 0x" + m64i.Address.ToString("X12") + "\t\tSize: 0x" + m64i.Size.ToString("X") + "\t   Offset in file: 0x" + offset.ToString("X5"));
                Console.WriteLine(String.Format("|{0,6}|{1,20}|{2,16}|{3,16}|", centeredString((i + 1).ToString(), 6), centeredString("0x"+m64i.Address.ToString("X"), 20), centeredString("0x"+m64i.Size.ToString("X"), 16), centeredString("0x"+offset.ToString("X"), 16)));
                offset += (int)m64i.Size;
            }
        }


        public static void ParseModuleListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
        {
            int moduleinfo_size = 108;
            fs.Seek(streamInfo.Location, SeekOrigin.Begin);
            byte[] ml_data = new byte[4];
            fs.Read(ml_data, 0, ml_data.Length);
            ModuleListStream ml_stream = MarshalBytesTo<ModuleListStream>(ml_data);
            int number_of_modules = (int)ml_stream.NumberOfModules;
            Console.WriteLine("[+] NumberOfModules: \t" + number_of_modules);
            Console.WriteLine(String.Format("|{0,6}|{1,18}|{2,10}|{3,14}|{4,12}|{5,50}|", centeredString("Module", 6), centeredString("BaseAddress", 18), centeredString("Size", 10), centeredString("Timestamp", 14), centeredString("PointerName", 12), centeredString("Name", 50)));

            for (int i = 0; i < number_of_modules; i++)
            {
                fs.Seek((streamInfo.Location + 4 + i * moduleinfo_size), SeekOrigin.Begin);
                byte[] mi_data = new byte[moduleinfo_size];
                fs.Read(mi_data, 0, mi_data.Length);
                ModuleInfo module_info = MarshalBytesTo<ModuleInfo>(mi_data);
                // Console.WriteLine("[+]\tModule " + (i + 1));
                // Console.WriteLine("[+]\t   BaseAddress: 0x" + module_info.BaseAddress.ToString("X") + "\tSize: 0x" + module_info.Size.ToString("X") + "\tu1: 0x" + module_info.u1.ToString("X") + "\t\tTimestamp: 0x" + module_info.Timestamp.ToString("X") + "\tPointerName: 0x" + module_info.PointerName.ToString("X") + "\tu2: 0x" + module_info.u2.ToString("X") + "\tu3: 0x" + module_info.u3.ToString("X") + "\tu4: 0x" + module_info.u4.ToString("X"));
                // Console.WriteLine("[+]\t   u5: 0x" + module_info.u5.ToString("X") + "\tu6: 0x" + module_info.u6.ToString("X") + "\tu7: 0x" + module_info.u7.ToString("X") + "\t\tu8: t0x" + module_info.u8.ToString("X") + "\tu9: 0x" + module_info.u9.ToString("X") + "\t\tu10: 0x" + module_info.u10.ToString("X") + "\tu11: 0x" + module_info.u11.ToString("X") + "\t\tu12: 0x" + module_info.u12.ToString("X"));

                // Get unicode length from UNICODE_STRING struct
                fs.Seek(module_info.PointerName, SeekOrigin.Begin);
                byte[] dll_name_length_data = new byte[2];
                fs.Read(dll_name_length_data, 0, dll_name_length_data.Length);
                int dll_name_length = BitConverter.ToInt16(dll_name_length_data, 0);

                // Get unicode buffer from UNICODE_STRING struct
                fs.Seek(module_info.PointerName + 4, SeekOrigin.Begin);
                byte[] name_unicode_bytes = new byte[dll_name_length];
                fs.Read(name_unicode_bytes, 0, name_unicode_bytes.Length);
                string name_unicode = Encoding.Unicode.GetString(name_unicode_bytes);
                // Console.WriteLine("[+]\t   Name: " + name_unicode);

                // Console.WriteLine(String.Format("|{0,8}|{1,14}|{2,10}|{3,10}|{4,10}|{5,11}|{6,10}|{7,10}|{8,10}|{9,10}|{10,10}|{11,10}|{12,10}|{13,10}|{14,10}|{15,10}|{16,10}|{17,10}|", centeredString("Module", 10), centeredString("BaseAddress", 14), centeredString("Size", 10), centeredString("u1", 10), centeredString("Timestamp", 10), centeredString("PointerName", 10), centeredString("u2", 10), centeredString("u3", 10), centeredString("u4", 10), centeredString("u5", 10), centeredString("u6", 10), centeredString("u7", 10), centeredString("u8", 10), centeredString("u9", 10), centeredString("u10", 10), centeredString("u11", 10), centeredString("u12", 10), centeredString("Name", 10)));
                // Console.WriteLine(String.Format("|{0,8}|{1,10}|{2,10}|{3,10}|{4,10}|{5,11}|{6,10}|{7,10}|{8,10}|{9,10}|{10,10}|{11,10}|{12,10}|{13,10}|{14,10}|{15,10}|{16,10}|{17,10}|", centeredString((i + 1).ToString(), 10), centeredString("0x" + module_info.BaseAddress.ToString("X"), 10), centeredString("0x" + module_info.Size.ToString("X"), 10), centeredString("0x" + module_info.u1.ToString("X"), 10), centeredString("0x" + module_info.Timestamp.ToString("X"), 10), centeredString("0x" + module_info.PointerName.ToString("X"), 10), centeredString("0x" + module_info.u2.ToString("X"), 10), centeredString("0x" + module_info.u3.ToString("X"), 10), centeredString("0x" + module_info.u4.ToString("X"), 10), centeredString("0x" + module_info.u5.ToString("X"), 10), centeredString("0x" + module_info.u6.ToString("X"), 10), centeredString("0x" + module_info.u7.ToString("X"), 10), centeredString("0x" + module_info.u8.ToString("X"), 10), centeredString("0x" + module_info.u9.ToString("X"), 10), centeredString("0x" + module_info.u10.ToString("X"), 10), centeredString("0x" + module_info.u11.ToString("X"), 10), centeredString("0x" + module_info.u12.ToString("X"), 10), centeredString(name_unicode, 10)));
                Console.WriteLine(String.Format("|{0,6}|{1,18}|{2,10}|{3,14}|{4,12}|{5,50}|", centeredString((i + 1).ToString(), 6), centeredString("0x" + module_info.BaseAddress.ToString("X"), 18), centeredString("0x" + module_info.Size.ToString("X5"), 10), centeredString("0x" + module_info.Timestamp.ToString("X"), 14), centeredString("0x" + module_info.PointerName.ToString("X"), 12), centeredString(name_unicode, 50)));
            }
        }


        public static void ParseThreadInfoListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
        {
            fs.Seek(streamInfo.Location, SeekOrigin.Begin);
            byte[] tis_data = new byte[12];
            fs.Read(tis_data, 0, tis_data.Length);
            ThreadInfoStream tis_stream = MarshalBytesTo<ThreadInfoStream>(tis_data);
            int number_threads = (int)tis_stream.NumberOfThreads;
            Console.WriteLine("[+]\tField 1\t\t\t0x" + tis_stream.u1.ToString("X"));
            Console.WriteLine("[+]\tField 2:\t\t0x" + tis_stream.u2.ToString("X"));
            Console.WriteLine("[+]\tNumberOfThreads: \t" + number_threads);
            Console.WriteLine(String.Format("|{0,10}|{1,10}|{2,10}|{3,10}|{4,20}|{5,10}|{6,10}|{7,10}|{8,20}|{9,10}|", centeredString("Thread", 10), centeredString("ThreadId", 10), centeredString("Dump", 10), centeredString("ExitStatus", 10), centeredString("CreateTime", 20), centeredString("ExitTime", 10), centeredString("KernelTime", 10), centeredString("UserTime", 10), centeredString("StartAddress", 20), centeredString("Affinity", 10)));
            for (int i = 0; i < number_threads; i++)
            {
                fs.Seek((streamInfo.Location + 12 + i * Marshal.SizeOf(typeof(ThreadInfoStream_Element))), SeekOrigin.Begin);
                byte[] tis_element_data = new byte[Marshal.SizeOf(typeof(ThreadInfoStream_Element))];
                fs.Read(tis_element_data, 0, tis_element_data.Length);
                ThreadInfoStream_Element tis_element = MarshalBytesTo<ThreadInfoStream_Element>(tis_element_data);
                // Console.WriteLine("[+]\tThread " + (i + 1) + "\tThreadId: 0x" + tis_element.ThreadId.ToString("X5") + "\tDump: 0x" + tis_element.Dump.ToString("X") + "\t\tExitStatus: 0x" + tis_element.ExitStatus.ToString("X") + "\t\tCreateTime: 0x" + tis_element.CreateTime.ToString("X") + "\tExitTime: 0x" + tis_element.ExitTime.ToString("X"));
                // Console.WriteLine("[+]\t\t\tKernelTime: 0x" + tis_element.KernelTime.ToString("X5") + "\tUserTime: 0x" + tis_element.UserTime.ToString("X5") + "\tStartAddress: 0x" + tis_element.StartAddress.ToString("X") + "\tAffinity: 0x" + tis_element.Affinity.ToString("X"));
                Console.WriteLine(String.Format("|{0,10}|{1,10}|{2,10}|{3,10}|{4,20}|{5,10}|{6,10}|{7,10}|{8,20}|{9,10}|", centeredString((i + 1).ToString(), 10), centeredString("0x" + tis_element.ThreadId.ToString("X"), 10), centeredString("0x"+tis_element.Dump.ToString("X"), 10), centeredString("0x"+tis_element.ExitStatus.ToString("X"), 10), centeredString("0x"+ tis_element.CreateTime.ToString("X"), 20), centeredString("0x"+tis_element.ExitTime.ToString("X"), 10), centeredString("0x"+tis_element.KernelTime.ToString("X"), 10), centeredString("0x"+ tis_element.UserTime.ToString("X"), 10), centeredString("0x"+tis_element.StartAddress.ToString("X"), 20), centeredString("0x"+ tis_element.Affinity.ToString("X"), 10)));
            }
        }


        public static void ParseThreadListStream(FileStream fs, MinidumpStreamDirectoryEntry streamInfo)
        {
            fs.Seek(streamInfo.Location, SeekOrigin.Begin);
            byte[] tl_data = new byte[4];
            fs.Read(tl_data, 0, tl_data.Length);
            ThreadListStream tl_stream = MarshalBytesTo<ThreadListStream>(tl_data);
            Console.WriteLine("[+] \tNumberOfThreads:\t" + tl_stream.NumberOfThreads);
            Console.WriteLine(String.Format("|{0,10}|{1,10}|{2,15}|{3,15}|{4,10}|{5,15}|{6,10}|{7,10}|{8,10}|{9,10}|{10,10}|{11,10}|", centeredString("Thread", 10), centeredString("ThreadId", 10), centeredString("SuspendCount", 15), centeredString("PriorityClass", 15), centeredString("Priority", 10), centeredString("Teb", 15), centeredString("u1", 10), centeredString("u2", 10), centeredString("u3", 10), centeredString("u4", 10), centeredString("u5", 10), centeredString("u6", 10)));

            for (int i = 0; i < (int)tl_stream.NumberOfThreads; i++)
            {
                fs.Seek((streamInfo.Location + 4 + i * Marshal.SizeOf(typeof(ThreadInfo))), SeekOrigin.Begin);
                tl_data = new byte[Marshal.SizeOf(typeof(ThreadInfo))];
                fs.Read(tl_data, 0, tl_data.Length);
                ThreadInfo t_info = MarshalBytesTo<ThreadInfo>(tl_data);
                // Console.WriteLine("[+]\tThread " + (i + 1) + "\tThreadId: 0x" + t_info.ThreadId.ToString("X5") + "\tSuspendCount: " + t_info.SuspendCount + "\tPriorityClass: " + t_info.PriorityClass + "\tPriority: " + t_info.Priority + "\tTeb: 0x" + t_info.Teb.ToString("X"));
                // Console.WriteLine("[+]\t\t\tu1: " + t_info.u1 + "\t\tu2: " + t_info.u2 + "\t\tu3: " + t_info.u3 + "\t\tu4: " + t_info.u4 + "\t\tu5: " + t_info.u5 + "\tu6: " + t_info.u6);
                Console.WriteLine(String.Format("|{0,10}|{1,10}|{2,15}|{3,15}|{4,10}|{5,15}|{6,10}|{7,10}|{8,10}|{9,10}|{10,10}|{11,10}|", centeredString((i + 1).ToString(), 10), centeredString("0x"+t_info.ThreadId.ToString("X"),10), centeredString(t_info.SuspendCount.ToString(),15), centeredString(t_info.PriorityClass.ToString(), 15) , centeredString(t_info.Priority.ToString(), 10), centeredString("0x" + t_info.Teb.ToString("X"), 15), centeredString("0x" + t_info.u1.ToString("X"),10), centeredString("0x" + t_info.u2.ToString("X"), 10), centeredString("0x" + t_info.u3.ToString("X"), 10), centeredString("0x" + t_info.u4.ToString("X"), 10), centeredString("0x" + t_info.u5.ToString("X"), 10), centeredString("0x" + t_info.u6.ToString("X"), 10)));
            }
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


        public static void ParseHeader(MinidumpHeader header)
        {
            Console.WriteLine("[+]\t Signature: \t\t0x" + header.Signature.ToString("X"));
            Console.WriteLine("[+]\t Version: \t\t" + header.Version);
            Console.WriteLine("[+]\t ImplementationVersion:\t" + header.ImplementationVersion);
            Console.WriteLine("[+]\t NumberOfStreams: \t" + header.NumberOfStreams);
            Console.WriteLine("[+]\t StreamDirectoryRva: \t0x" + header.StreamDirectoryRva.ToString("X"));
            Console.WriteLine("[+]\t CheckSum: \t\t0x" + header.CheckSum.ToString("X"));
            Console.WriteLine("[+]\t TimeDateStamp: \t" + header.TimeDateStamp);
        }


        static string centeredString(string s, int width)
        {
            if (s.Length >= width)
            {
                return s;
            }
            int leftPadding = (width - s.Length) / 2;
            int rightPadding = width - s.Length - leftPadding;
            return new string(' ', leftPadding) + s + new string(' ', rightPadding);
        }


        private static T MarshalBytesTo<T>(byte[] bytes)
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }


        static string GetCleanString(byte[] byteArray)
        {
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < byteArray.Length - 1; i += 2)
            {
                ushort unicodeChar = BitConverter.ToUInt16(byteArray, i);
                if (unicodeChar >= 0x20 && unicodeChar <= 0x7E)
                {
                    stringBuilder.Append((char)unicodeChar);
                }
            }
            return stringBuilder.ToString();
        }


        static T ReadStruct<T>(BinaryReader br) where T : struct
        {
            byte[] buffer = br.ReadBytes(Marshal.SizeOf<T>());
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            T result = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            handle.Free();
            return result;
        }


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
                    return "Unknown";
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


        static void Main(string[] args)
        {
            string minidumpFilePath = args[0];
            Console.WriteLine("[+] Minidump file to analyze: \t" + minidumpFilePath);

            using (FileStream fs = new FileStream(minidumpFilePath, FileMode.Open, FileAccess.Read))
            {
                BinaryReader br = new BinaryReader(fs);
                MinidumpHeader header = ReadStruct<MinidumpHeader>(br);
                Console.WriteLine("\n[+] Reading Header at 0x0");
                ParseHeader(header);

                fs.Seek((long)header.StreamDirectoryRva, SeekOrigin.Begin);
                List<MinidumpStreamDirectoryEntry> streamInfoList = new List<MinidumpStreamDirectoryEntry>();
                for (int i = 0; i < header.NumberOfStreams; i++)
                {
                    MinidumpStreamDirectoryEntry entry = ReadStruct<MinidumpStreamDirectoryEntry>(br);
                    MinidumpStreamDirectoryEntry streamInfo = new MinidumpStreamDirectoryEntry
                    {
                        StreamType = entry.StreamType,
                        Size = entry.Size,
                        Location = entry.Location
                    };
                    streamInfoList.Add(streamInfo);
                }
                streamInfoList = streamInfoList.OrderBy(x => x.Location).ToList();

                Console.WriteLine("\n[+] Reading Stream Directory content at 0x" + header.StreamDirectoryRva.ToString("X"));
                foreach (var streamInfo in streamInfoList)
                {
                    if (streamInfo.Location != 0)
                    {
                        string streamTypeName = GetStreamTypeName(streamInfo.StreamType);
                        Console.WriteLine("[+] \tAddress: 0x" + streamInfo.Location.ToString("X4") + " - 0x" + (streamInfo.Location + streamInfo.Size - 1).ToString("X4") + " \t Size: " + streamInfo.Size + " \t Stream Type: " + streamTypeName + " (" + streamInfo.StreamType + ")");
                    }
                }

                foreach (var streamInfo in streamInfoList)
                {
                    if (streamInfo.Location != 0)
                    {
                        string streamTypeName = GetStreamTypeName(streamInfo.StreamType);

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
                        else if (streamTypeName == "MiscInfoStream")
                        {
                            Console.WriteLine("\n[+] Reading MiscInfoStream at 0x" + streamInfo.Location.ToString("X"));
                            ParseMiscInfoStream(fs, streamInfo);
                        }
                        // TO DO
                        // else if (streamTypeName == "FunctionTableStream"){ }
                        // else if (streamTypeName == "TokenStream"){ }
                        // else if (streamTypeName == "HandleOperationListStream"){ }
                        // else if (streamTypeName == "HandleDataStream"){ }
                    }
                }
            }
        }
    }
}