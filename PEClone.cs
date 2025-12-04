using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace PEClone
{
    class Program
    {
        // ================= P/Invoke 定义 =================
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReserved, uint dwFlags);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr FindResource(IntPtr hModule, IntPtr lpName, IntPtr lpType);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LockResource(IntPtr hResData);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr BeginUpdateResource(string pFileName, bool bDeleteExistingResources);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool UpdateResource(IntPtr hUpdate, IntPtr lpType, IntPtr lpName, ushort wLanguage, byte[] lpData, uint cb);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool EndUpdateResource(IntPtr hUpdate, bool fDiscard);
        [DllImport("kernel32.dll")]
        public static extern bool EnumResourceNames(IntPtr hModule, IntPtr lpszType, EnumResNameDelegate lpEnumFunc, IntPtr lParam);
        public delegate bool EnumResNameDelegate(IntPtr hModule, IntPtr lpszType, IntPtr lpszName, IntPtr lParam);
        [DllImport("imagehlp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint MapFileAndCheckSum(string Filename, out uint HeaderSum, out uint CheckSum);

        public const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
        private static List<IntPtr> _foundIds;

        // ================= 主程序入口 =================
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("╔═══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║        PE Clone Final (Interactive Native Version)            ║");
            Console.WriteLine("╚═══════════════════════════════════════════════════════════════╝");
            Console.WriteLine("");
            Console.ResetColor();

            string sourcePath = "";
            string targetPath = "";
            bool interactiveMode = false;

            // 1. 判断启动模式
            if (args.Length >= 2)
            {
                sourcePath = args[0];
                targetPath = args[1];
            }
            else
            {
                interactiveMode = true;
                Console.WriteLine("--- 交互模式 (支持直接拖入文件) ---");
                
                Console.Write("\n[?] 请输入源文件路径 (Source Path): ");
                string input1 = Console.ReadLine();
                if (input1 != null) sourcePath = input1.Trim(new char[] { '"', ' ' });

                Console.Write("[?] 请输入目标文件路径 (Target Path): ");
                string input2 = Console.ReadLine();
                if (input2 != null) targetPath = input2.Trim(new char[] { '"', ' ' });
            }

            // 2. 基础校验
            if (string.IsNullOrEmpty(sourcePath) || string.IsNullOrEmpty(targetPath))
            {
                LogError("路径不能为空。");
                PauseIfInteractive(interactiveMode);
                return;
            }

            try { sourcePath = Path.GetFullPath(sourcePath); } catch { }
            try { targetPath = Path.GetFullPath(targetPath); } catch { }

            if (!File.Exists(sourcePath)) 
            { 
                LogError(string.Format("源文件不存在: {0}", sourcePath)); 
                PauseIfInteractive(interactiveMode);
                return; 
            }
            if (!File.Exists(targetPath)) 
            { 
                LogError(string.Format("目标文件不存在: {0}", targetPath)); 
                PauseIfInteractive(interactiveMode);
                return; 
            }

            LogValue("Source", sourcePath);
            LogValue("Target", targetPath);

            // 3. 构建输出路径
            string targetDir = Path.GetDirectoryName(targetPath);
            string targetBase = Path.GetFileNameWithoutExtension(targetPath);
            string targetExt = Path.GetExtension(targetPath);
            // 兼容性修改: 使用 string.Format 替代 $
            string finalPath = Path.Combine(targetDir, string.Format("{0}_perfect{1}", targetBase, targetExt));

            LogInfo(string.Format("检测到目标类型: {0}", targetExt));
            LogInfo(string.Format("输出文件路径: {0}", finalPath));

            // 4. 复制文件
            try
            {
                if (File.Exists(finalPath)) File.Delete(finalPath);
                File.Copy(targetPath, finalPath);
            }
            catch (Exception ex)
            {
                LogError(string.Format("文件复制失败: {0}", ex.Message));
                PauseIfInteractive(interactiveMode);
                return;
            }

            Console.WriteLine();

            // 5. 执行核心功能
            ProcessResources(sourcePath, finalPath);
            ProcessDigitalSignature(sourcePath, finalPath);
            ProcessTimeStomping(sourcePath, finalPath);
            ProcessChecksum(finalPath);
            ProcessFileAttributes(sourcePath, finalPath);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("===============================================================");
            LogSuccess(string.Format("任务完成! 完美文件位于: {0}", finalPath));
            Console.ResetColor();

            PauseIfInteractive(interactiveMode);
        }

        static void PauseIfInteractive(bool isInteractive)
        {
            if (isInteractive)
            {
                Console.WriteLine("\n按任意键退出...");
                Console.ReadKey();
            }
        }

        // ================= 功能模块 =================

        static void ProcessResources(string src, string dst)
        {
            LogInfo("阶段 1: 资源克隆 (Resource Cloning)");
            IntPtr hSource = LoadLibraryEx(src, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
            if (hSource == IntPtr.Zero) { LogError("源文件加载失败"); return; }

            IntPtr hUpdate = BeginUpdateResource(dst, true);
            if (hUpdate == IntPtr.Zero)
            {
                LogError("无法打开目标文件进行资源更新");
                FreeLibrary(hSource);
                return;
            }

            int[] typeIds = { 16, 24, 14, 3 };
            string[] typeNames = { "RT_VERSION", "RT_MANIFEST", "RT_GROUP_ICON", "RT_ICON" };

            for (int i = 0; i < typeIds.Length; i++)
            {
                int typeId = typeIds[i];
                LogStep(string.Format("枚举资源: {0}", typeNames[i]));

                _foundIds = new List<IntPtr>();
                EnumResourceNames(hSource, (IntPtr)typeId, new EnumResNameDelegate(EnumResCallback), IntPtr.Zero);

                foreach (IntPtr idPtr in _foundIds)
                {
                    IntPtr hResInfo = FindResource(hSource, idPtr, (IntPtr)typeId);
                    if (hResInfo == IntPtr.Zero) continue;

                    uint size = SizeofResource(hSource, hResInfo);
                    IntPtr hGlobal = LoadResource(hSource, hResInfo);
                    IntPtr pData = LockResource(hGlobal);

                    if (size > 0 && pData != IntPtr.Zero)
                    {
                        byte[] data = new byte[size];
                        Marshal.Copy(pData, data, 0, (int)size);
                        UpdateResource(hUpdate, (IntPtr)typeId, idPtr, 0, data, size);
                    }
                }
            }

            if (EndUpdateResource(hUpdate, false)) LogSuccess("资源写入完成");
            else LogError("资源写入失败");
            
            FreeLibrary(hSource);
        }

        static bool EnumResCallback(IntPtr hModule, IntPtr lpszType, IntPtr lpszName, IntPtr lParam)
        {
            if (((long)lpszName >> 16) == 0) _foundIds.Add(lpszName);
            return true;
        }

        static void ProcessDigitalSignature(string src, string dst)
        {
            LogInfo("阶段 2: 签名移植 (Signature Transplant)");
            byte[] srcBytes = File.ReadAllBytes(src);
            
            int sPeOff = BitConverter.ToInt32(srcBytes, 0x3C);
            ushort sMagic = BitConverter.ToUInt16(srcBytes, sPeOff + 24);
            int sSecDirOff = (sMagic == 0x10b) ? (sPeOff + 24 + 128) : (sPeOff + 24 + 144);
            
            int certRVA = BitConverter.ToInt32(srcBytes, sSecDirOff);
            int certSize = BitConverter.ToInt32(srcBytes, sSecDirOff + 4);

            if (certRVA == 0 || certSize == 0) { LogError("源文件无签名"); return; }

            byte[] certData = new byte[certSize];
            Array.Copy(srcBytes, certRVA, certData, 0, certSize);

            byte[] dstBytes = File.ReadAllBytes(dst);
            int dPeOff = BitConverter.ToInt32(dstBytes, 0x3C);
            ushort dMagic = BitConverter.ToUInt16(dstBytes, dPeOff + 24);
            int rvaCountOffset = (dMagic == 0x10b) ? (dPeOff + 24 + 92) : (dPeOff + 24 + 108);
            int rvaCount = BitConverter.ToInt32(dstBytes, rvaCountOffset);

            if (rvaCount <= 4) { LogError("结构空间不足，跳过签名"); return; }

            int dSecDirOff = (dMagic == 0x10b) ? (dPeOff + 24 + 128) : (dPeOff + 24 + 144);
            int newLoc = dstBytes.Length;
            
            byte[] newBytes = new byte[dstBytes.Length + certSize];
            Array.Copy(dstBytes, 0, newBytes, 0, dstBytes.Length);
            Array.Copy(certData, 0, newBytes, dstBytes.Length, certSize);

            Array.Copy(BitConverter.GetBytes(newLoc), 0, newBytes, dSecDirOff, 4);
            Array.Copy(BitConverter.GetBytes(certSize), 0, newBytes, dSecDirOff + 4, 4);

            File.WriteAllBytes(dst, newBytes);
            LogSuccess("签名已注入");
        }

        static void ProcessTimeStomping(string src, string dst)
        {
            LogInfo("阶段 3: PE 内部编译时间戳 (PE TimeStomping)");
            byte[] srcBytes = File.ReadAllBytes(src);
            int sPeOff = BitConverter.ToInt32(srcBytes, 0x3C);
            int timeStamp = BitConverter.ToInt32(srcBytes, sPeOff + 8);

            DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            DateTime humanTime = origin.AddSeconds(timeStamp).ToLocalTime();
            LogValue("Source Time", humanTime.ToString());

            byte[] dstBytes = File.ReadAllBytes(dst);
            int dPeOff = BitConverter.ToInt32(dstBytes, 0x3C);
            Array.Copy(BitConverter.GetBytes(timeStamp), 0, dstBytes, dPeOff + 8, 4);

            File.WriteAllBytes(dst, dstBytes);
            LogSuccess("PE 时间戳已修改");
        }

        static void ProcessChecksum(string dst)
        {
            LogInfo("阶段 4: 修复校验和 (Checksum Repair)");
            uint headerSum = 0;
            uint checkSum = 0;
            uint ret = MapFileAndCheckSum(dst, out headerSum, out checkSum);

            // 无论返回什么，只要 checkSum 有值就写入
            if (checkSum != 0)
            {
                byte[] bytes = File.ReadAllBytes(dst);
                int peOff = BitConverter.ToInt32(bytes, 0x3C);
                int checksumOffset = peOff + 24 + 64; 
                Array.Copy(BitConverter.GetBytes(checkSum), 0, bytes, checksumOffset, 4);
                File.WriteAllBytes(dst, bytes);
                LogValue("New Checksum", "0x" + checkSum.ToString("X"));
                LogSuccess("校验和已修复");
            }
            else
            {
                LogError("API 调用异常或校验和为0");
            }
        }

        static void ProcessFileAttributes(string src, string dst)
        {
            LogInfo("阶段 5: 文件系统属性克隆");
            try
            {
                FileInfo sInfo = new FileInfo(src);
                FileInfo dInfo = new FileInfo(dst);
                dInfo.CreationTime = sInfo.CreationTime;
                dInfo.LastWriteTime = sInfo.LastWriteTime;
                dInfo.LastAccessTime = sInfo.LastAccessTime;
                LogSuccess("文件系统属性同步完成");
            }
            catch (Exception ex) { LogError(ex.Message); }
        }

        // ================= 辅助日志 (兼容修复) =================
        static void LogStep(string msg) { Console.ForegroundColor = ConsoleColor.DarkGray; Console.WriteLine("[:] " + msg); Console.ResetColor(); }
        static void LogInfo(string msg) { Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine("[*] " + msg); Console.ResetColor(); }
        static void LogSuccess(string msg) { Console.ForegroundColor = ConsoleColor.Green; Console.WriteLine("[+] " + msg); Console.ResetColor(); }
        static void LogError(string msg) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] " + msg); Console.ResetColor(); }
        static void LogValue(string name, string val)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write("    -> " + name + ": ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(val);
            Console.ResetColor();
        }
    }
}