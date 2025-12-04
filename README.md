# PEClone

**PEClone** 是一款轻量级、原生 C# 编写的 PE 文件（EXE/DLL）属性克隆工具。

它可以将源文件（如系统自带的合法程序）的资源、数字签名、时间戳等特征，“完美”地移植到目标程序中，用于红队行动中的伪装或文件特征混淆。

> **注意**: 本工具仅供安全研究与教育用途，请勿用于非法活动。

## ✨ 主要功能

* **资源克隆 (Resources)**: 完整复制图标 (Icon)、版本信息 (VersionInfo)、Manifest 等资源。
* **签名移植 (Signature)**: 提取源文件的数字签名证书并附加到目标文件（*注：签名状态会显示为无效，但文件属性中可见证书信息*）。
* **时间戳伪造 (TimeStomping)**: 
    * 修改 PE 头部的编译时间戳 (Compile Time)。
    * 同步文件系统的创建时间、修改时间、访问时间。
* **校验和修复 (Checksum)**: 重新计算并修复 PE 头的 Checksum，确保文件结构合法。
* **智能识别**: 自动识别目标是 EXE 还是 DLL，并保持扩展名一致。
* **原生无依赖**: 纯 C# 编写，无需 Visual Studio，无需第三方库，兼容 .NET Framework 4.0+ (甚至支持老旧系统的 `csc.exe` 编译)。

## 🚀 编译指南 (Build)

你不需要安装庞大的 Visual Studio。只要是 Windows 系统，都可以使用自带的编译器进行编译。

### 方法 1: 使用 CMD 命令行
打开命令提示符 (CMD)，运行以下命令：

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /out:PEClone.exe PEClone.cs
```

### 方法 2: 使用 PowerShell
```powershell
& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:exe /out:PEClone.exe PEClone.cs
```

编译成功后，当前目录下会生成 `PEClone.exe`。

## 📖 使用方法 (Usage)

本工具支持 **交互模式** 和 **命令行模式**。

### 1. 交互模式 (推荐)
直接双击运行 `PEClone.exe`，或在控制台直接输入程序名：

1. 程序会提示输入 **源文件 (Source)** 路径（支持直接拖入文件）。
2. 程序会提示输入 **目标文件 (Target)** 路径。
3. 执行完毕后，会在目标文件同级目录下生成 `*_perfect.exe` 或 `*_perfect.dll`。

### 2. 命令行模式 (CLI)
适合集成到脚本或 Cobalt Strike 插件中：

```cmd
PEClone.exe <SourcePath> <TargetPath>
```

**示例:**
```cmd
PEClone.exe C:\Windows\System32\calc.exe C:\Payloads\beacon.dll
```
*输出:* `C:\Payloads\beacon_perfect.dll`

## 🛠️ 技术细节

工具主要经过以下五个阶段的处理：

1.  **资源枚举与更新**: 使用 `LoadLibraryEx` (as DataFile) 和 `UpdateResource` API 提取并写入资源。
2.  **证书表迁移**: 解析 PE 结构中的 Security Directory，提取证书块并追加到目标文件尾部，修正目录表指针。
3.  **PE 时间戳修改**: 直接二进制读写 PE 头部偏移 `0x3C -> PE Header -> +8 bytes` 处的时间戳。
4.  **校验和计算**: 调用 `imagehlp.dll` 的 `MapFileAndCheckSum` 确保 PE 校验和正确。
5.  **文件属性同步**: 使用 .NET `FileInfo` 类同步文件系统时间属性。

## ⚠️ 免责声明 (Disclaimer)

* 本项目仅用于网络安全检测和教学，严禁用于传播恶意软件或进行网络攻击。
* 开发者对使用者利用本项目造成的任何损失或法律后果概不负责。
* 使用本工具即代表您同意上述条款。

## 📄 License

[MIT License](LICENSE)