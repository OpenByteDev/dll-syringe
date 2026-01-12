using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace DllSyringe.Net.Sys;

public static unsafe partial class NativeMethods
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct Syringe {
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct ModuleHandle {
        public IntPtr BaseAddress;
    }


    // https://docs.microsoft.com/en-us/dotnet/standard/native-interop/cross-platform
    // Library path will search
    // win => __DllName, __DllName.dll
    // linux, osx => __DllName.so, __DllName.dylib
    internal static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName == __DllName)
        {
            var dllName = __DllName;
            var path = "runtimes/";
            var extension = "";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                path += "win-";
                extension = ".dll";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                path += "osx-";
                extension = ".dylib";
                dllName = "lib" + dllName;
            }
            else
            {
                path += "linux-";
                extension = ".so";
                dllName = "lib" + dllName;
            }

            if (RuntimeInformation.ProcessArchitecture == Architecture.X86)
            {
                path += "x86";
            }
            else if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
            {
                path += "x64";
            }
            else if (RuntimeInformation.ProcessArchitecture == Architecture.Arm)
            {
                path += "arm";
            }
            else if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
            {
                path += "arm64";
            }

            path += "/native/" + dllName + extension;
            try
            {
                return NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, path), assembly, searchPath);
            }
            catch (DllNotFoundException)
            {
                return NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, dllName + extension));
            }
        }

        return IntPtr.Zero;
    }
}