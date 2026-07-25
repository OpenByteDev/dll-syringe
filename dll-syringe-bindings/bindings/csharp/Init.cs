using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using DllSyringe.Sys;

internal class Init {
#pragma warning disable CA2255
    [ModuleInitializer]
    internal static void RegisterImportResolver() {
        NativeLibrary.SetDllImportResolver(typeof(NativeMethods).Assembly, NativeMethods.DllImportResolver);
    }
#pragma warning restore CA2255
}
