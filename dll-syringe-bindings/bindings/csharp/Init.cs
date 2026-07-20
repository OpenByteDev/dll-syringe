using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using DllSyringe.Sys;

internal class Init {
    [ModuleInitializer]
    internal static void RegisterImportResolver() {
        NativeLibrary.SetDllImportResolver(typeof(NativeMethods).Assembly, NativeMethods.DllImportResolver);
    }
}
