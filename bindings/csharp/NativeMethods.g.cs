// <auto-generated>
// This code is generated by csbindgen.
// DON'T CHANGE THIS DIRECTLY.
// </auto-generated>
#pragma warning disable CS8500
#pragma warning disable CS8981
using System;
using System.Runtime.InteropServices;


namespace dll_syringe.Net.Sys
{
    public static unsafe partial class NativeMethods
    {
        const string __DllName = "dll_syringe";



        /// <summary>Creates a new `Syringe` instance for a process identified by PID.  # Arguments  * `pid` - The PID of the target process.  # Returns  A pointer to a `CSyringe` instance, or null if the process could not be opened.</summary>
        [DllImport(__DllName, EntryPoint = "syringe_for_process", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern CSyringe* syringe_for_process(uint pid);

        /// <summary>Creates a new `Syringe` instance for a suspended process identified by PID.  # Arguments  * `pid` - The PID of the target suspended process.  # Returns  A pointer to a `CSyringe` instance, or null if the process could not be opened or initialized.</summary>
        [DllImport(__DllName, EntryPoint = "syringe_for_suspended_process", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern CSyringe* syringe_for_suspended_process(uint pid);

        /// <summary>Injects a DLL into the target process associated with the given `Syringe`.  # Safety  This function is unsafe because it dereferences raw pointers.  # Arguments  * `c_syringe` - A pointer to the `CSyringe` instance. * `dll_path` - A C string path to the DLL to be injected.  # Returns  `true` if injection succeeded, otherwise `false`.</summary>
        [DllImport(__DllName, EntryPoint = "syringe_inject", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool syringe_inject(CSyringe* c_syringe, byte* dll_path);

        /// <summary>Finds or injects a DLL into the target process.  If the DLL is already present in the target process, it returns the existing module. Otherwise, it injects the DLL.  # Safety  This function is unsafe because it dereferences raw pointers.  # Arguments  * `c_syringe` - A pointer to the `CSyringe` instance. * `dll_path` - A C string path to the DLL to be injected.  # Returns  A pointer to a `CProcessModule`, or null if the operation failed.</summary>
        [DllImport(__DllName, EntryPoint = "syringe_find_or_inject", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern CProcessModule* syringe_find_or_inject(CSyringe* c_syringe, byte* dll_path);

        /// <summary>Ejects a module from the target process.  # Arguments  * `c_syringe` - A pointer to the `CSyringe` instance. * `c_module` - A pointer to the `CProcessModule` to be ejected.  # Returns  `true` if ejection succeeded, otherwise `false`.  # Safety This is safe as long as it has a valid pointer to a Syringe and Module.</summary>
        [DllImport(__DllName, EntryPoint = "syringe_eject", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool syringe_eject(CSyringe* c_syringe, CProcessModule* c_module);

        /// <summary>Frees a `CSyringe` instance.  # Arguments  * `c_syringe` - A pointer to the `CSyringe` instance to be freed.  # Safety This is safe as long as it has a valid pointer to a Syringe instance.</summary>
        [DllImport(__DllName, EntryPoint = "syringe_free", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern void syringe_free(CSyringe* c_syringe);

        /// <summary>Frees a `CProcessModule` instance.  # Arguments  * `c_module` - A pointer to the `CProcessModule` to be freed.  # Safety This is safe as long as it has a valid pointer to a module created by this Syringe instance.</summary>
        [DllImport(__DllName, EntryPoint = "syringe_module_free", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        public static extern void syringe_module_free(CProcessModule* c_module);


    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe partial struct CSyringe
    {
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe partial struct CProcessModule
    {
    }



}
    