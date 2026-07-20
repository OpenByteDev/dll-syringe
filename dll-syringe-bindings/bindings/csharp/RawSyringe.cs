using System;
using DllSyringe.Sys;
using SysSyringe = DllSyringe.Sys.Syringe;

namespace DllSyringe;

/// <summary>
/// A low-level injector that can inject modules (.dll's) into a target process.
/// </summary>
public sealed unsafe class RawSyringe : IDisposable {
    private SysSyringe* _Handle;
    private bool _Disposed;

    private RawSyringe(SysSyringe* handle) {
        _Handle = handle;
    }

    /// <summary>
    /// Creates a new Syringe instance for a process identified by PID.
    /// </summary>
    public static RawSyringe? ForProcess(uint pid) {
        SysSyringe* handle = NativeMethods.syringe_for_process(pid);
        return handle != null ? new RawSyringe(handle) : null;
    }

    /// <summary>
    /// Creates a new Syringe instance for a suspended process identified by PID.
    /// </summary>
    public static RawSyringe? ForSuspendedProcess(uint pid) {
        SysSyringe* handle = NativeMethods.syringe_for_suspended_process(pid);
        return handle != null ? new RawSyringe(handle) : null;
    }

    /// <summary>
    /// Injects a DLL into the target process.
    /// </summary>
    public bool Inject(ReadOnlySpan<byte> dllPath) {
        CheckDisposed();

        fixed (byte* ptr = dllPath) {
            return NativeMethods.syringe_inject(_Handle, ptr);
        }
    }

    /// <summary>
    /// Finds an existing module or injects the DLL if not present.
    /// Returns the base address of the module.
    /// </summary>
    public IntPtr FindOrInject(ReadOnlySpan<byte> dllPath) {
        CheckDisposed();

        fixed (byte* ptr = dllPath) {
            return (nint)NativeMethods.syringe_find_or_inject(_Handle, ptr);
        }

    }

    /// <summary>
    /// Ejects a module from the target process using its base address.
    /// </summary>
    public bool Eject(IntPtr module) {
        CheckDisposed();

        return NativeMethods.syringe_eject(_Handle, (void*)module);
    }

    private void CheckDisposed() => ObjectDisposedException.ThrowIf(_Disposed, this);

    /// <inheritdoc/>
    public void Dispose() {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool _disposing) {
        if (!_Disposed) {
            if (_Handle is not null) {
                NativeMethods.syringe_free(_Handle);
                _Handle = null;
            }
            _Disposed = true;
        }
    }

    /// <inheritdoc/>
    ~RawSyringe() {
        Dispose(false);
    }
}

