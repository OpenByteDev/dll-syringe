using System;
using System.Diagnostics;
using System.Text;

namespace DllSyringe;

/// <summary>
/// An injector that can inject modules (.dll's) into a target process.
/// </summary>
public class Syringe : IDisposable {
    private readonly RawSyringe _Raw;

    /// <summary>
    /// The process this syringe operates on.
    /// </summary>
    public Process Process { get; private set; }

    /// <summary>
    /// Creates a new instance targeting the given process.
    /// </summary>
    /// <param name="process"></param>
    public Syringe(Process process) {
        Process = process;
        _Raw = CreateRaw(process);
    }

    private static RawSyringe CreateRaw(Process process) {
        var pid = (uint)process.Id;
        var thread = process.Threads[0];
        RawSyringe? raw;
        if (thread.ThreadState == System.Diagnostics.ThreadState.Wait && thread.WaitReason == ThreadWaitReason.Suspended) {
            raw = RawSyringe.ForSuspendedProcess(pid);
        } else {
            raw = RawSyringe.ForProcess(pid);
        }
        if (raw is null) {
            throw new SyringeException($"Failed to create syringe.");
        }
        return raw;
    }

    private static RentedBuffer<byte> ToTerminatedUtf8(ReadOnlySpan<char> str) {
        var byteCount = Encoding.UTF8.GetByteCount(str);
        var buf = new RentedBuffer<byte>(byteCount + 1);
        var written = Encoding.UTF8.GetBytes(str, buf.Span);
        buf.Span[written] = 0;
        return buf;
    }

    /// <summary>
    /// Injects a DLL into the target process.
    /// </summary>
    public bool Inject(ReadOnlySpan<char> dllPath) {
        using var bytes = ToTerminatedUtf8(dllPath);
        return _Raw.Inject(bytes.Span);
    }

    /// <summary>
    /// Finds an existing module or injects the DLL if not present.
    /// Returns the base address of the module.
    /// </summary>
    public ProcessModule FindOrInject(string dllPath) {
        using var bytes = ToTerminatedUtf8(dllPath);
        var handle = _Raw.FindOrInject(bytes.Span);
        if (handle == IntPtr.Zero) {
            throw new SyringeException("Failed to find or inject dll.");
        }

        Process.Refresh();
        foreach (ProcessModule module in Process.Modules) {
            if (module.BaseAddress == handle) {
                return module;
            }
        }

        throw new SyringeException("Failed to find module in target process.");
    }

    /// <summary>
    /// Ejects a module from the target process.
    /// </summary>
    public bool Eject(ProcessModule module) => _Raw.Eject(module.BaseAddress);

    /// <inheritdoc/>
    public void Dispose() {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc/>
    protected virtual void Dispose(bool disposing) {
        if (disposing) {
            _Raw.Dispose();
            Process.Dispose();
        }
    }
}
