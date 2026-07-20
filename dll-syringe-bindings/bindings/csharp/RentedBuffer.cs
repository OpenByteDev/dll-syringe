using System;
using System.Buffers;
using System.Diagnostics;

namespace DllSyringe;

internal struct RentedBuffer<T> : IDisposable {
    private T[]? _Array;
    public int _Length;

    public RentedBuffer(int minimumLength) {
        _Array = ArrayPool<T>.Shared.Rent(minimumLength);
        Length = minimumLength;
    }

    /// <summary>
    /// Gets the minimum length of the buffer.
    /// Can be set to any value smaller or equal to capacity.
    /// </summary>
    public int Length {
        readonly get => _Length;
        set {
            CheckDisposed();
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 0, nameof(value));
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, Capacity, nameof(value));
            _Length = value;
        }
    }

    /// <summary>
    /// Gets the length of the underlying array, which may be larger than length.
    /// </summary>
    public readonly int Capacity => Array.Length;

    /// <summary>
    /// Gets a Span representing the exact requested portion of the rented buffer.
    /// </summary>
    public readonly Span<T> Span {
        get {
            CheckDisposed();
            return _Array.AsSpan(0, Length);
        }
    }

    /// <summary>
    /// Gets the underlying array.
    /// </summary>
    public readonly T[] Array {
        get {
            CheckDisposed();
            Debug.Assert(_Array is not null);
            return _Array;
        }
    }

    private readonly void CheckDisposed() => ObjectDisposedException.ThrowIf(_Array is null, this);

    public void Dispose() {
        if (_Array is not null) {
            ArrayPool<T>.Shared.Return(_Array);
            _Array = null;
        }
    }
}

