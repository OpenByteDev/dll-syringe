using System;

namespace DllSyringe;

/// <summary>
/// The exception that is thrown when a DLL injection or process operation fails.
/// </summary>
[Serializable]
public class SyringeException : Exception {
    /// <summary>
    /// Initializes a new instance of the <see cref="SyringeException"/> class.
    /// </summary>
    public SyringeException() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="SyringeException"/> class with a specified error message.
    /// </summary>
    public SyringeException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="SyringeException"/> class with a specified error message 
    /// and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    public SyringeException(string message, Exception innerException) : base(message, innerException) { }
}
