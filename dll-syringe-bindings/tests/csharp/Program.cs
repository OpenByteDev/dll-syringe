using DllSyringe;
using System.Diagnostics;

namespace Test;

public static class Program {
    public static void Main(string[] args) {
        if (args.Length != 2) {
            throw new ArgumentException("Expected exactly 2 arguments: <pid> <dll>");
        }

        var pid = int.Parse(args[0]);
        var dll = args[1];

        var process = Process.GetProcessById(pid);
        var syringe = new Syringe(process);

        var ok = syringe.Inject(dll);
        if (!ok) {
            throw new Exception("Failed to inject dll");
        }
    }
}
