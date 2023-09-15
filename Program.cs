using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
#pragma warning disable CA1416

namespace NTAppLocker;

internal class Program
{
    [DllImport("kernel32.dll")]
    private static extern nint OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId); // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread

    [DllImport("kernel32.dll")]
    private static extern uint SuspendThread(nint hThread); // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(nint hHandle); // https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle

    [Flags]
    private enum ThreadAccess : uint // https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    { 
        SuspendResume = 0x0002 
    } 

    private static void Main(string[] args)
    {
        var blacklist = new HashSet<string?> { "Discord" };

        using var watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        watcher.EventArrived += async (_, e) =>
        {
            var processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
            var processName = GetProcessName(processId);

            if (IsBlacklisted(processName, blacklist))
            {
                await SuspendProcessThreadsAsync(processId);
            }
        };

        watcher.Start();
        Console.WriteLine("Monitoring for new processes. Press Enter to exit.");
        Console.ReadLine();
        watcher.Stop();
    }

    private static async Task SuspendProcessThreadsAsync(int processId)
    {
        try
        {
            var process = Process.GetProcessById(processId);
            await Task.WhenAll(process.Threads.Cast<ProcessThread>().Select(SuspendThreadAsync));
            Console.WriteLine($"Suspended all threads in process {processId}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error suspending threads: {ex.Message}");
        }
    }

    private static async Task SuspendThreadAsync(ProcessThread thread)
    {
        var hThread = OpenThread(ThreadAccess.SuspendResume, false, (uint)thread.Id);
        if (hThread != nint.Zero)
        {
            await Task.Run(() => SuspendThread(hThread));
            CloseHandle(hThread);
            Console.WriteLine($"Suspended thread {thread.Id}");
        }
    }

    private static string? GetProcessName(int processId)
    {
        try
        {
            var process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsBlacklisted(string? processName, IReadOnlySet<string?> blacklist)
    {
        return blacklist.Contains(processName);
    }
}