using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SecurityReview.Infrastructure.Windows.Native;

namespace SecurityReview.Infrastructure.Windows.Sandbox;

// Owns one Job Object handle. No raw job handle escapes this type.
public sealed class WorkerJob : SafeHandleZeroOrMinusOneIsInvalid
{
#pragma warning disable CA1419 // WorkerJob handles originate only from Create(); the constructor satisfies the SafeHandle pattern.
    private WorkerJob()
        : base(true)
    {
    }
#pragma warning restore CA1419

    public static WorkerJob Create()
    {
        SafeJobHandle handle = NativeMethods.CreateJobObject(nint.Zero, null);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new WindowsSecurityException("CreateJobObjectW", error);
        }

        var job = new WorkerJob();
        job.SetHandle(handle.DangerousGetHandle());
        handle.SetHandleAsInvalid();
        handle.Dispose();
        return job;
    }

    public void ApplyLimits(ScanJobLimits limits)
    {
        uint flags = NativeMethods.JobObjectLimitActiveProcess
            | NativeMethods.JobObjectLimitJobMemory;
        if (limits.KillOnJobClose)
        {
            flags |= NativeMethods.JobObjectLimitKillOnJobClose;
        }

        var info = new NativeMethods.JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new NativeMethods.JobObjectBasicLimitInformation
            {
                LimitFlags = flags,
                ActiveProcessLimit = (uint)limits.ActiveProcessLimit,
            },
            JobMemoryLimit = (nuint)limits.JobMemoryBytes,
        };
        SetLimits(info);
    }

    public void ApplyLimits(WorkerJobLimits limits)
    {
        uint flags = NativeMethods.JobObjectLimitActiveProcess
            | NativeMethods.JobObjectLimitProcessMemory;
        if (limits.KillOnJobClose)
        {
            flags |= NativeMethods.JobObjectLimitKillOnJobClose;
        }

        if (limits.DieOnUnhandledException)
        {
            flags |= NativeMethods.JobObjectLimitDieOnUnhandledException;
        }

        var info = new NativeMethods.JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new NativeMethods.JobObjectBasicLimitInformation
            {
                LimitFlags = flags,
                ActiveProcessLimit = (uint)limits.ActiveProcessLimit,
            },
            ProcessMemoryLimit = (nuint)limits.ProcessMemoryBytes,
        };
        SetLimits(info);
    }

    public void AssignProcess(SafeHandle processHandle)
    {
        ObjectDisposedException.ThrowIf(IsClosed, this);
        if (!NativeMethods.AssignProcessToJobObject(this, processHandle))
        {
            throw new WindowsSecurityException("AssignProcessToJobObject",
                Marshal.GetLastPInvokeError());
        }
    }

    public void Terminate(uint exitCode)
    {
        if (IsClosed || IsInvalid)
        {
            return;
        }

        if (!NativeMethods.TerminateJobObject(this, exitCode))
        {
            throw new WindowsSecurityException("TerminateJobObject",
                Marshal.GetLastPInvokeError());
        }
    }

    protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);

    private void SetLimits(NativeMethods.JobObjectExtendedLimitInformation info)
    {
        ObjectDisposedException.ThrowIf(IsClosed, this);
        int size = Marshal.SizeOf<NativeMethods.JobObjectExtendedLimitInformation>();
        nint buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, buffer, false);
            using var job = new SafeJobHandle(DangerousGetHandle(), ownsHandle: false);
            if (!NativeMethods.SetInformationJobObject(job,
                NativeMethods.JobObjectInfoClass.ExtendedLimitInformation, buffer, (uint)size))
            {
                throw new WindowsSecurityException("SetInformationJobObject",
                    Marshal.GetLastPInvokeError());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
