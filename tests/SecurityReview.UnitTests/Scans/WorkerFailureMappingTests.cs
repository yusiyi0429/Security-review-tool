using SecurityReview.Application.Scans;
using SecurityReview.Domain.Scans;
using SecurityReview.Infrastructure.Windows.Sandbox;

namespace SecurityReview.UnitTests.Scans;

public sealed class WorkerFailureMappingTests
{
    [Theory]
    [InlineData("exception:ProtocolException", "Crash:ProtocolException")]
    [InlineData("exception:InvalidOperationException", "Crash:InvalidOperationException")]
    [InlineData("exception:IOException", "Crash:IOException")]
    public void exception_error_code_preserves_exception_type_in_detail_code(
        string errorCode, string expectedDetailCode)
    {
        (WorkerFailure failure, string detailCode) =
            SandboxWorkerJobProcessor.MapWorkerFailure(errorCode);

        Assert.Equal(WorkerFailure.Crash, failure);
        Assert.Equal(expectedDetailCode, detailCode);
        Assert.Equal(GapReason.ParserCrash, WorkerFailureMapper.MapFailure(failure));
    }

    [Theory]
    [InlineData("timeout", WorkerFailure.Timeout, "Timeout")]
    [InlineData("cancelled", WorkerFailure.Cancelled, "Cancelled")]
    [InlineData("invalid_parse_job", WorkerFailure.ProtocolViolation, "ProtocolViolation")]
    [InlineData("boom", WorkerFailure.Crash, "Crash")]
    [InlineData("exception:", WorkerFailure.Crash, "Crash")]
    [InlineData(null, WorkerFailure.Crash, "Crash")]
    public void non_exception_error_codes_map_exactly_as_before(
        string? errorCode, WorkerFailure expectedFailure, string expectedDetailCode)
    {
        (WorkerFailure failure, string detailCode) =
            SandboxWorkerJobProcessor.MapWorkerFailure(errorCode);

        Assert.Equal(expectedFailure, failure);
        Assert.Equal(expectedDetailCode, detailCode);
    }
}
