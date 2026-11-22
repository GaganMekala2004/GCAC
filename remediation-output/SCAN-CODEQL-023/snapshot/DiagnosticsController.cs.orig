using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace GcasE2ETestApi;

[ApiController]
[Route("api/diagnostics")]
public sealed class DiagnosticsController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        using var process = new Process();
        process.StartInfo.FileName = "sh";
        process.StartInfo.Arguments = "-c \"ping -c 1 " + host + "\"";
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.UseShellExecute = false;
        process.Start();
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        return Ok(new { output });
    }
}
