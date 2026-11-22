using Microsoft.AspNetCore.Mvc;

namespace GcasE2ETestApi;

[ApiController]
[Route("api/files")]
public sealed class FileController : ControllerBase
{
    private static readonly string BaseDirectory = Path.Combine(AppContext.BaseDirectory, "data");

    [HttpGet]
    public IActionResult Get([FromQuery] string fileName)
    {
        // Intentionally vulnerable: caller controls the path without containment validation.
        var path = Path.Combine(BaseDirectory, fileName);
        if (!System.IO.File.Exists(path))
        {
            return NotFound();
        }

        return PhysicalFile(path, "application/octet-stream");
    }
}
