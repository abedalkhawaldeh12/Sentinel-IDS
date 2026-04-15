using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using IdsDashboard.Models;
using IdsDashboard.Data;

namespace IdsDashboard.Controllers;

public class HomeController : Controller
{
    private readonly IdsDbContext _context;

    public HomeController(IdsDbContext context)
    {
        _context = context;
    }

    public async Task<IActionResult> Index()
    {
        var logs = await _context.ThreatLogs
                                 .OrderByDescending(t => t.Timestamp)
                                 .Take(100)
                                 .ToListAsync();

        ViewBag.TotalThreats = await _context.ThreatLogs.CountAsync();
        ViewBag.PortScans = await _context.ThreatLogs.CountAsync(t => t.ThreatType == "Port Scan");
        ViewBag.Cleartext = await _context.ThreatLogs.CountAsync(t => t.ThreatType == "Cleartext Protocol");
        ViewBag.DnsAnomalies = await _context.ThreatLogs.CountAsync(t => t.ThreatType == "DNS Anomaly");

        return View(logs);
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    [HttpPost]
    public async Task<IActionResult> ExportThreats()
    {
        var logs = await _context.ThreatLogs.OrderByDescending(t => t.Timestamp).ToListAsync();
        var builder = new System.Text.StringBuilder();
        // Adding BOM for UTF-8 to ensure Excel reads Arabic/Unicode correctly
        builder.Append('\uFEFF');
        builder.AppendLine("Id,Timestamp,SourceIp,TargetPort,ThreatType,Description");
        
        foreach (var log in logs)
        {
            var description = log.Description?.Replace("\"", "\"\"") ?? "";
            builder.AppendLine($"{log.Id},{log.Timestamp:yyyy-MM-dd HH:mm:ss},{log.SourceIp},{log.TargetPort},\"{log.ThreatType}\",\"{description}\"");
        }
        
        var bytes = System.Text.Encoding.UTF8.GetBytes(builder.ToString());
        return File(bytes, "text/csv", $"ThreatsExport_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
    }

    [HttpPost]
    public async Task<IActionResult> ArchiveThreats()
    {
        var logs = await _context.ThreatLogs.ToListAsync();
        if (logs.Any())
        {
            // Save to archive folder locally as JSON
            var archiveDir = Path.Combine(Directory.GetCurrentDirectory(), "Archives");
            if (!Directory.Exists(archiveDir)) 
            {
                Directory.CreateDirectory(archiveDir);
            }
            
            var filename = Path.Combine(archiveDir, $"Archive_{DateTime.Now:yyyyMMdd_HHmmss}.json");
            var json = System.Text.Json.JsonSerializer.Serialize(logs, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            await System.IO.File.WriteAllTextAsync(filename, json);

            _context.ThreatLogs.RemoveRange(logs);
            await _context.SaveChangesAsync();
        }
        return RedirectToAction(nameof(Index));
    }
}
