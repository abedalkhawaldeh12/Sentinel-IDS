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
}
