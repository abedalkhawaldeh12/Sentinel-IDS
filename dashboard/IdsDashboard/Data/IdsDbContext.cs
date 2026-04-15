using Microsoft.EntityFrameworkCore;
using IdsDashboard.Models;

namespace IdsDashboard.Data
{
    public class IdsDbContext : DbContext
    {
        public DbSet<ThreatLog> ThreatLogs { get; set; }

        public IdsDbContext(DbContextOptions<IdsDbContext> options) : base(options)
        {
        }
    }
}
