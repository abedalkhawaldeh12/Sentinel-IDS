using System;
using System.ComponentModel.DataAnnotations;

namespace IdsDashboard.Models
{
    public class ThreatLog
    {
        [Key]
        public int Id { get; set; }
        public string SourceIp { get; set; }
        public string ThreatType { get; set; }
        public int TargetPort { get; set; }
        public string Description { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
