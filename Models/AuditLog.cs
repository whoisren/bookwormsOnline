namespace BookwormsOnline.Models;

public class AuditLog
{
    public int Id { get; set; }
    public int? MemberId { get; set; }
    public string? Email { get; set; }
    public string Action { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
