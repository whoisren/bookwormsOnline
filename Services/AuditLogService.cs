using BookwormsOnline.Data;
using BookwormsOnline.Models;

namespace BookwormsOnline.Services;

public class AuditLogService
{
    private readonly AppDbContext _dbContext;

    public AuditLogService(AppDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task WriteAsync(string action, int? memberId, string? email, string? ipAddress, string? userAgent)
    {
        var log = new AuditLog
        {
            Action = action,
            MemberId = memberId,
            Email = email,
            IpAddress = ipAddress,
            UserAgent = userAgent
        };

        _dbContext.AuditLogs.Add(log);
        await _dbContext.SaveChangesAsync();
    }
}
