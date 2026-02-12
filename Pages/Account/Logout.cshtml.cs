using System.Security.Claims;
using BookwormsOnline.Data;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline.Pages.Account;

public class LogoutModel : PageModel
{
    private readonly AppDbContext _dbContext;
    private readonly AuditLogService _auditLogService;

    public LogoutModel(AppDbContext dbContext, AuditLogService auditLogService)
    {
        _dbContext = dbContext;
        _auditLogService = auditLogService;
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var memberIdValue = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (int.TryParse(memberIdValue, out var memberId))
        {
            var member = await _dbContext.Members.FirstOrDefaultAsync(m => m.Id == memberId);
            if (member is not null)
            {
                member.SessionId = null;
                _dbContext.Members.Update(member);
                await _dbContext.SaveChangesAsync();

                await _auditLogService.WriteAsync(
                    "Logout",
                    member.Id,
                    member.Email,
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    Request.Headers.UserAgent.ToString());
            }
        }

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToPage("/Account/Login");
    }
}
