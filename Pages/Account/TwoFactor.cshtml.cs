using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

public class TwoFactorModel : PageModel
{
    private readonly AppDbContext _dbContext;
    private readonly SecurityOptions _securityOptions;
    private readonly AuditLogService _auditLogService;

    public TwoFactorModel(
        AppDbContext dbContext,
        IOptions<SecurityOptions> securityOptions,
        AuditLogService auditLogService)
    {
        _dbContext = dbContext;
        _securityOptions = securityOptions.Value;
        _auditLogService = auditLogService;
    }

    [BindProperty]
    public TwoFactorInputModel Input { get; set; } = new();

    public string? DevelopmentCode { get; set; }

    public void OnGet(string email)
    {
        var pendingEmail = HttpContext.Session.GetString("pending_2fa_email");
        if (string.IsNullOrWhiteSpace(pendingEmail) || !string.Equals(pendingEmail, email, StringComparison.OrdinalIgnoreCase))
        {
            Response.Redirect("/Account/Login");
            return;
        }

        Input.Email = email;
        DevelopmentCode = TempData["TwoFactorCode"] as string;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var pendingEmail = HttpContext.Session.GetString("pending_2fa_email");
        var pendingMember = HttpContext.Session.GetString("pending_2fa_member");
        if (string.IsNullOrWhiteSpace(pendingEmail) || string.IsNullOrWhiteSpace(pendingMember))
        {
            return RedirectToPage("/Account/Login");
        }

        if (!string.Equals(pendingEmail, Input.Email, StringComparison.OrdinalIgnoreCase))
        {
            return RedirectToPage("/Account/Login");
        }

        var normalizedEmail = Input.Email.Trim().ToLowerInvariant();
        var member = await _dbContext.Members.FirstOrDefaultAsync(m => m.EmailNormalized == normalizedEmail);
        if (member is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid verification request.");
            return Page();
        }

        var codeHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Input.Code)));
        var token = await _dbContext.TwoFactorTokens
            .Where(t => t.MemberId == member.Id && t.CodeHash == codeHash && !t.Used)
            .OrderByDescending(t => t.CreatedAt)
            .FirstOrDefaultAsync();

        if (token is null || token.ExpiresAt < DateTimeOffset.UtcNow)
        {
            ModelState.AddModelError(string.Empty, "Invalid or expired verification code.");
            await _auditLogService.WriteAsync(
                "TwoFactorFailed",
                member.Id,
                member.Email,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString());
            return Page();
        }

        token.Used = true;
        member.SessionId = Guid.NewGuid().ToString("N");
        _dbContext.TwoFactorTokens.Update(token);
        _dbContext.Members.Update(member);
        await _dbContext.SaveChangesAsync();

        await SignInMemberAsync(member);

        await _auditLogService.WriteAsync(
            "LoginSucceeded",
            member.Id,
            member.Email,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers.UserAgent.ToString());

        HttpContext.Session.Remove("pending_2fa_email");
        HttpContext.Session.Remove("pending_2fa_member");

        if (member.LastPasswordChangeUtc.HasValue)
        {
            var maxAge = TimeSpan.FromMinutes(_securityOptions.MaxPasswordAgeMinutes);
            if (DateTimeOffset.UtcNow - member.LastPasswordChangeUtc.Value > maxAge)
            {
                TempData["PasswordExpired"] = "true";
                return RedirectToPage("/Account/ChangePassword", new { force = true });
            }
        }

        return RedirectToPage("/Index");
    }

    private async Task SignInMemberAsync(Member member)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, member.Id.ToString()),
            new(ClaimTypes.Name, $"{member.FirstName} {member.LastName}".Trim()),
            new(ClaimTypes.Email, member.Email),
            new(ClaimTypes.GivenName, member.FirstName),
            new(ClaimTypes.Surname, member.LastName),
            new("session_id", member.SessionId ?? string.Empty)
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        HttpContext.Session.SetString("session_id", member.SessionId ?? string.Empty);
    }

    public class TwoFactorInputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Verification Code")]
        [StringLength(6, MinimumLength = 6)]
        public string Code { get; set; } = string.Empty;
    }
}
