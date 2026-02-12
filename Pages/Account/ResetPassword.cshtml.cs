using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

public class ResetPasswordModel : PageModel
{
    private readonly AppDbContext _dbContext;
    private readonly IPasswordHasher<Member> _passwordHasher;
    private readonly RecaptchaService _recaptchaService;
    private readonly RecaptchaOptions _recaptchaOptions;
    private readonly SecurityOptions _securityOptions;
    private readonly AuditLogService _auditLogService;

    public ResetPasswordModel(
        AppDbContext dbContext,
        IPasswordHasher<Member> passwordHasher,
        RecaptchaService recaptchaService,
        IOptions<RecaptchaOptions> recaptchaOptions,
        IOptions<SecurityOptions> securityOptions,
        AuditLogService auditLogService)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _recaptchaService = recaptchaService;
        _recaptchaOptions = recaptchaOptions.Value;
        _securityOptions = securityOptions.Value;
        _auditLogService = auditLogService;
    }

    [BindProperty]
    public ResetPasswordInputModel Input { get; set; } = new();

    public string RecaptchaSiteKey => _recaptchaOptions.SiteKey;

    public void OnGet(string email, string token)
    {
        Input.Email = email;
        Input.Token = token;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var recaptchaPassed = await _recaptchaService.VerifyAsync(
            Input.RecaptchaToken,
            "reset_password",
            HttpContext.Connection.RemoteIpAddress?.ToString());

        if (!recaptchaPassed)
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
            return Page();
        }

        var normalizedEmail = Input.Email.Trim().ToLowerInvariant();
        var member = await _dbContext.Members.FirstOrDefaultAsync(m => m.EmailNormalized == normalizedEmail);
        if (member is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid reset request.");
            return Page();
        }

        var tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Input.Token)));
        var resetToken = await _dbContext.PasswordResetTokens
            .Where(token => token.MemberId == member.Id && token.TokenHash == tokenHash && !token.Used)
            .OrderByDescending(token => token.CreatedAt)
            .FirstOrDefaultAsync();

        if (resetToken is null || resetToken.ExpiresAt < DateTimeOffset.UtcNow)
        {
            ModelState.AddModelError(string.Empty, "Invalid or expired reset token.");
            return Page();
        }

        var recentPasswords = await _dbContext.PasswordHistories
            .Where(history => history.MemberId == member.Id)
            .OrderByDescending(history => history.ChangedAt)
            .Take(_securityOptions.PasswordHistoryCount)
            .ToListAsync();

        foreach (var history in recentPasswords)
        {
            if (_passwordHasher.VerifyHashedPassword(member, history.PasswordHash, Input.NewPassword) == PasswordVerificationResult.Success)
            {
                ModelState.AddModelError(string.Empty, "You cannot reuse your recent passwords.");
                return Page();
            }
        }

        member.PasswordHash = _passwordHasher.HashPassword(member, Input.NewPassword);
        member.LastPasswordChangeUtc = DateTimeOffset.UtcNow;
        member.LockoutEndUtc = null;
        member.FailedLoginAttempts = 0;

        resetToken.Used = true;

        _dbContext.PasswordHistories.Add(new PasswordHistory
        {
            MemberId = member.Id,
            PasswordHash = member.PasswordHash
        });

        _dbContext.Members.Update(member);
        _dbContext.PasswordResetTokens.Update(resetToken);
        await _dbContext.SaveChangesAsync();

        var extra = await _dbContext.PasswordHistories
            .Where(history => history.MemberId == member.Id)
            .OrderByDescending(history => history.ChangedAt)
            .Skip(_securityOptions.PasswordHistoryCount)
            .ToListAsync();

        if (extra.Count > 0)
        {
            _dbContext.PasswordHistories.RemoveRange(extra);
            await _dbContext.SaveChangesAsync();
        }

        await _auditLogService.WriteAsync(
            "PasswordResetCompleted",
            member.Id,
            member.Email,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers.UserAgent.ToString());

        return RedirectToPage("/Account/Login");
    }

    public class ResetPasswordInputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Token { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        [StringLength(100, MinimumLength = 12)]
        [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z0-9]).{12,}$",
            ErrorMessage = "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.")]
        public string NewPassword { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare(nameof(NewPassword))]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        public string RecaptchaToken { get; set; } = string.Empty;
    }
}
