using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

public class ChangePasswordModel : PageModel
{
    private readonly AppDbContext _dbContext;
    private readonly IPasswordHasher<Member> _passwordHasher;
    private readonly SecurityOptions _securityOptions;
    private readonly AuditLogService _auditLogService;

    public ChangePasswordModel(
        AppDbContext dbContext,
        IPasswordHasher<Member> passwordHasher,
        IOptions<SecurityOptions> securityOptions,
        AuditLogService auditLogService)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _securityOptions = securityOptions.Value;
        _auditLogService = auditLogService;
    }

    [BindProperty]
    public ChangePasswordInputModel Input { get; set; } = new();

    public bool ForceChange { get; set; }

    public void OnGet(bool force = false)
    {
        ForceChange = force || TempData["PasswordExpired"] as string == "true";
    }

    public async Task<IActionResult> OnPostAsync(bool force = false)
    {
        ForceChange = force || TempData["PasswordExpired"] as string == "true";

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var memberIdValue = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!int.TryParse(memberIdValue, out var memberId))
        {
            return RedirectToPage("/Account/Login");
        }

        var member = await _dbContext.Members.FirstOrDefaultAsync(m => m.Id == memberId);
        if (member is null)
        {
            return RedirectToPage("/Account/Login");
        }

        if (member.LastPasswordChangeUtc.HasValue)
        {
            var minAge = TimeSpan.FromMinutes(_securityOptions.MinPasswordAgeMinutes);
            if (DateTimeOffset.UtcNow - member.LastPasswordChangeUtc.Value < minAge)
            {
                ModelState.AddModelError(string.Empty, "Password was changed recently. Please try again later.");
                return Page();
            }
        }

        var verificationResult = _passwordHasher.VerifyHashedPassword(member, member.PasswordHash, Input.CurrentPassword);
        if (verificationResult == PasswordVerificationResult.Failed)
        {
            ModelState.AddModelError(string.Empty, "Current password is incorrect.");
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

        _dbContext.PasswordHistories.Add(new PasswordHistory
        {
            MemberId = member.Id,
            PasswordHash = member.PasswordHash
        });

        _dbContext.Members.Update(member);
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
            "PasswordChanged",
            member.Id,
            member.Email,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers.UserAgent.ToString());

        return RedirectToPage("/Index");
    }

    public class ChangePasswordInputModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current Password")]
        public string CurrentPassword { get; set; } = string.Empty;

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
    }
}
