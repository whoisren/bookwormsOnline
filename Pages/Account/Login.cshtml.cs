using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Net.Mail;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

public class LoginModel : PageModel
{
    private readonly AppDbContext _dbContext;
    private readonly IPasswordHasher<Member> _passwordHasher;
    private readonly RecaptchaService _recaptchaService;
    private readonly RecaptchaOptions _recaptchaOptions;
    private readonly SecurityOptions _securityOptions;
    private readonly AuditLogService _auditLogService;
    private readonly IWebHostEnvironment _environment;
    private readonly EmailService _emailService;

    public LoginModel(
        AppDbContext dbContext,
        IPasswordHasher<Member> passwordHasher,
        RecaptchaService recaptchaService,
        IOptions<RecaptchaOptions> recaptchaOptions,
        IOptions<SecurityOptions> securityOptions,
        AuditLogService auditLogService,
        IWebHostEnvironment environment,
        EmailService emailService)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _recaptchaService = recaptchaService;
        _recaptchaOptions = recaptchaOptions.Value;
        _securityOptions = securityOptions.Value;
        _auditLogService = auditLogService;
        _environment = environment;
        _emailService = emailService;
    }

    [BindProperty]
    public LoginInputModel Input { get; set; } = new();

    public string RecaptchaSiteKey => _recaptchaOptions.SiteKey;

    public string? InfoMessage { get; set; }

    public void OnGet(string? reason = null)
    {
        if (string.Equals(reason, "session", StringComparison.OrdinalIgnoreCase))
        {
            InfoMessage = "Your session has ended because you logged in elsewhere.";
        }
        else if (string.Equals(reason, "timeout", StringComparison.OrdinalIgnoreCase))
        {
            InfoMessage = "Your session has ended due to inactivity.";
        }
        else if (string.Equals(reason, "access", StringComparison.OrdinalIgnoreCase))
        {
            InfoMessage = "Please sign in to access that page.";
        }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var recaptchaPassed = await _recaptchaService.VerifyAsync(
            Input.RecaptchaToken,
            "login",
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
            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            await _auditLogService.WriteAsync(
                "LoginFailed",
                null,
                Input.Email,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString());
            return Page();
        }

        if (member.LockoutEndUtc.HasValue)
        {
            var now = DateTimeOffset.UtcNow;
            if (member.LockoutEndUtc.Value > now)
            {
                ModelState.AddModelError(string.Empty, "Account is locked. Please try again later.");
                await _auditLogService.WriteAsync(
                    "LoginLockedOut",
                    member.Id,
                    member.Email,
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    Request.Headers.UserAgent.ToString());
                return Page();
            }

            member.LockoutEndUtc = null;
            member.FailedLoginAttempts = 0;
            _dbContext.Members.Update(member);
            await _dbContext.SaveChangesAsync();
        }

        var verificationResult = _passwordHasher.VerifyHashedPassword(member, member.PasswordHash, Input.Password);
        if (verificationResult == PasswordVerificationResult.Failed)
        {
            member.FailedLoginAttempts++;
            if (member.FailedLoginAttempts >= _securityOptions.MaxFailedAccessAttempts)
            {
                member.LockoutEndUtc = DateTimeOffset.UtcNow.AddMinutes(_securityOptions.LockoutMinutes);
                member.FailedLoginAttempts = 0;
            }

            _dbContext.Members.Update(member);
            await _dbContext.SaveChangesAsync();

            ModelState.AddModelError(string.Empty, "Invalid email or password.");
            await _auditLogService.WriteAsync(
                "LoginFailed",
                member.Id,
                member.Email,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString());
            return Page();
        }

        member.FailedLoginAttempts = 0;
        member.LockoutEndUtc = null;
        _dbContext.Members.Update(member);
        await _dbContext.SaveChangesAsync();

        var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString("D6");
        var codeHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code)));
        _dbContext.TwoFactorTokens.Add(new TwoFactorToken
        {
            MemberId = member.Id,
            CodeHash = codeHash,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            Used = false
        });
        await _dbContext.SaveChangesAsync();

        try
        {
            var subject = "Your Bookworms Online verification code";
            var body = $"<p>Your verification code is <strong>{code}</strong>. It expires in 5 minutes.</p>";
            await _emailService.SendAsync(member.Email, subject, body);

            await _auditLogService.WriteAsync(
                "TwoFactorCodeGenerated",
                member.Id,
                member.Email,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString());

            if (_environment.IsDevelopment())
            {
                TempData["TwoFactorCode"] = code;
            }
        }
        catch (InvalidOperationException)
        {
            ModelState.AddModelError(string.Empty, "Unable to send verification code. Please try again later.");
            return Page();
        }
        catch (SmtpException)
        {
            ModelState.AddModelError(string.Empty, "Unable to send verification code. Please try again later.");
            return Page();
        }

        HttpContext.Session.SetString("pending_2fa_email", member.Email);
        HttpContext.Session.SetString("pending_2fa_member", member.Id.ToString());

        return RedirectToPage("/Account/TwoFactor", new { email = member.Email });
    }

    public class LoginInputModel
    {
        [Required]
        [Display(Name = "Email Address")]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required]
        public string RecaptchaToken { get; set; } = string.Empty;
    }
}
