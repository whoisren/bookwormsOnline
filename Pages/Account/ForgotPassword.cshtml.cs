using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Net.Mail;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

public class ForgotPasswordModel : PageModel
{
    private readonly AppDbContext _dbContext;
    private readonly RecaptchaService _recaptchaService;
    private readonly RecaptchaOptions _recaptchaOptions;
    private readonly AuditLogService _auditLogService;
    private readonly IWebHostEnvironment _environment;
    private readonly EmailService _emailService;

    public ForgotPasswordModel(
        AppDbContext dbContext,
        RecaptchaService recaptchaService,
        IOptions<RecaptchaOptions> recaptchaOptions,
        AuditLogService auditLogService,
        IWebHostEnvironment environment,
        EmailService emailService)
    {
        _dbContext = dbContext;
        _recaptchaService = recaptchaService;
        _recaptchaOptions = recaptchaOptions.Value;
        _auditLogService = auditLogService;
        _environment = environment;
        _emailService = emailService;
    }

    [BindProperty]
    public ForgotPasswordInputModel Input { get; set; } = new();

    public string RecaptchaSiteKey => _recaptchaOptions.SiteKey;

    public string? ResetLink { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var recaptchaPassed = await _recaptchaService.VerifyAsync(
            Input.RecaptchaToken,
            "forgot_password",
            HttpContext.Connection.RemoteIpAddress?.ToString());

        if (!recaptchaPassed)
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
            return Page();
        }

        var normalizedEmail = Input.Email.Trim().ToLowerInvariant();
        var member = await _dbContext.Members.FirstOrDefaultAsync(m => m.EmailNormalized == normalizedEmail);
        if (member is not null)
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(32);
            var token = Convert.ToBase64String(tokenBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
            var tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

            _dbContext.PasswordResetTokens.Add(new PasswordResetToken
            {
                MemberId = member.Id,
                TokenHash = tokenHash,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                Used = false
            });

            await _dbContext.SaveChangesAsync();

            await _auditLogService.WriteAsync(
                "PasswordResetRequested",
                member.Id,
                member.Email,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString());

            var resetLink = Url.Page("/Account/ResetPassword", null, new { email = member.Email, token }, Request.Scheme);
            if (!string.IsNullOrWhiteSpace(resetLink))
            {
                try
                {
                    var subject = "Reset your Bookworms Online password";
                    var body = $"<p>Click the link below to reset your password:</p><p><a href=\"{resetLink}\">Reset Password</a></p>";
                    await _emailService.SendAsync(member.Email, subject, body);

                    if (_environment.IsDevelopment())
                    {
                        ResetLink = resetLink;
                    }
                }
                catch (InvalidOperationException)
                {
                    ModelState.AddModelError(string.Empty, "Unable to send reset email. Please try again later.");
                    return Page();
                }
                catch (SmtpException)
                {
                    ModelState.AddModelError(string.Empty, "Unable to send reset email. Please try again later.");
                    return Page();
                }
            }
        }

        TempData["ResetRequested"] = "true";
        return Page();
    }

    public class ForgotPasswordInputModel
    {
        [Required]
        [Display(Name = "Email Address")]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string RecaptchaToken { get; set; } = string.Empty;
    }
}
