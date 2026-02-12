using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

public class RegisterModel : PageModel
{
    private readonly AppDbContext _dbContext;
    private readonly IDataProtector _creditCardProtector;
    private readonly IDataProtector _memberDataProtector;
    private readonly IPasswordHasher<Member> _passwordHasher;
    private readonly RecaptchaService _recaptchaService;
    private readonly IWebHostEnvironment _environment;
    private readonly RecaptchaOptions _recaptchaOptions;
    private readonly SecurityOptions _securityOptions;
    private readonly AuditLogService _auditLogService;

    public RegisterModel(
        AppDbContext dbContext,
        IDataProtectionProvider dataProtectionProvider,
        IPasswordHasher<Member> passwordHasher,
        RecaptchaService recaptchaService,
        IWebHostEnvironment environment,
        IOptions<RecaptchaOptions> recaptchaOptions,
        IOptions<SecurityOptions> securityOptions,
        AuditLogService auditLogService)
    {
        _dbContext = dbContext;
        _creditCardProtector = dataProtectionProvider.CreateProtector("BookwormsOnline.CreditCard");
        _memberDataProtector = dataProtectionProvider.CreateProtector("BookwormsOnline.MemberData");
        _passwordHasher = passwordHasher;
        _recaptchaService = recaptchaService;
        _environment = environment;
        _recaptchaOptions = recaptchaOptions.Value;
        _securityOptions = securityOptions.Value;
        _auditLogService = auditLogService;
    }

    [BindProperty]
    public RegisterInputModel Input { get; set; } = new();

    public string RecaptchaSiteKey => _recaptchaOptions.SiteKey;

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
            "register",
            HttpContext.Connection.RemoteIpAddress?.ToString());

        if (!recaptchaPassed)
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
            return Page();
        }

        var normalizedEmail = Input.Email.Trim().ToLowerInvariant();
        var emailExists = await _dbContext.Members.AnyAsync(member => member.EmailNormalized == normalizedEmail);
        if (emailExists)
        {
            ModelState.AddModelError("Input.Email", "Email address is already registered.");
            return Page();
        }

        if (Input.Photo is null || Input.Photo.Length == 0)
        {
            ModelState.AddModelError("Input.Photo", "A .JPG photo is required.");
            return Page();
        }

        if (Input.Photo.Length > _securityOptions.MaxPhotoSizeBytes)
        {
            ModelState.AddModelError("Input.Photo", "Photo size exceeds the allowed limit.");
            return Page();
        }

        var fileExtension = Path.GetExtension(Input.Photo.FileName);
        if (!string.Equals(fileExtension, ".jpg", StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError("Input.Photo", "Only .JPG files are allowed.");
            return Page();
        }

        if (!string.Equals(Input.Photo.ContentType, "image/jpeg", StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError("Input.Photo", "Photo must be a JPEG image.");
            return Page();
        }

        var webRootPath = _environment.WebRootPath;
        if (string.IsNullOrWhiteSpace(webRootPath))
        {
            webRootPath = Path.Combine(_environment.ContentRootPath, "wwwroot");
        }

        var uploadsPath = Path.Combine(webRootPath, "uploads");
        try
        {
            Directory.CreateDirectory(uploadsPath);

            var fileName = $"{Guid.NewGuid():N}.jpg";
            var filePath = Path.Combine(uploadsPath, fileName);
            await using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await Input.Photo.CopyToAsync(stream);
            }

            var member = new Member
            {
                FirstName = Input.FirstName.Trim(),
                LastName = Input.LastName.Trim(),
                Email = Input.Email.Trim(),
                EmailNormalized = normalizedEmail,
                MobileNo = Input.MobileNo.Trim(),
                BillingAddress = _memberDataProtector.Protect(Input.BillingAddress.Trim()),
                ShippingAddress = _memberDataProtector.Protect(Input.ShippingAddress.Trim()),
                CreditCardEncrypted = _creditCardProtector.Protect(Input.CreditCardNo.Trim()),
                PhotoFileName = fileName,
                LastPasswordChangeUtc = DateTimeOffset.UtcNow
            };

            member.PasswordHash = _passwordHasher.HashPassword(member, Input.Password);

            _dbContext.Members.Add(member);
            await _dbContext.SaveChangesAsync();

            _dbContext.PasswordHistories.Add(new PasswordHistory
            {
                MemberId = member.Id,
                PasswordHash = member.PasswordHash
            });
            await _dbContext.SaveChangesAsync();

            await _auditLogService.WriteAsync(
                "MemberRegistered",
                member.Id,
                member.Email,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent.ToString());

            return RedirectToPage("/Account/Login");
        }
        catch (IOException)
        {
            ModelState.AddModelError("Input.Photo", "Unable to save the uploaded photo. Please try again.");
            return Page();
        }
        catch (UnauthorizedAccessException)
        {
            ModelState.AddModelError("Input.Photo", "Unable to save the uploaded photo. Please try again.");
            return Page();
        }
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
            new("session_id", Guid.NewGuid().ToString("N"))
        };

        var sessionId = claims.Last().Value;
        member.SessionId = sessionId;
        _dbContext.Members.Update(member);
        await _dbContext.SaveChangesAsync();

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
        HttpContext.Session.SetString("session_id", sessionId);
    }

    public class RegisterInputModel
    {
        [Required]
        [Display(Name = "First Name")]
        [MaxLength(100)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Last Name")]
        [MaxLength(100)]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Credit Card No")]
        [MaxLength(30)]
        [RegularExpression("^\\d{16}$", ErrorMessage = "Credit card number must be 16 digits.")]
        public string CreditCardNo { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Mobile No")]
        [Phone]
        [MaxLength(30)]
        public string MobileNo { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Billing Address")]
        [MaxLength(300)]
        public string BillingAddress { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Shipping Address")]
        [MaxLength(300)]
        public string ShippingAddress { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Email Address")]
        [EmailAddress]
        [MaxLength(256)]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [StringLength(100, MinimumLength = 12)]
        [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z0-9]).{12,}$",
            ErrorMessage = "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.")]
        public string Password { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare(nameof(Password))]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Photo (.JPG only)")]
        public IFormFile? Photo { get; set; }

        [Required]
        public string RecaptchaToken { get; set; } = string.Empty;
    }
}
