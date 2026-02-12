using System.Security.Claims;
using System.Security.Cryptography;
using BookwormsOnline.Data;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly AppDbContext _dbContext;
        private readonly IDataProtector _memberDataProtector;
        private readonly IDataProtector _creditCardProtector;

        public IndexModel(
            ILogger<IndexModel> logger,
            AppDbContext dbContext,
            IDataProtectionProvider dataProtectionProvider)
        {
            _logger = logger;
            _dbContext = dbContext;
            _memberDataProtector = dataProtectionProvider.CreateProtector("BookwormsOnline.MemberData");
            _creditCardProtector = dataProtectionProvider.CreateProtector("BookwormsOnline.CreditCard");
        }

        public MemberProfileViewModel? Profile { get; private set; }

        public async Task OnGetAsync()
        {
            if (User.Identity?.IsAuthenticated != true)
            {
                return;
            }

            var memberIdValue = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!int.TryParse(memberIdValue, out var memberId))
            {
                return;
            }

            var member = await _dbContext.Members.AsNoTracking().FirstOrDefaultAsync(m => m.Id == memberId);
            if (member is null)
            {
                return;
            }

            var mobile = SafeUnprotect(_memberDataProtector, member.MobileNo);
            var billing = SafeUnprotect(_memberDataProtector, member.BillingAddress);
            var shipping = SafeUnprotect(_memberDataProtector, member.ShippingAddress);
            var creditCard = SafeUnprotect(_creditCardProtector, member.CreditCardEncrypted);

            Profile = new MemberProfileViewModel
            {
                Email = member.Email,
                MobileNo = mobile,
                BillingAddress = billing,
                ShippingAddress = shipping,
                MaskedCreditCard = MaskCreditCard(creditCard),
                PhotoUrl = string.IsNullOrWhiteSpace(member.PhotoFileName) ? null : $"/uploads/{member.PhotoFileName}"
            };
        }

        private static string SafeUnprotect(IDataProtector protector, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            try
            {
                return protector.Unprotect(value);
            }
            catch (CryptographicException)
            {
                return value;
            }
            catch (FormatException)
            {
                return value;
            }
        }

        private static string MaskCreditCard(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            var trimmed = value.Trim();
            if (trimmed.Length <= 4)
            {
                return trimmed;
            }

            return string.Concat(new string('•', trimmed.Length - 4), trimmed[^4..]);
        }

        public sealed class MemberProfileViewModel
        {
            public string Email { get; init; } = string.Empty;
            public string MobileNo { get; init; } = string.Empty;
            public string BillingAddress { get; init; } = string.Empty;
            public string ShippingAddress { get; init; } = string.Empty;
            public string MaskedCreditCard { get; init; } = string.Empty;
            public string? PhotoUrl { get; init; }
        }
    }
}
