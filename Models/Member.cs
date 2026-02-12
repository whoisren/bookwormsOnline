using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models;

public class Member
{
    public int Id { get; set; }

    [Required]
    [MaxLength(100)]
    public string FirstName { get; set; } = string.Empty;

    [Required]
    [MaxLength(100)]
    public string LastName { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [MaxLength(256)]
    public string EmailNormalized { get; set; } = string.Empty;

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    [Required]
    public string CreditCardEncrypted { get; set; } = string.Empty;

    [Required]
    [MaxLength(30)]
    public string MobileNo { get; set; } = string.Empty;

    [Required]
    [MaxLength(300)]
    public string BillingAddress { get; set; } = string.Empty;

    [Required]
    [MaxLength(300)]
    public string ShippingAddress { get; set; } = string.Empty;

    [MaxLength(260)]
    public string? PhotoFileName { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public int FailedLoginAttempts { get; set; }

    public DateTimeOffset? LockoutEndUtc { get; set; }

    [MaxLength(64)]
    public string? SessionId { get; set; }

    public DateTimeOffset? LastPasswordChangeUtc { get; set; }
}
