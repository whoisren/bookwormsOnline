namespace BookwormsOnline.Models;

public class PasswordResetToken
{
    public int Id { get; set; }
    public int MemberId { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public bool Used { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
