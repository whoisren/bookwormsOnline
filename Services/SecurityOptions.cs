namespace BookwormsOnline.Services;

public class SecurityOptions
{
    public int MaxFailedAccessAttempts { get; set; } = 3;
    public int LockoutMinutes { get; set; } = 15;
    public int MinPasswordAgeMinutes { get; set; } = 60 * 24;
    public int MaxPasswordAgeMinutes { get; set; } = 60 * 24 * 90;
    public int PasswordHistoryCount { get; set; } = 2;
    public long MaxPhotoSizeBytes { get; set; } = 2 * 1024 * 1024;
}
