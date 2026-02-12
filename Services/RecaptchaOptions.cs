namespace BookwormsOnline.Services;

public class RecaptchaOptions
{
    public string SiteKey { get; set; } = string.Empty;
    public string SecretKey { get; set; } = string.Empty;
    public double ScoreThreshold { get; set; } = 0.5;
}
