using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Services;

public class RecaptchaService
{
    private readonly HttpClient _httpClient;
    private readonly RecaptchaOptions _options;

    public RecaptchaService(HttpClient httpClient, IOptions<RecaptchaOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
    }

    public async Task<bool> VerifyAsync(string token, string expectedAction, string? remoteIp)
    {
        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(_options.SecretKey))
        {
            return false;
        }

        var form = new Dictionary<string, string>
        {
            ["secret"] = _options.SecretKey,
            ["response"] = token
        };

        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            form["remoteip"] = remoteIp;
        }

        RecaptchaVerificationResult? result;
        try
        {
            using var response = await _httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", new FormUrlEncodedContent(form));
            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            result = await response.Content.ReadFromJsonAsync<RecaptchaVerificationResult>();
        }
        catch (HttpRequestException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (OperationCanceledException)
        {
            return false;
        }

        if (result is null || !result.Success)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(result.Action) && !string.Equals(result.Action, expectedAction, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return result.Score >= _options.ScoreThreshold;
    }

    private sealed class RecaptchaVerificationResult
    {
        public bool Success { get; init; }
        public double Score { get; init; }
        public string? Action { get; init; }
        public string? Hostname { get; init; }
        public DateTimeOffset ChallengeTs { get; init; }
    }
}
