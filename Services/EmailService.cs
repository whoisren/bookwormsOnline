using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Services;

public class EmailService
{
    private readonly SmtpOptions _options;

    public EmailService(IOptions<SmtpOptions> options)
    {
        _options = options.Value;
    }

    public async Task SendAsync(string toEmail, string subject, string htmlBody)
    {
        if (string.IsNullOrWhiteSpace(_options.Host) || string.IsNullOrWhiteSpace(_options.FromAddress))
        {
            throw new InvalidOperationException("SMTP settings are not configured.");
        }

        if (!_options.EnableSsl)
        {
            throw new InvalidOperationException("SMTP must be configured to use SSL/TLS when sending email.");
        }

        // Prevent sending sensitive data in emails
        if (htmlBody != null && (htmlBody.Contains("password", StringComparison.OrdinalIgnoreCase) || htmlBody.Contains("exception", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Attempt to send sensitive data in email body is blocked.");
        }
        if (subject != null && (subject.Contains("password", StringComparison.OrdinalIgnoreCase) || subject.Contains("exception", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Attempt to send sensitive data in email subject is blocked.");
        }

        // Basic sanitization: HTML encode subject and body for user-supplied content
        string safeSubject = System.Net.WebUtility.HtmlEncode(subject);
        string safeBody = htmlBody ?? string.Empty;

        using var message = new MailMessage
        {
            From = new MailAddress(_options.FromAddress, _options.FromName),
            Subject = safeSubject,
            Body = safeBody,
            IsBodyHtml = true
        };
        message.To.Add(new MailAddress(toEmail));

        using var client = new SmtpClient(_options.Host, _options.Port)
        {
            EnableSsl = _options.EnableSsl
        };

        if (!string.IsNullOrWhiteSpace(_options.UserName))
        {
            client.Credentials = new NetworkCredential(_options.UserName, _options.Password);
        }

        try
        {
            await client.SendMailAsync(message);
        }
        catch (SmtpException ex)
        {
            // Log the exception (replace with your logger if available)
            System.Diagnostics.Debug.WriteLine($"Email send failed: {ex}");
            throw new InvalidOperationException("Failed to send email. Please try again later.");
        }
    }
}
