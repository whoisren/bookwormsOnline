using System.Security.Claims;
using BookwormsOnline.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline.Services;

public class SessionValidationMiddleware
{
    private readonly RequestDelegate _next;

    public SessionValidationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, AppDbContext dbContext)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var memberIdValue = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var sessionId = context.User.FindFirstValue("session_id");
            var sessionValue = context.Session.GetString("session_id");

            if (int.TryParse(memberIdValue, out var memberId) && !string.IsNullOrWhiteSpace(sessionId))
            {
                if (string.IsNullOrWhiteSpace(sessionValue))
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/Account/Login?reason=timeout");
                    return;
                }

                if (!string.Equals(sessionValue, sessionId, StringComparison.Ordinal))
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/Account/Login?reason=session");
                    return;
                }

                var member = await dbContext.Members.AsNoTracking().FirstOrDefaultAsync(m => m.Id == memberId);
                if (member == null || !string.Equals(member.SessionId, sessionId, StringComparison.Ordinal))
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/Account/Login?reason=session");
                    return;
                }
            }

            if (context.Session.IsAvailable)
            {
                context.Session.SetString("session_id", sessionId ?? string.Empty);
            }
        }

        await _next(context);
    }
}
