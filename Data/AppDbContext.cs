using BookwormsOnline.Models;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Member> Members => Set<Member>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<PasswordHistory> PasswordHistories => Set<PasswordHistory>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<TwoFactorToken> TwoFactorTokens => Set<TwoFactorToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Member>()
            .HasIndex(member => member.EmailNormalized)
            .IsUnique();

        modelBuilder.Entity<PasswordHistory>()
            .HasIndex(history => new { history.MemberId, history.ChangedAt });

        modelBuilder.Entity<PasswordResetToken>()
            .HasIndex(token => new { token.MemberId, token.ExpiresAt });

        modelBuilder.Entity<TwoFactorToken>()
            .HasIndex(token => new { token.MemberId, token.ExpiresAt });
    }
}
