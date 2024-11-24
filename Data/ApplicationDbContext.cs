using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ProgressTracker.Models;

namespace ProgressTracker.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }
        // DbSets for your entities
        public DbSet<TaskItem> Tasks { get; set; }
        public DbSet<Comment> Comments { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure TaskItem -> AssignedToUser relationship
            builder.Entity<TaskItem>()
                .HasOne(t => t.AssignedToUser)
                .WithMany(u => u.TasksAssigned)
                .HasForeignKey(t => t.AssignedToUserId)
                .OnDelete(DeleteBehavior.Restrict);

            // Configure TaskItem -> CreatedByUser relationship
            builder.Entity<TaskItem>()
                .HasOne(t => t.CreatedByUser)
                .WithMany(u => u.TasksCreated)
                .HasForeignKey(t => t.CreatedByUserId)
                .OnDelete(DeleteBehavior.Restrict);

            // Configure Comment -> User relationship
            builder.Entity<Comment>()
                .HasOne(c => c.User)
                .WithMany(u => u.Comments)
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Configure Comment -> Task relationship
            builder.Entity<Comment>()
                .HasOne(c => c.Task)
                .WithMany(t => t.Comments)
                .HasForeignKey(c => c.TaskId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
