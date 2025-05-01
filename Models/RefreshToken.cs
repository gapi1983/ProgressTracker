using System.ComponentModel.DataAnnotations;

namespace ProgressTracker.Models
{
    public class RefreshToken
    {
        [Key] public Guid Id { get; set; }

        // FK to AspNetUsers
        [Required] public Guid UserId { get; set; }
        public ApplicationUser User { get; set; }

        [Required] public string Token { get; set; }
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public DateTime? Revoked { get; set; }

        public bool IsActive => Revoked == null && Expires > DateTime.UtcNow;
    }
}

