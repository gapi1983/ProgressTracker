using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProgressTracker.Models
{
    public class Comment
    {
        [Key]
        public Guid CommentId { get; set; }

        [Required]
        [ForeignKey(nameof(Task))]
        public Guid TaskId { get; set; }
        public virtual TaskItem Task { get; set; }

        [Required]
        [ForeignKey(nameof(User))]
        public Guid UserId { get; set; }
        public virtual ApplicationUser User { get; set; }

        [Required]
        public string Content { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
