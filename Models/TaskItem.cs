using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProgressTracker.Models
{
    public class TaskItem
    {
        [Key]
        public Guid TaskId { get; set; }

        [Required]
        [StringLength(100)]
        public string Title { get; set; }

        [Required]
        public string Description { get; set; }

        public DateTime DueDate { get; set; }

        // Progress percentage (0 to 100)
        [Range(0, 100)]
        public int ProgressPercentage { get; set; } = 0;

        // Status (e.g., Pending, In Progress, Completed)
        [Required]
        [StringLength(50)]
        public string Status { get; set; } = "Pending";

        // Foreign keys and navigation properties

        // Assigned to (Employee)
        [Required]
        [ForeignKey(nameof(AssignedToUser))]
        public Guid AssignedToUserId { get; set; }
        public virtual ApplicationUser AssignedToUser { get; set; }

        // Created by (Manager)
        [Required]
        [ForeignKey(nameof(CreatedByUser))]
        public Guid CreatedByUserId { get; set; }
        public virtual ApplicationUser CreatedByUser { get; set; }

        // Comments on the task
        public virtual ICollection<Comment> Comments { get; set; }
    }
}
