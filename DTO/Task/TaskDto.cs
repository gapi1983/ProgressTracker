using System.ComponentModel.DataAnnotations;

namespace ProgressTracker.DTO.Task
{
    public class TaskDto
    {
        [Required]
        [StringLength(100)]
        public string Title { get; set; }

        [Required]
        public string Description { get; set; }

        [Required]
        public DateTime DueDate { get; set; }
        [Required]
        public string Status { get; set; }
        [Required]
        public int ProgressPercentage { get; set; }

        [Required]
        public Guid AssignedToUserId { get; set; } // changed form user id and guid
    }
}
