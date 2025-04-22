using System.ComponentModel.DataAnnotations;

namespace ProgressTracker.DTO.Comment
{
    public class CreateCommentDto
    {
        [Required]
        public Guid UserId { get; set; }

        [Required]
        public string Content { get; set; }
    }
}
