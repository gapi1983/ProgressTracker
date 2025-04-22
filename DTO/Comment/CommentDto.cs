using ProgressTracker.Models;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace ProgressTracker.DTO.Comment
{
    public class CommentDto
    {

        public Guid CommentId { get; set; }
        public Guid TaskId { get; set; }

        public Guid UserId { get; set; }
        public string UserName { get; set; }

        public string Content { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
