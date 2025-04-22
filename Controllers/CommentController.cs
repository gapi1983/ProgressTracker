using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using ProgressTracker.DTO.Comment;
using ProgressTracker.Models;
using ProgressTracker.Repositories.RepositorieInterface;

namespace ProgressTracker.Controllers
{
    [Route("api/tasks/{taskId:guid}/comments")]
    [ApiController]
    public class CommentController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        public CommentController(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }
        [HttpGet]
        public async Task<ActionResult<IEnumerable<CommentDto>>> GetAll(Guid taskId)
        {
            var comments = await _userRepository.GetCommentByTaskIdAsync(taskId);

            var commentDto = comments.Select(c => new CommentDto
            {
                TaskId = c.TaskId,
                UserId = c.UserId,
                UserName = c.User.Email,      
                Content = c.Content,
                CreatedAt = c.CreatedAt
            });

            return Ok(commentDto);
        }

        [HttpPost]
        public async Task<ActionResult<CommentDto>>CreateComment(Guid taskId, [FromBody] CreateCommentDto createCommentDto)
        {
            var comment = new Comment
            {
                CommentId = Guid.NewGuid(),
                TaskId = taskId,
                UserId = createCommentDto.UserId,
                Content = createCommentDto.Content,
            };
            var createdComment = await _userRepository.CreateCommentAsync(comment);

            var user = await _userRepository.GetUserByIdAsync(createdComment.UserId);

            var commentDto = new CommentDto
            {
                CommentId = createdComment.CommentId,
                TaskId = createdComment.TaskId,
                UserId = createdComment.UserId,
                UserName = createdComment.User.Email,
                Content = createdComment.Content,
                CreatedAt = createdComment.CreatedAt
            };


            return CreatedAtAction(nameof(GetAll), new { taskId = taskId },commentDto);
        }
        [HttpDelete("{commentId:guid}")]
        public async Task<IActionResult> DeleteComment(Guid taskId, Guid commentId)
        {
            var deletedComment = await _userRepository.DeleteCommentAsync(commentId);
            if (deletedComment == null)
            {
                return NotFound();
            }
            return NoContent();
        }


    }

}
