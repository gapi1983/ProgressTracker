using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProgressTracker.DTO.Task;
using ProgressTracker.Models;
using ProgressTracker.Repositories.RepositorieInterface;
using System.Security.Claims;

namespace ProgressTracker.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TaskController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        public TaskController(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        [Authorize(Roles = "Admin,Manager")]
        [HttpPost("create-task")]
        public async Task<IActionResult> CreateTask([FromBody] TaskDto taskDto)
        {
            try
            {
                if (taskDto.AssignedToUserId == Guid.Empty)
                {
                    return BadRequest("Assigned user ID is empty");
                }

                var assignedUser = await _userRepository.GetUserByIdAsync(taskDto.AssignedToUserId);
                if (assignedUser == null)
                {
                    return BadRequest("Assigned user does not exist");
                }

                // retrieve current user (the one creating the task)
                string userIdString = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userIdString) || !Guid.TryParse(userIdString, out Guid createdByUserId))
                {
                    return BadRequest("Creating user is not found");
                }

                var newTask = new TaskItem
                {
                    TaskId = Guid.NewGuid(),
                    Title = taskDto.Title,
                    Description = taskDto.Description,
                    DueDate = taskDto.DueDate, 
                    AssignedToUserId = taskDto.AssignedToUserId,
                    CreatedByUserId = createdByUserId,
                    Status = taskDto.Status,
                    ProgressPercentage = taskDto.ProgressPercentage,
                };

                var createdTask = await _userRepository.CreateTaskAsync(newTask);
                return Ok();
            }
            catch (Exception ex)
            {
                // Log ex somewhere (e.g., console, file, etc.)
                return StatusCode(500, new { error = ex.Message, stackTrace = ex.StackTrace });
            }
        }
        [Authorize(Roles = "Admin,Manager")]
        [HttpGet("get-all-tasks")]
        public async Task<IActionResult> GetAllTasks()
        {
            var tasks = await _userRepository.GetAllTasksAsync();
            return Ok(tasks);
        }
        [Authorize(Roles = "Admin,Manager")]
        [HttpGet("{taskId:guid}")]
        public async Task<IActionResult> GetTaskById(Guid taskId) 
        {
            var task = await _userRepository.GetTaskByIdAsync(taskId);
            if (task == null)
            {
                return NotFound(new { message = "Task not found." });
            }
            return Ok(task);

        }
        [Authorize(Roles = "Admin,Manager")]
        [HttpPut("{taskId:guid}")]
        public async Task<IActionResult>UpdateTask(Guid taskId, [FromBody] TaskDto taskDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existingTask = await _userRepository.GetTaskByIdAsync(taskId);
            if (existingTask == null)
                return NotFound($"Task with id '{taskId}' not found.");
  
            existingTask.Title = taskDto.Title;
            existingTask.Description = taskDto.Description;
            existingTask.DueDate = taskDto.DueDate;
            existingTask.Status = taskDto.Status;
            existingTask.ProgressPercentage = taskDto.ProgressPercentage;
         
            
            var updatedTask = await _userRepository.UpdateTaskAsync(taskId, existingTask);

            
            return Ok(updatedTask);
        }
        [Authorize(Roles = "Admin,Manager")]
        [HttpDelete("{taskId:guid}")]
        public async Task<IActionResult> DeleteTask(Guid taskId) 
        {
            var task = await _userRepository.GetTaskByIdAsync(taskId);
            if (task == null)
            {
                return NotFound(new { message = "Task not found." });
            }
            await _userRepository.DeleteTaskAsync(taskId);
            return Ok(new { message = "Task deleted successfully." });
        }

        // adding endpoint for employees tasks (to see only their tasks)
        [Authorize(Roles = "Employee")]
        [HttpGet("my-tasks")]
        public async Task<IActionResult> GetMyTasks() 
        {
        
            var userIdString = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdString) || !Guid.TryParse(userIdString, out Guid userId))
            {
                return BadRequest("User ID is not found");
            }
            var tasks = await _userRepository.GetTaskByUserIdAsync(userId);
            return Ok(tasks);
        }


    }
}
