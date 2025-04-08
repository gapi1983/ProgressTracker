using Microsoft.AspNetCore.Identity;
using ProgressTracker.Models;

namespace ProgressTracker.Repositories.RepositorieInterface
{
    public interface IUserRepository
    {
        Task<IEnumerable<ApplicationUser>> GetAllUsersAsync();
        Task<ApplicationUser> GetUserByIdAsync(Guid userId);
        Task<ApplicationUser> GetUserByEmailAsync(string email);
        Task<IdentityResult> AddUserAsync(ApplicationUser user, string password);
        Task<IdentityResult> UpdateUserAsync(ApplicationUser user);
        Task<IdentityResult> DeleteUserAsync(ApplicationUser user);
        Task<bool> CheckPasswordAsync(ApplicationUser user, string password);
        Task<IList<string>> GetUserRolesAsync(ApplicationUser user);
        Task<IList<IdentityRole<Guid>>> GetAllRolesAsync();
        Task<IList<ApplicationUser>> GetUsersByRoleAsync(Guid roleId);
        Task<IdentityResult> AddToRoleAsync(ApplicationUser user, string role);
        Task<IdentityResult> RemoveFromRoleAsync(ApplicationUser user, string role);
        Task<bool> IsEmailConfirmedAsync(ApplicationUser user);
        Task<string> GenerateEmailConfirmationTokenAsync(ApplicationUser user);
        Task<IdentityResult> ConfirmEmailAsync(ApplicationUser user, string token);
        Task<bool> RoleExistsAsync(string roleName);
        Task<IdentityResult> CreateRoleAsync(string roleName);
        Task<IdentityResult> ResetPasswordAsync(ApplicationUser user, string token, string newPassword);
        Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user);

        // Tasks
        Task<TaskItem> CreateTaskAsync(TaskItem task);
        Task<List<TaskItem>> GetAllTasksAsync();
        Task<TaskItem>GetTaskByIdAsync(Guid taskId);
        Task<TaskItem> UpdateTaskAsync(Guid id, TaskItem task);

        // Comments
        Task<IEnumerable<Comment>> GetCommentByTaskIdAsync(Guid taskId);
        Task<Comment> CreateCommentAsync(Comment comment);
    }
}
