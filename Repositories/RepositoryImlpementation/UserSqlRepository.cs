using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProgressTracker.Data;
using ProgressTracker.Models;
using ProgressTracker.Repositories.RepositorieInterface;
using System.Threading.Tasks;

namespace ProgressTracker.Repositories.RepositoryImlpementation
{
    public class UserSqlRepository : IUserRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole<Guid>> _roleManager;
        private readonly ApplicationDbContext dbContext;



        public UserSqlRepository(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole<Guid>> roleManager, ApplicationDbContext dbContext)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            this.dbContext = dbContext;
        }

        public async Task<IEnumerable<ApplicationUser>> GetAllUsersAsync()
        {
            return await _userManager.Users.ToListAsync();
        }

        public async Task<IdentityResult> DeleteUserAsync(ApplicationUser user)
        {
            return await _userManager.DeleteAsync(user);
        }

        public async Task<ApplicationUser> GetUserByEmailAsync(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }

        public async Task<ApplicationUser> GetUserByIdAsync(Guid userId)
        {
            return await _userManager.FindByIdAsync(userId.ToString());
        }

        public async Task<IdentityResult> UpdateUserAsync(ApplicationUser user)
        {
            return await _userManager.UpdateAsync(user);
        }

        public async Task<IdentityResult> AddUserAsync(ApplicationUser user, string password)
        {
            return await _userManager.CreateAsync(user, password);
        }
        public async Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
        {
            return await _userManager.CheckPasswordAsync(user, password);
        }
        // Additional methods
        public async Task<IList<string>> GetUserRolesAsync(ApplicationUser user)
        {
            return await _userManager.GetRolesAsync(user);
        }
        public async Task<IList<IdentityRole<Guid>>> GetAllRolesAsync()
        {
            return await _roleManager.Roles.ToListAsync();
        }

        public async Task<IdentityResult> AddToRoleAsync(ApplicationUser user, string role)
        {
            return await _userManager.AddToRoleAsync(user, role);
        }
        public async Task<IdentityResult> RemoveFromRoleAsync(ApplicationUser user, string role)
        {
            return await _userManager.RemoveFromRoleAsync(user, role);
        }

        public async Task<bool> IsEmailConfirmedAsync(ApplicationUser user)
        {
            return await _userManager.IsEmailConfirmedAsync(user);
        }

        public async Task<string> GenerateEmailConfirmationTokenAsync(ApplicationUser user)
        {
            return await _userManager.GenerateEmailConfirmationTokenAsync(user);
        }

        public async Task<IdentityResult> ConfirmEmailAsync(ApplicationUser user, string token)
        {
            return await _userManager.ConfirmEmailAsync(user, token);
        }
        public async Task<IList<ApplicationUser>> GetUsersByRoleAsync(Guid roleId)
        {
            var role = await _roleManager.FindByIdAsync(roleId.ToString());
            if (role == null)
            {
                return new List<ApplicationUser>();
            }
            var users = await _userManager.GetUsersInRoleAsync(role.Name);
            return users;
        }

        public async Task<bool> RoleExistsAsync(string roleName)
        {
            return await _roleManager.RoleExistsAsync(roleName);
        }
       public async Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user)
        {
            return await _userManager.GeneratePasswordResetTokenAsync(user);
        }
        public async Task<IdentityResult> ResetPasswordAsync(ApplicationUser user, string token, string newPassword)
        {
            return await _userManager.ResetPasswordAsync(user, token, newPassword);
        }

        public async Task<IdentityResult> CreateRoleAsync(string roleName)
        {
            if (!await RoleExistsAsync(roleName))
            {
                return await _roleManager.CreateAsync(new IdentityRole<Guid>(roleName));
            }
            else 
            {
                return IdentityResult.Failed(new IdentityError { Description = $"Role '{roleName}' already exists." });
            }
            
        }

        // tasks
        public async Task<TaskItem> CreateTaskAsync(TaskItem task)
        {
            await dbContext.Tasks.AddAsync(task);
            await dbContext.SaveChangesAsync();
            return task;
        }

        public async Task<List<TaskItem>>GetAllTasksAsync()
        {
            var tasks =  await dbContext.Tasks.ToListAsync();
            return tasks;
        }
        public async Task<TaskItem> GetTaskByIdAsync(Guid taskId)
        {
            return await dbContext.Tasks.FindAsync(taskId);
        }
        public async Task<TaskItem> UpdateTaskAsync(Guid taskId, TaskItem updatedTask)
        {
            
            var existingTask = await dbContext.Tasks.FindAsync(taskId);
            if (existingTask == null)
            {
                
                return null;
            }

            
            existingTask.Title = updatedTask.Title;
            existingTask.Description = updatedTask.Description;
            existingTask.DueDate = updatedTask.DueDate;
            existingTask.Status = updatedTask.Status;
            existingTask.ProgressPercentage = updatedTask.ProgressPercentage;
            existingTask.AssignedToUserId = updatedTask.AssignedToUserId;
          

      
            await dbContext.SaveChangesAsync();


            return existingTask;
        }
        // comments

        public async Task<IEnumerable<Comment>> GetCommentByTaskIdAsync(Guid taskId)
        {
            return await dbContext.Comments
                .Where(c => c.TaskId == taskId)
                .Include(c => c.User) 
                .OrderByDescending(c => c.CreatedAt)
                .ToListAsync();
        }

        public async Task<Comment> CreateCommentAsync(Comment comment)
        {
            await dbContext.Comments.AddAsync(comment);
            await dbContext.SaveChangesAsync();
            return comment;
        }

        public async Task<Comment> DeleteCommentAsync(Guid commentId)
        {
            var commentToDelete = await dbContext.Comments.FirstOrDefaultAsync(c => c.CommentId == commentId);
            if (commentToDelete == null) 
            {
                return null;
            }
            dbContext.Comments.Remove(commentToDelete);
            await dbContext.SaveChangesAsync();
            return commentToDelete;
        }



        public async Task<List<TaskItem>> GetTaskByUserIdAsync(Guid userId)
        {
            return await dbContext.Tasks.Where(t => t.AssignedToUserId == userId).ToListAsync();
        }

        public async Task<TaskItem> DeleteTaskAsync(Guid taskId)
        {
            var taskToDelete = await dbContext.Tasks.FirstOrDefaultAsync(t => t.TaskId == taskId);

            if (taskToDelete != null)
            {
                dbContext.Tasks.Remove(taskToDelete);
                await dbContext.SaveChangesAsync();
                return taskToDelete;
            }
            else
            {
                return null;
            }
        }

        
    }
}
