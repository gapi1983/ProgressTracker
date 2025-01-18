using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProgressTracker.DTO.User;
using ProgressTracker.Repositories.RepositorieInterface;

namespace ProgressTracker.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

        private readonly IUserRepository _userRepository;

        public UserController(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        [Authorize(Roles ="Admin")]
        [HttpGet("all-users")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userRepository.GetAllUsersAsync();

            var userDtos = new List<UserDto>();
            foreach (var user in users)
            {
                var roles = await _userRepository.GetUserRolesAsync(user);
                
                var userDto = new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    EmailConfirmed = await _userRepository.IsEmailConfirmedAsync(user),
                    Role = roles
                };
                userDtos.Add(userDto);
            }

            return Ok(userDtos);
        }
        [Authorize(Roles = "Admin")]
        [HttpDelete("delete-user/{id:guid}")]
        public async Task<IActionResult> DeleteUserById(Guid id) 
        {
            var user = await _userRepository.GetUserByIdAsync(id);
            if (user == null) 
            {
                return NotFound();
            }
            await _userRepository.DeleteUserAsync(user);
            return Ok(new { message = "User deleted." });
        
        }
        [Authorize(Roles = "Admin")]
        [HttpPut("update-user/{id:guid}")]
        public async Task<IActionResult> UpdateUserById(Guid id, [FromBody] UserDto userDto)
        {
            var user = await _userRepository.GetUserByIdAsync(id);
            if(user == null)
            {
                return NotFound();
            }
            user.Email = userDto.Email;
            user.FirstName = userDto.FirstName;
            user.LastName = userDto.LastName;

            var result = await _userRepository.UpdateUserAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Error updating user.", errors = result.Errors });
            }
            return Ok(new { message = "User profile updated successfully." });
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("add-user-role/{id:guid}/{roleName}")]

        public async Task<IActionResult> AddRoleToUser(Guid id,string roleName) 
        {
            var user = await _userRepository.GetUserByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            var roleExists = await _userRepository.RoleExistsAsync(roleName);
            if (!roleExists)
            {
                return BadRequest(new { message = "Role does not exist." });
            }
            var result = await _userRepository.AddToRoleAsync(user, roleName);
            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Error adding role to user.", errors = result.Errors });
            }
            return Ok(new { message = $"Role {roleName} added to user {user.Email}." });
        }

        [Authorize(Roles = "Admin")]
        [HttpDelete("remove-user-role/{id:guid}/{roleName}")]
        public async Task<IActionResult> RemoveRoleFromUser(Guid id, string roleName)
        {
            var user = await _userRepository.GetUserByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            var roleExists = await _userRepository.RoleExistsAsync(roleName);
            if (!roleExists)
            {
                return BadRequest(new { message = "Role does not exist." });
            }
            var result = await _userRepository.RemoveFromRoleAsync(user, roleName);
            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Error removing role from user.", errors = result.Errors });
            }
            return Ok(new { message = $"Role {roleName} removed from user {user.Email}." });
        }
    }
}
