using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using ProgressTracker.DTO;
using ProgressTracker.Models;
using ProgressTracker.Repositories.RepositorieInterface;
using ProgressTracker.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ProgressTracker.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        
        private readonly IConfiguration _configuration; // used to access appsettings.json for jwt data
        private readonly EmailService _emailService;
        private readonly IUserRepository _userRepository;
        public AuthController(IUserRepository userRepository, IConfiguration configuration, EmailService emailService)
        {
            _userRepository = userRepository;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var userExists = await _userRepository.GetUserByEmailAsync(model.Email);
            if (userExists != null)
                return Conflict(new { message = "User already exists!" });

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };
            var result = await _userRepository.AddUserAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

           var roleAssignment = await _userRepository.AddToRoleAsync(user, "Employee");
            if (!roleAssignment.Succeeded)
            {
                return BadRequest(roleAssignment.Errors);
            }

            // email confirmation
            try
            {
                if(await SendConfirmEmailAsync(user))
                {
                    return Ok(new { message = "User registered successfully! Please confirm your email." });
                }
                    return BadRequest(new { message = "Email confirmation failed." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Email confirmation failed." });
            }
            
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userRepository.GetUserByEmailAsync(model.Email);
            if (user == null)
                return Unauthorized(new { message = "Invalid credentials." });

            if (!await _userRepository.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new { message = "Invalid credentials." });

            // Check if email is confirmed
            if (!await _userRepository.IsEmailConfirmedAsync(user))
                return Unauthorized(new { message = "Email not confirmed." });

            // Generate JWT token
            var token = await GenerateJwtTokenAsync(user);

            // Instead of returning token in JSON i will return it in a cookie (HttpOnly)
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                Expires = DateTime.UtcNow.AddHours(1),
                SameSite = SameSiteMode.None,
            };
            Response.Cookies.Append("jwt", token, cookieOptions);

            return Ok(new { message="Login successful", token=token }); // remove token after testing
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout() 
        {
            Response.Cookies.Delete("jwt", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            });

            return Ok(new { message = "Logout successful." });
        }

        [Authorize]
        [HttpGet("verify")]
        public async Task<IActionResult> Verify()
        {
            return Ok(new { isLoggedIn = true });
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery]ConfirmEmailDto model) 
        {
            var user = await _userRepository.GetUserByEmailAsync(model.Email);
            if (user == null)
                return Unauthorized(new { message = "This email has not been registered yet." });

            if(user.EmailConfirmed==true) return BadRequest("your email was already confirmed please login to your account");

            try 
            { 
                var decodedTokenBytes = WebEncoders.Base64UrlDecode(model.Token);
                var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

                var result = await _userRepository.ConfirmEmailAsync(user, decodedToken);

                if(result.Succeeded)
                {
                    return Ok(new { message = "Email confirmed successfully." });
                }
                return BadRequest(new { message = "Token not okay." });
            }
            catch (Exception)
            {
                return BadRequest(new { message = "Email confirmation failed." });
            }
        }

        [HttpPost("forgot-password/{email}")]
        public async Task<IActionResult> ForgotPassword(string email) 
        {
            var user = await _userRepository.GetUserByEmailAsync(email);
            if (user == null) 
            {
                return Unauthorized(new { message = "This email has not been registered yet." });
            };

            var emailSent = await SendForgetPasswordEmailAsync(user);
            if (!emailSent)
            {
                return BadRequest(new { message = "Failed to send password reset email. Please try again." });
            }

            return Ok(new { message = "Password reset email sent successfully, check your email." });

        }
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
        {
            if (!ModelState.IsValid) 
            {
                return BadRequest(ModelState);
            }
            var user = await _userRepository.GetUserByEmailAsync(resetPasswordDto.Email);
            if (user == null)
            {
                return Unauthorized(new { message = "This email has not been registered yet." });
            }

            var decodedTokenBytes = WebEncoders.Base64UrlDecode(resetPasswordDto.Token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userRepository.ResetPasswordAsync(user, decodedToken, resetPasswordDto.NewPassword);
            if (!result.Succeeded)
            {
                return BadRequest(new { message = "Error resetting password.", errors = result.Errors });
            }

            return Ok(new { message = "Password has been reset successfully." });
        }
        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            // Fetch the user from your repository:
            var user = await _userRepository.GetUserByIdAsync(Guid.Parse(userId));
            var roles = await _userRepository.GetUserRolesAsync(user);
            return Ok(new
            {
                id = user.Id,
                firstName = user.FirstName,
                lastName = user.LastName,
                roles = roles
            });
        }

        private async Task<string> GenerateJwtTokenAsync(ApplicationUser user)
        {
            var jwtSettings = _configuration.GetSection("Jwt");

            var userRoles = await _userRepository.GetUserRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
            };

            // Add roles to claims
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: authClaims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

       

        #region  Helper Methods

        private async Task<bool> SendConfirmEmailAsync(ApplicationUser applicationUser)
        {
            var token = await _userRepository.GenerateEmailConfirmationTokenAsync(applicationUser);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var url = $"{_configuration["Jwt:ClientUrl"]}/{_configuration["Email:ConfirmEmailPath"]}?token={encodedToken}&email={applicationUser.Email}";

            var body = $"<p>Greetings: {applicationUser.FirstName} {applicationUser.LastName}<p>"+
                $"<p>Please confirm your email by clicking the link below</p>" +
                $"<a href='{url}'>Confirm Email</a>"+
                $"<br>{_configuration["Email:ApplicationName"]}";

            var emailSend = new EmailSendDto(applicationUser.Email, "Confirm your Email", body);

            return await _emailService.SendEmailAsync(emailSend);
        }

        public async Task<bool> SendForgetPasswordEmailAsync(ApplicationUser applicationUser)
        {
            var token = await _userRepository.GeneratePasswordResetTokenAsync(applicationUser);

            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var resetUrl = $"{_configuration["Jwt:ClientUrl"]}/{_configuration["Email:ResetPasswordEmailPath"]}?token={encodedToken}&email={applicationUser.Email}";

            var body = $@"
                <p>Hi {applicationUser.FirstName} {applicationUser.LastName},</p>
                <p>You requested a password reset. Please click the link below to reset your password:</p>
                <a href='{resetUrl}'>Reset Password</a>
                <br />
                <p>{_configuration["Email:ApplicationName"]}</p>";

            var emailSend = new EmailSendDto(applicationUser.Email, "Reset your password", body);

            return await _emailService.SendEmailAsync(emailSend);
        }

        #endregion

    }

}

