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

            return Ok(new { token });
        }
        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(ConfirmEmailDto model) 
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

        #endregion

    }

}

