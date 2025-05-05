using Mailjet.Client.Resources;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using ProgressTracker.DTO;
using ProgressTracker.DTO._2FA;
using ProgressTracker.Models;
using ProgressTracker.Repositories.RepositorieInterface;
using ProgressTracker.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;


namespace ProgressTracker.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        
        private readonly IConfiguration _configuration; // used to access appsettings.json for jwt data
        private readonly EmailService _emailService;
        private readonly IUserRepository _userRepository;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UrlEncoder _urlEncoder;

        public AuthController(IUserRepository userRepository, IConfiguration configuration, EmailService emailService, UserManager<ApplicationUser>userManager, SignInManager<ApplicationUser> signInManager, UrlEncoder urlEncoder)
        {
            _userRepository = userRepository;
            _configuration = configuration;
            _emailService = emailService;
            _userManager = userManager;
            _signInManager = signInManager;
            _urlEncoder = urlEncoder;
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
            if (user == null || !await _userRepository.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new { message = "Invalid credentials." });

            if (!await _userRepository.IsEmailConfirmedAsync(user))
                return Unauthorized(new { message = "Email not confirmed." });

            // --- ENFORCE 2FA SETUP ---
            if (!user.TwoFactorSetupComplete)
            {
                // 1) issue a temp JWT so they can call the [Authorize] setup endpoint
                var tempToken = await GenerateJwtTokenAsync(user);
                Response.Cookies.Append("jwt", tempToken, AccessCookieOpts());

                // 2) tell the client to provision 2FA
                return Ok(new
                {
                    mustSetup2FA = true,
                    userId = user.Id
                });
            }
            if (user.TwoFactorEnabled)
            {
                return Ok(new
                {
                    requires2FA = true,
                    userId = user.Id
                });
            }

            // --- ISSUE TOKENS FOR FULLY-AUTHENTICATED USER ---
            var accessToken = await GenerateJwtTokenAsync(user);
            var refreshToken = new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                Token = GenerateSecureToken(),
                Expires = DateTime.UtcNow.AddDays(7)
            };
            await _userRepository.AddRefreshTokenAsync(refreshToken);

            Response.Cookies.Append("jwt", accessToken, AccessCookieOpts());
            Response.Cookies.Append("refresh", refreshToken.Token, RefreshCookieOpts(refreshToken.Expires));

            return Ok(new { message = "Login successful" });
        }


        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            // 1️⃣  revoke the refresh token 
            if (Request.Cookies.TryGetValue("refresh", out var rt))
                await _userRepository.RevokeRefreshTokenAsync(rt);

            
            var deleteOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            };

            //delete both cookies
            Response.Cookies.Delete("jwt", deleteOptions);
            Response.Cookies.Delete("refresh", deleteOptions);

            return Ok(new { message = "Logout successful." });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh() 
        {
            // read refresh cookie
            if (!Request.Cookies.TryGetValue("refresh", out var refreshCookie))
                return Unauthorized();

            var storedRefreshToken = await _userRepository.GetRefreshTokenAsync(refreshCookie);
            if (storedRefreshToken == null || !storedRefreshToken.IsActive) return Unauthorized();

            // chek if user found is valid 
            var user = await _userRepository.GetUserByIdAsync(storedRefreshToken.UserId);
            if (user == null) return Unauthorized();

            // revoking old token ąnd creating new one (rotation - means old token is revoked and new issued)
            storedRefreshToken.Revoked = DateTime.UtcNow;
            await _userRepository.RevokeRefreshTokenAsync(refreshCookie);

            var newRt = new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                Token = GenerateSecureToken(),
                Expires = DateTime.UtcNow.AddDays(7)
            };
            await _userRepository.AddRefreshTokenAsync(newRt);

            // new access token
            var newAccess = await GenerateJwtTokenAsync(user);

            Response.Cookies.Append("jwt", newAccess, AccessCookieOpts());
            Response.Cookies.Append("refresh", newRt.Token, RefreshCookieOpts(newRt.Expires));

            return Ok(new { message = "Token refreshed" });
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
            // Fetch the user from repository:
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

        // 2FA
        [Authorize]
        [HttpGet("2fa/setup")]
        public async Task<IActionResult> Get2FaSetup()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user.TwoFactorSetupComplete)
                return BadRequest("2FA already configured.");

            // Ensure the user has a key
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user)
                                  ?? await ResetAndGetAuthenticatorKeyAsync(user);

            // Build the otpauth:// URI for the QR-code generator
            var qrCodeUri = GenerateQrCodeUri(user.Email, unformattedKey);

            return Ok(new Setup2FaResponseDto
            {
                SharedKey = FormatKey(unformattedKey),
                AuthenticatorUri = qrCodeUri
            });
        }
        [Authorize]
        [HttpPost("2fa/enable")]
        public async Task<IActionResult> Enable2Fa([FromBody] CodeDto codeDto) 
        {
            var user = await _userManager.GetUserAsync(User);

            // sanitize code
            var code = codeDto.Code.Replace(" ", string.Empty)
                               .Replace("-", string.Empty);

            var valid = await _userManager.VerifyTwoFactorTokenAsync(
                            user,
                            _userManager.Options.Tokens.AuthenticatorTokenProvider,
                            code);
            if (!valid)
                return BadRequest(new { message = "Invalid authenticator code." });

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            user.TwoFactorSetupComplete = true;
            await _userManager.UpdateAsync(user);

            return Ok(new { message = "2FA enabled." });
        }
        [HttpPost("login/2fa")]
        public async Task<IActionResult> Login2Fa([FromBody] Login2FaDto dto)
        {
            // 1) Lookup user by the ID passed from the client
            var user = await _userManager.FindByIdAsync(dto.UserId.ToString());
            if (user == null)
                return Unauthorized(new { message = "Invalid 2FA attempt." });

            // 2) Sanitize & verify the TOTP code
            var code = dto.Code.Replace(" ", string.Empty)
                               .Replace("-", string.Empty);

            var valid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                code);

            if (!valid)
                return Unauthorized(new { message = "Invalid 2FA code." });

            // 3) Code is valid → issue your JWT + refresh token just like a normal login
            var accessToken = await GenerateJwtTokenAsync(user);
            var refreshToken = new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                Token = GenerateSecureToken(),
                Expires = DateTime.UtcNow.AddDays(7)
            };
            await _userRepository.AddRefreshTokenAsync(refreshToken);

            Response.Cookies.Append("jwt", accessToken, AccessCookieOpts());
            Response.Cookies.Append("refresh", refreshToken.Token, RefreshCookieOpts(refreshToken.Expires));

            return Ok(new { message = "Login successful" });
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
        // this method generates 64 cryptographically secure random mbytes
        private string GenerateSecureToken()  
        {
            var bytes = RandomNumberGenerator.GetBytes(64);
            return Convert.ToBase64String(bytes);
        }

        // Returns a CookieOptions object for the refresh token cookie with:
        private CookieOptions RefreshCookieOpts(DateTime until) => new()
        {
            HttpOnly = true,                // not accessible via JavaScript (prevents XSS)
            Secure = true,                  // only sent over HTTPS
            SameSite = SameSiteMode.None,   // allows cross-site usage (e.g., frontend on a different domain)
            Expires = until,                // sets expiration based on the argument passed
            Path = "/"                      // make it valid for every endpoint
        };

        // Returns the same kind of cookie options, but specifically for access tokens, which expire in 1 hour.
        private CookieOptions AccessCookieOpts() => new()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = DateTime.UtcNow.AddHours(1),
            Path = "/"
        };
        // 
        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            // otpauth://totp/{Issuer}:{email}?secret={key}&issuer={Issuer}&digits=6
            var issuer = _urlEncoder.Encode("ProgressTracker");
            var user = _urlEncoder.Encode(email);
            return $"otpauth://totp/{issuer}:{user}" + $"?secret={unformattedKey}&issuer={issuer}&digits=6";
        }

        private async Task<string> ResetAndGetAuthenticatorKeyAsync(ApplicationUser user)
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            return await _userManager.GetAuthenticatorKeyAsync(user);
        }

        private string FormatKey(string unformattedKey)
        {
            // split into groups of 4, uppercase
            return string.Join(" ", Enumerable
                .Range(0, unformattedKey.Length / 4)
                .Select(i => unformattedKey.Substring(i * 4, 4)))
                .ToLowerInvariant();
        }
    }

}

