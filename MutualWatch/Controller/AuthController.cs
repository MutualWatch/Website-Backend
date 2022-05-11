using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Service.Models;
using Service.ViewModels;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Linq;

namespace MutualWatch.Controller
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly JwtBearerTokenSettings jwtBearerTokenSettings;
        private readonly UserManager<IdentityUser> userManager;
        private RoleManager<IdentityRole> roleManager;
        public AuthController(IOptions<JwtBearerTokenSettings> jwtTokenOptions,UserManager<IdentityUser> userManager, RoleManager<IdentityRole> _roleManager)
        {
            this.userManager = userManager;
            this.roleManager = _roleManager;
            jwtBearerTokenSettings = jwtTokenOptions.Value;
        }
        #region Register
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserDetails userDetails)
        {
            if (!ModelState.IsValid || userDetails == null)
            {
                return new BadRequestObjectResult(new { Message = "User Registration Failed" });
            }

            var identityUser = new IdentityUser() { UserName = userDetails.Firstname+userDetails.Lastname, Email = userDetails.Email };
            var result = await userManager.CreateAsync(identityUser, userDetails.Password);
            if (!result.Succeeded)
            {
                var dictionary = new ModelStateDictionary();
                foreach (IdentityError error in result.Errors)
                {
                    dictionary.AddModelError(error.Code, error.Description);
                }

                return new BadRequestObjectResult(new { Message = "User Registration Failed", Errors = dictionary });
            }


            //#region Register User
            //VM_Customer customerDetail = new VM_Customer();
            //customerDetail.FullName = userDetails.Firstname + userDetails.Lastname;
            //customerDetail.UserName = userDetails.Email;
            //customerDetail.Email = userDetails.Email;
            //customerDetail.Password = userDetails.Password;
            //customerDetail.IsSeller = (userDetails.UserType == 0) ? true : false;
            //customerDetail.UserId = identityUser.Id;
            //var response = Customers.Post_Customers(customerDetail);
            //#endregion Register User

            #region Role
            IdentityRole role = new IdentityRole();
            if (userDetails.UserType == 0)
            {
                role = await roleManager.FindByNameAsync("SuperAdmin");
            }
            else
            {
                role = await roleManager.FindByNameAsync("User");
            }

            var user = await userManager.FindByEmailAsync(userDetails.Email);
            if (!await userManager.IsInRoleAsync(user, role.Name))
            {
                await userManager.AddToRoleAsync(user, role.Name);
            }
            #endregion

            Response response = new Response();
            response.Data = result;
            response.Message = "User Reigstration Successful";
            response.Success = true;
            return Ok(response);
        }
        #endregion

        #region Login
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginCredentials credentials)
        {
            IdentityUser identityUser;

            if (!ModelState.IsValid || credentials == null || (identityUser = await ValidateUser(credentials)) == null)
            {
                return new BadRequestObjectResult(new { Message = "Login failed" });
            }
            var val =  userManager.GetRolesAsync(identityUser);
            TokenClass tokenClass = new TokenClass();
            tokenClass = GenerateToken(identityUser, (await userManager.GetRolesAsync(identityUser)).ToList());
            var refreshToken= RefreshToken(identityUser, (await userManager.GetRolesAsync(identityUser)).ToList());
            Response response = new Response();
            response.Data = new
            {
                UserId = identityUser.Id,
                UserName = identityUser.UserName,
                Email = identityUser.Email,
                Token=tokenClass.token,
                ExpTime=tokenClass.exptime,
                RefreshToken=refreshToken,
                Roles=val
            };
            response.Success = true;
            response.Message = "Login Succesfull.";
            return Ok(response);
        }
        #endregion

        #region ValidateUser
        private async Task<IdentityUser> ValidateUser(LoginCredentials credentials)
        {
            var identityUser = new IdentityUser();
            var LoginUser = await userManager.FindByNameAsync(credentials.Username);
            if(LoginUser == null)
            {
                identityUser = await userManager.FindByEmailAsync(credentials.Username);
            }
            else
            {
                identityUser=await userManager.FindByNameAsync(credentials.Username);
            }
            if (identityUser != null)
            {
                var result = userManager.PasswordHasher.VerifyHashedPassword(identityUser, identityUser.PasswordHash, credentials.Password);
                return result == PasswordVerificationResult.Failed ? null : identityUser;
            }
            return null;
        }
        #endregion


        #region GenerateToken
        private TokenClass GenerateToken(IdentityUser identityUser, List<string> UserRoles)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(jwtBearerTokenSettings.SecretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, identityUser.UserName.ToString()),
                    new Claim(ClaimTypes.Email, identityUser.Email),
                    new Claim(ClaimTypes.NameIdentifier, identityUser.Id),
                    new Claim(ClaimTypes.Role,string.Join(",",UserRoles))
                }),

                Expires = DateTime.UtcNow.AddSeconds(jwtBearerTokenSettings.ExpiryTimeInSeconds),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = jwtBearerTokenSettings.Audience,
                Issuer = jwtBearerTokenSettings.Issuer
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
           
           var val= tokenHandler.WriteToken(token).ToString();
           
            var expTime = DateTime.UtcNow.AddSeconds(jwtBearerTokenSettings.ExpiryTimeInSeconds).ToLocalTime();
            TokenClass tokenClass = new TokenClass();
            tokenClass.token = val;
            tokenClass.exptime = expTime;
            return tokenClass;
        }

        #endregion

        #region RefreshToken
        private object RefreshToken(IdentityUser identityUser, List<string> UserRoles)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(jwtBearerTokenSettings.SecretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, identityUser.UserName.ToString()),
                    new Claim(ClaimTypes.Email, identityUser.Email),
                    new Claim(ClaimTypes.NameIdentifier, identityUser.Id),
                    new Claim(ClaimTypes.Role,string.Join(",",UserRoles))
                }),

                Expires = DateTime.UtcNow.AddSeconds(jwtBearerTokenSettings.ExpiryTimeInSeconds),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = jwtBearerTokenSettings.Audience,
                Issuer = jwtBearerTokenSettings.Issuer
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return  tokenHandler.WriteToken(token).ToString();

           
         
        }

        #endregion

    }
}
