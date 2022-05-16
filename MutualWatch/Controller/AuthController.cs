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

using Service.DbModels;
using Service.Data;
using System.Net.Mail;

using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Service.Common;
using Newtonsoft.Json;
using System.Net;
using Google.Apis.Auth;

namespace MutualWatch.Controller
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly JwtBearerTokenSettings jwtBearerTokenSettings;
        private readonly UserManager<IdentityUser> userManager;
        private RoleManager<IdentityRole> roleManager;
        private readonly UsersDbContext userDbContext;
        public AuthController(IOptions<JwtBearerTokenSettings> jwtTokenOptions, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> _roleManager, UsersDbContext userDbContext)
        {
            this.userManager = userManager;
            this.roleManager = _roleManager;
            jwtBearerTokenSettings = jwtTokenOptions.Value;
            this.userDbContext = userDbContext;
        }

        [HttpPost]
        public async Task<IActionResult> FacebookLogin([FromBody] string accessToken)
        {
            // 1.generate an app access token
            Response res = new Response();
            HttpClient client = new HttpClient();
            // 3. we've got a valid token so we can request user data from fb
            var userInfoResponse = await client.GetStringAsync($"https://graph.facebook.com/v2.8/me?fields=id,email,first_name,last_name,name&access_token={accessToken}");
            var userInfo = JsonConvert.DeserializeObject<FacebookUserData>(userInfoResponse);

            var identityUser = new IdentityUser() { UserName = userInfo.FirstName + userInfo.LastName, Email = userInfo.Email, EmailConfirmed = true };
            TokenClass tokenClass = new TokenClass();
            tokenClass = GenerateToken(identityUser, (await userManager.GetRolesAsync(identityUser)).ToList());
            var isexist = userManager.Users.FirstOrDefault(x => x.Id == identityUser.Id);
            if (isexist == null)
            {
                var result = await userManager.CreateAsync(identityUser);
                if (!result.Succeeded)
                {
                    var dictionary = new ModelStateDictionary();
                    foreach (IdentityError error in result.Errors)
                    {
                        dictionary.AddModelError(error.Code, error.Description);
                    }

                    return new BadRequestObjectResult(new { Message = "User Registration Failed", Errors = dictionary });
                }
                else
                {
                    res.Data = new
                    {
                        UserID = identityUser.Id,
                        UserName = identityUser.UserName,
                        Email = identityUser.Email,
                        Token = tokenClass.token,
                        ExpTime = tokenClass.exptime
                    };
                    res.Message = "User Reigstration Successful";
                    res.Success = true;
                    return Ok(res);
                }
            }
            else
            {
                res.Message = "User Existed";
                res.Success = false;
                return Ok(res);
            }


        }

        #region Register
        [HttpPost]
            [Route("Register")]
            public async Task<IActionResult> Register([FromBody] UserDetails userDetails)
            {
                Response response = new Response();
                if (!ModelState.IsValid || userDetails == null)
                {
                    return new BadRequestObjectResult(new { Message = "User Registration Failed" });
                }
                if (IsValidEmail(userDetails.Email))
                {
                    var identityUser = new IdentityUser() { UserName = userDetails.Firstname + userDetails.Lastname, Email = userDetails.Email };
                    TokenClass tokenClass = new TokenClass();
                    tokenClass = GenerateToken(identityUser, (await userManager.GetRolesAsync(identityUser)).ToList());
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



                    #region CheckRoleIfExist
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


                    response.Data = new
                    {
                        UserID = identityUser.Id,
                        UserName = identityUser.UserName,
                        Email = identityUser.Email,
                        Token = tokenClass.token,
                        ExpTime = tokenClass.exptime
                    };
                    response.Message = "User Reigstration Successful";
                    response.Success = true;
                }
                else
                {
                    response.Message = "Invalid Email.";
                    response.Success = false;
                }
                return Ok(response);
            }
            #endregion

            #region IsValidEmail
            [HttpGet]
            public bool IsValidEmail(string emailaddress)
            {
                try
                {
                    MailAddress m = new MailAddress(emailaddress);
                    return true;
                }
                catch (FormatException)
                {
                    return false;
                }
            }
            #endregion

            #region Login
            [HttpPost]
            [Route("Login")]
            public async Task<IActionResult> Login([FromBody] LoginCredentials credentials)
            {
                Response response = new Response();
                try
                {
                    IdentityUser identityUser;

                    if (!ModelState.IsValid || credentials == null || (identityUser = await ValidateUser(credentials)) == null)
                    {
                        return new BadRequestObjectResult(new { Message = "Login failed.Please Register,User Does not Exists." });
                    }
                    var val = userManager.GetRolesAsync(identityUser);
                    TokenClass tokenClass = new TokenClass();
                    tokenClass = GenerateToken(identityUser, (await userManager.GetRolesAsync(identityUser)).ToList());
                    //var result = await _signInManager.PasswordSignInAsync(userName, Input.Password, Input.RememberMe, lockoutOnFailure: false);
                    var refreshToken = RefreshToken(identityUser, (await userManager.GetRolesAsync(identityUser)).ToList());
                    RefreshValue refreshToken1 = new RefreshValue();
                    //refreshToken1.Id = 1;
                    refreshToken1.UserId = identityUser.Id;
                    refreshToken1.RefreshToken = refreshToken;
                    var data = await userDbContext.RefreshValues.AddAsync(refreshToken1);
                    bool hasChanges = userDbContext.ChangeTracker.HasChanges();
                    await userDbContext.SaveChangesAsync();



                    response.Data = new
                    {
                        UserId = identityUser.Id,
                        UserName = identityUser.UserName,
                        Email = identityUser.Email,
                        Token = tokenClass.token,
                        ExpTime = tokenClass.exptime,
                        RefreshToken = refreshToken,
                        Roles = val
                    };
                    response.Success = true;
                    response.Message = "Login Succesfull.";
                    return Ok(response);
                }
                catch (Exception ex)
                {
                    response.Message = ex.Message;
                    return Ok(response.Message);
                }

            }
            #endregion

            #region ValidateUser
            private async Task<IdentityUser> ValidateUser(LoginCredentials credentials)
            {
                var identityUser = new IdentityUser();
                var LoginUser = await userManager.FindByNameAsync(credentials.Username);
                if (LoginUser == null)
                {
                    identityUser = await userManager.FindByEmailAsync(credentials.Username);
                }
                else
                {
                    identityUser = await userManager.FindByNameAsync(credentials.Username);
                }
                if (identityUser != null)
                {
                    var result = userManager.PasswordHasher.VerifyHashedPassword(identityUser, identityUser.PasswordHash, credentials.Password);
                    return result == PasswordVerificationResult.Failed ? null : identityUser;
                }
                return null;
            }
            #endregion

            #region GetUsers
            [HttpGet]
            [Route("GetUsers")]
            [Authorize(Roles = "SuperAdmin,Admin")]
            public async Task<IActionResult> GetUsers()
            {
                Response res = new Response();
                var currentUser = await userManager.GetUserAsync(HttpContext.User);
                var allUsersExceptCurrentUser = await userManager.Users.Where(a => a.Id != currentUser.Id).ToListAsync();
                if (allUsersExceptCurrentUser != null)
                {
                    res.Success = true;
                    res.Message = "Displayed All Users.";
                    res.Data = new
                    {
                        currentUser = currentUser,
                        allUsersExceptCurrentUser = allUsersExceptCurrentUser,
                    };
                }
                else
                {
                    res.Success = false;
                    res.error.errorCode = 401;
                    res.error.errorMessage = "Users Not Found.";
                }
                return Ok(res);
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

                    Expires = DateTime.Now.AddSeconds(jwtBearerTokenSettings.ExpiryTimeInSeconds),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                    Audience = jwtBearerTokenSettings.Audience,
                    Issuer = jwtBearerTokenSettings.Issuer
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);

                var val = tokenHandler.WriteToken(token).ToString();

                var expTime = DateTime.UtcNow.AddSeconds(jwtBearerTokenSettings.ExpiryTimeInSeconds).ToLocalTime();
                TokenClass tokenClass = new TokenClass();
                tokenClass.token = val;
                tokenClass.exptime = expTime;
                return tokenClass;
            }

            #endregion

            #region RefreshToken
            private string RefreshToken(IdentityUser identityUser, List<string> UserRoles)
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

                    Expires = DateTime.Now.AddDays(7),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                    Audience = jwtBearerTokenSettings.Audience,
                    Issuer = jwtBearerTokenSettings.Issuer
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);

                return tokenHandler.WriteToken(token).ToString();



            }

            #endregion

            #region CheckRefreshtoken

            [HttpPost]
            [Route("CheckRefreshtoken")]
            public async Task<IActionResult> CheckRefreshtoken([FromQuery] string Token)
            {
                Response response = new Response();
                var storedtoken = userDbContext.RefreshValues.FirstOrDefault(x => x.RefreshToken == Token);
                if (storedtoken != null)
                {
                    var userdata = userManager.FindByIdAsync(storedtoken.UserId);
                    var newAccessToken = GenerateToken(userdata.Result, (await userManager.GetRolesAsync(userdata.Result)).ToList());
                    var newRefreshToken = RefreshToken(userdata.Result, (await userManager.GetRolesAsync(userdata.Result)).ToList());
                    var GetUserById = userDbContext.RefreshValues.FirstOrDefault(x => x.Id == storedtoken.Id);
                    //RefreshValue refreshToken1 = new RefreshValue();
                    //GetUserById.UserId = userdata.Result.Id;
                    GetUserById.RefreshToken = newRefreshToken;
                    var data = userDbContext.RefreshValues.Update(GetUserById);
                    bool hasChanges = userDbContext.ChangeTracker.HasChanges();
                    await userDbContext.SaveChangesAsync();
                    response.Message = "You are Logged In.";
                    response.Success = true;
                    response.Data = new
                    {
                        newRefreshToken = newRefreshToken,
                        newAccessToken = newAccessToken
                    };
                }
                else
                {
                    response.Success = false;
                    response.error.errorCode = 401;
                    response.error.errorMessage = "UserName doesn't exists";
                }
                return Ok(response);
            }
            #endregion

            #region LogOut
            [HttpPost]
            [Route("Logout")]
            public async Task<IActionResult> Logout(string accessToken)
            {
                // Well, What do you want to do here ?
                // Wait for token to get expired OR 
                // Maintain token cache and invalidate the tokens after logout method is called
                var token = accessToken;
                var handler = new JwtSecurityTokenHandler();
                var jwtSecurityToken = handler.ReadJwtToken(token);

                var UserId = jwtSecurityToken.Claims.SingleOrDefault(x => x.Type == "nameid").Value;
                if (UserId != null)
                {
                    var GetUser = userDbContext.RefreshValues.FirstOrDefault(x => x.UserId == UserId);
                    userDbContext.RefreshValues.Remove(GetUser);
                    bool hasChanges = userDbContext.ChangeTracker.HasChanges();
                    await userDbContext.SaveChangesAsync();
                }
                return Ok(new { Token = "", Message = "Logged Out" });
            }
            #endregion

            #region GetGoogleResponse
            [HttpGet]
            [Route("GetGoogleResponse")]
            public async Task<IActionResult> GetGoogleResponse(string idToken)
            {
                Response res = new Response();

                var validPayload = await GoogleJsonWebSignature.ValidateAsync(idToken);
                if (validPayload == null)
                {
                    res.error.errorCode = 302;
                    res.Message = "Google API Token Info aud field ({0}) not containing the required client id";

                    return Ok(res);
                }
                else
                {

                    res.Message = "DataObtained using response.";
                    res.Data = validPayload;
                    var identityUser = new IdentityUser() { UserName = validPayload.GivenName + validPayload.FamilyName, Email = validPayload.Email, EmailConfirmed = validPayload.EmailVerified };
                    TokenClass tokenClass = new TokenClass();
                    tokenClass = GenerateToken(identityUser, (await userManager.GetRolesAsync(identityUser)).ToList());
                    var isexist = userManager.Users.FirstOrDefault(x => x.Id == identityUser.Id);
                    if (isexist == null)
                    {
                        var result = await userManager.CreateAsync(identityUser);
                        if (!result.Succeeded)
                        {
                            var dictionary = new ModelStateDictionary();
                            foreach (IdentityError error in result.Errors)
                            {
                                dictionary.AddModelError(error.Code, error.Description);
                            }

                            return new BadRequestObjectResult(new { Message = "User Registration Failed", Errors = dictionary });
                        }
                        else
                        {
                            res.Data = new
                            {
                                UserID = identityUser.Id,
                                UserName = identityUser.UserName,
                                Email = identityUser.Email,
                                Token = tokenClass.token,
                                ExpTime = tokenClass.exptime
                            };
                            res.Message = "User Reigstration Successful";
                            res.Success = true;
                            return Ok(res);
                        }
                    }
                    else
                    {
                        res.Message = "User Existed";
                        res.Success = false;
                        return Ok(res);
                    }


                }
            }
        }
        #endregion

    } 



