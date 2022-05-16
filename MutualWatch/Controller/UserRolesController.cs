using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

using Service.Models;
using Service.ViewModels;

namespace MutualWatch.Controller
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserRolesController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public UserRolesController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }
        [HttpGet]
        [Route("GetUR")]
        public async Task<IActionResult> GetUR()
        {
            Response response = new Response();
            var users = await _userManager.Users.ToListAsync();
            var userRolesViewModel = new List<UserRolesViewModel>();
            foreach (IdentityUser user in users)
            {
                var thisViewModel = new UserRolesViewModel();
                thisViewModel.UserId = user.Id;
                thisViewModel.Email = user.Email;
                thisViewModel.UserName = user.UserName;
               
                thisViewModel.Roles = await GetUserRoles(user);
                userRolesViewModel.Add(thisViewModel);
            }

            if (userRolesViewModel != null)
            {
                response.Success = false;
                response.error.errorCode = 401;
                response.error.errorMessage = "UserRoles doesn't exists";
            }
            else
            {
                response.Success = true;
                response.Message = "List Available.";
                response.Data = userRolesViewModel;
            }
            return Ok(response);
        }
        private async Task<List<string>> GetUserRoles(IdentityUser user)
        {
            return new List<string>(await _userManager.GetRolesAsync(user));
        }
        [HttpGet]
        public async Task<IActionResult> Manage(string userId)
        {
            //view.userId = userId;
            Response response = new Response();
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                response.Success = false;
                response.error.errorCode = 401;
                response.error.errorMessage = "This User Does Not Exists.";
            }
            //ViewBag.UserName = user.UserName;
            var model = new List<ManageUserRolesViewModel>();
            foreach (var role in _roleManager.Roles)
            {
                var userRolesViewModel = new ManageUserRolesViewModel
                {
                    RoleId = role.Id,
                    RoleName = role.Name
                };
                if (await _userManager.IsInRoleAsync(user, role.Name))
                {
                    userRolesViewModel.Selected = true;
                }
                else
                {
                    userRolesViewModel.Selected = false;
                }
                model.Add(userRolesViewModel);
                response.Success = true;
                response.Message = "Selected Role Of User in list are available.";
                response.Data = userRolesViewModel;
            }
            return Ok(response);
            
        }

        [HttpPost]
        [Route("Manage")]
        public async Task<IActionResult> Manage(List<ManageUserRolesViewModel> model, string userId)
        {
            Response response = new Response();
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                response.Success = false;
                response.error.errorCode = 401;
                response.error.errorMessage = "UserRoles doesn't exists";
            }
            var roles = await _userManager.GetRolesAsync(user);
            var result = await _userManager.RemoveFromRolesAsync(user, roles);
            if (!result.Succeeded)
            {
                response.Success = false;
                response.error.errorCode = 401;
                response.error.errorMessage = "Cannot remove user existing roles";
                
            }
            result = await _userManager.AddToRolesAsync(user, model.Where(x => x.Selected).Select(y => y.RoleName));
            if (!result.Succeeded)
            {
                response.Success = false;
                response.error.errorCode = 401;
                response.error.errorMessage = "Cannot add selected roles to user";
                
            }
            else
            {
                response.Success = true;
                response.Message = "List Available.";
                response.Data = result;
            }
            return Ok(response);
        }
    }
}
