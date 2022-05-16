using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using Service.ViewModels;
using System.ComponentModel.DataAnnotations;

namespace MutualWatch.Controller
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private RoleManager<IdentityRole> roleManager;

        public RoleController(RoleManager<IdentityRole> roleMgr)
        {
            this.roleManager = roleMgr;
        }
        [HttpPost]
        [Route("CreateRole")]
        public async Task<IActionResult> AddNewRole([Required] string roleName)
        {
            if (!ModelState.IsValid || roleName == null)
            {
                return new BadRequestObjectResult(new { Message = "Role Creation Failed" });
            }


            var identityUser = new IdentityRole() { Name = roleName };
            var result = await roleManager.CreateAsync(identityUser);
            if (!result.Succeeded)
            {
                var dictionary = new ModelStateDictionary();
                foreach (IdentityError error in result.Errors)
                {
                    dictionary.AddModelError(error.Code, error.Description);
                }

                return new BadRequestObjectResult(new { Message = "Role Creation Failed", Errors = dictionary });
            }

            return Ok(new { Message = "Role Creation Successful" });
        }
        [HttpGet]
        [Route("GetRoles")]
        public async Task<IActionResult> GetRoles()
        {
            Response response = new Response();
            var roles = await roleManager.Roles.ToListAsync();
            if (roles == null)
            {
               
                response.Success = false;
                response.error.errorCode = 401;
                response.error.errorMessage = "UserName doesn't exists";
            }
            else
            {
                response.Success = true;
                response.Message = "List Available.";
                response.Data = roles;
            }
            return Ok(response);
        }
    }
}
