using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Service.Common
{
    public static class ContextSeed
    {
        public static async Task SeedRolesAsync(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            //Seed Roles
            await roleManager.CreateAsync(new IdentityRole(Common.Roles.SuperAdmin.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Common.Roles.Admin.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Common.Roles.Moderator.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Common.Roles.Basic.ToString()));
        }
    }
}
