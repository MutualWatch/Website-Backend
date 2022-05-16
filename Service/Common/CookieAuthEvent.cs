using Microsoft.AspNetCore.Authentication.Cookies;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Service.Common
{
    public class CookieAuthEvent : CookieAuthenticationEvents
    {
        public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
        {
            context.Request.HttpContext.Items.Add("ExpiresUTC", context.Properties.ExpiresUtc);
        }
    }
}
