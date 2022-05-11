using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;

namespace MutualWatch.Extensions
{
    //{
    //    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    //    public class AuthorizeAttribute : Attribute, IAuthorizationFilter
    //    {
    //        public void OnAuthorization(AuthorizationFilterContext context)
    //        {
    //            if (context.ActionDescriptor.EndpointMetadata.OfType<AllowAnonymousAttribute>().Any()) return;//AllowAnonymous return
    //            var validate = context.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier);
    //            if (validate == null)
    //            {
    //                context.Result = new JsonResult(new { message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized };
    //            }
    //        }
    //    }
    public class AuthorizeAttribute : TypeFilterAttribute
    {
        public AuthorizeAttribute(params string[] claim) : base(typeof(AuthorizeFilter))
        {
            Arguments = new object[] { claim };
           
        }

    }

    public class AuthorizeFilter : IAuthorizationFilter
    {
        readonly string[] _claim;
       // private string[] UserProfilesRequired { get; set; }


        public AuthorizeFilter(params string[] claim)
        {
            

            _claim = claim;
        }



        public void OnAuthorization(AuthorizationFilterContext context)
        {

            var IsAuthenticated = context.HttpContext.User.Identity.IsAuthenticated;
            var claimsIndentity = context.HttpContext.User.Identity as ClaimsIdentity;
            
            if (context.ActionDescriptor.EndpointMetadata.OfType<AllowAnonymousAttribute>().Any()) return;
           
            foreach (var role in this._claim)
            {
                if (context.HttpContext.User.IsInRole(role))
                {
                    IsAuthenticated = true;
                    return;
                }
                else
                {
                    IsAuthenticated = false;
                    context.Result = new UnauthorizedObjectResult(new { message = "401 Unauthorized" });
                }
            }
               

            if (!IsAuthenticated)
            {
                //context.Result = new UnauthorizedObjectResult(new { message = "401 Unauthorized" });
                context.Result = new ContentResult()
                {
                    Content = "Session is Expired!!",
                    StatusCode = 203
                };
            }



           
            return;
        }
    }

}
