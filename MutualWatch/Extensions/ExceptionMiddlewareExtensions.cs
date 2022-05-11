using Microsoft.AspNetCore.Diagnostics;
using Service.ViewModels;
using System.Net;

namespace MutualWatch.Extensions
{
    public static class ExceptionMiddlewareExtensions
    {
        public static void ConfigureExceptionHandler(this IApplicationBuilder app, ILogger logger)
        {
            app.UseExceptionHandler(appError =>
            {
                appError.Run(async context =>
                {
                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    context.Response.ContentType = "application/json";
                    var contextFeature = context.Features.Get<IExceptionHandlerFeature>();
                    if (contextFeature != null)
                    {
                        logger.LogError($"Something went wrong: {contextFeature.Error}");
                        await context.Response.WriteAsync(new Response(MESSAGE.SAVED)
                        {
                            Message = "Internal Server Error." + contextFeature.Error.Message,
                            Success = false
                        }.ToString());
                    }
                });
            });
        }
    }
}