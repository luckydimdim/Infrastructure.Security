using Nancy;
using System;
using System.Linq;
using Cmas.Infrastructure.ErrorHandler;
using Nancy.Security;
using System.Security.Claims;

namespace Cmas.Infrastructure.Security
{
    public static class SecurityHooks
    {
        public static Response RequiresAuthentication(NancyContext ctx)
        {
            if (!ctx.CurrentUser.IsAuthenticated() || !ctx.CurrentUser.Claims.Any(c=>c.Type == ClaimTypes.Role))
                throw new UnauthorizedErrorException();
            else
                return null;
        }

        public static Response RequiresClaims(NancyContext ctx, params Predicate<Claim>[] claims)
        {
            if (!ctx.CurrentUser.HasClaims(claims))
                throw new ForbiddenErrorException();
            else
                return null;
        }
         
        public static Response RequiresAnyRole(NancyContext ctx, Role[] roles)
        { 
            if (!ctx.CurrentUser.HasAnyRole(roles))
                throw new ForbiddenErrorException();
            else
                return null;
        }
    }
}
