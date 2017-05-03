using Nancy;
using System; 
using Cmas.Infrastructure.ErrorHandler;
using Nancy.Security;
using System.Security.Claims;

namespace Cmas.Infrastructure.Security
{
    public static class SecurityHooks
    {
        public static Response RequiresAuthentication(NancyContext ctx)
        {
            if (!ctx.CurrentUser.IsAuthenticated())
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


        public static Response RequiresRoles(NancyContext ctx, Role[] roles)
        {
            if (roles.Length == 0)
                throw new ArgumentException("roles");

            var claims = new Predicate<Claim>[roles.Length];

            int i = 0;
            foreach (var role in roles)
            {
                 
                claims[i++] = new Predicate<Claim>((p) =>
                {
                    return p.Type == ClaimTypes.Role.ToString() && p.Value == role.ToString().ToUpper();
                });
            }

            if (!ctx.CurrentUser.HasClaims(claims))
                throw new ForbiddenErrorException();
            else
                return null;
        }
    }
}
