using System;
using System.Security.Claims;
using Nancy.Security;

namespace Cmas.Infrastructure.Security
{
    public static class ClaimsPrincipalHelper
    {
        public static bool HasAnyRole(this ClaimsPrincipal claimsPrincipal, Role[] roles)
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

            return claimsPrincipal.HasAnyClaim(claims);
        }
    }
}
