using Nancy;
using Nancy.Extensions;
using System;
using System.Linq;
using System.Security.Claims;

namespace Cmas.Infrastructure.Security
{
    public static class ModuleSecurity
    {
        /// <summary>This module requires authentication</summary>
        /// <param name="module">Module to enable</param>
        public static void RequiresAuthentication(this INancyModule module, string[] except = null)
        {
            module.AddBeforeHookOrExecute((ctx =>
            {
                if (except != null && except.Contains(ctx.ResolvedRoute.Description.Name))
                    return null;

                return SecurityHooks.RequiresAuthentication(ctx);
            }), "Requires Authentication");
        }

        /// <summary>
        /// This module requires authentication and certain claims to be present.
        /// </summary>
        /// <param name="module">Module to enable</param>
        /// <param name="requiredClaims">Claim(s) required</param>
        public static void RequiresClaims(this INancyModule module, string[] except = null,
            params Predicate<Claim>[] requiredClaims)
        {
            module.AddBeforeHookOrExecute((ctx =>
            {
                if (except != null && except.Contains(ctx.ResolvedRoute.Description.Name))
                    return null;

                return SecurityHooks.RequiresAuthentication(ctx);
            }), "Requires Authentication");

            module.AddBeforeHookOrExecute((ctx =>
            {
                if (except != null && except.Contains(ctx.ResolvedRoute.Description.Name))
                    return null;

                return SecurityHooks.RequiresClaims(ctx, requiredClaims);
            }), "Requires Claims");
        }

        public static void RequiresAnyRole(this INancyModule module, Role[] requiredRoles, string[] except = null)
        {
            module.AddBeforeHookOrExecute((ctx =>
            {
                if (except != null && except.Contains(ctx.ResolvedRoute.Description.Name))
                    return null;

                return SecurityHooks.RequiresAuthentication(ctx);
            }), "Requires Authentication");

            module.AddBeforeHookOrExecute((ctx =>
            {
                if (except != null && except.Contains(ctx.ResolvedRoute.Description.Name))
                    return null;

                return SecurityHooks.RequiresAnyRole(ctx, requiredRoles);
            }), "Requires Claims");
        }
    }
}