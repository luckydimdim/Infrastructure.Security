using Nancy;
using Nancy.Extensions;
using System;
using System.Security.Claims;

namespace Cmas.Infrastructure.Security
{
    public static class ModuleSecurity
    {
        /// <summary>This module requires authentication</summary>
        /// <param name="module">Module to enable</param>
        public static void RequiresAuthentication(this INancyModule module)
        {
            module.AddBeforeHookOrExecute(SecurityHooks.RequiresAuthentication, "Requires Authentication");
        }

        /// <summary>
        /// This module requires authentication and certain claims to be present.
        /// </summary>
        /// <param name="module">Module to enable</param>
        /// <param name="requiredClaims">Claim(s) required</param>
        public static void RequiresClaims(this INancyModule module, params Predicate<Claim>[] requiredClaims)
        {
            module.AddBeforeHookOrExecute(SecurityHooks.RequiresAuthentication, "Requires Authentication");
            module.AddBeforeHookOrExecute(ctx => SecurityHooks.RequiresClaims(ctx, requiredClaims), "Requires Claims");
        }

        public static void RequiresRoles(this INancyModule module, Role[] requiredRoles)
        {
            module.AddBeforeHookOrExecute(SecurityHooks.RequiresAuthentication, "Requires Authentication");
            module.AddBeforeHookOrExecute(ctx => SecurityHooks.RequiresRoles(ctx, requiredRoles), "Requires Claims");
        }

    }
}