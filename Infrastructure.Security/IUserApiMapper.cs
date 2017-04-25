using System.Security.Claims; 

namespace Cmas.Infrastructure.Security
{
    public interface IUserApiMapper
    {
        ClaimsPrincipal GetUserFromAccessToken(string jwtToken);
    }
}
