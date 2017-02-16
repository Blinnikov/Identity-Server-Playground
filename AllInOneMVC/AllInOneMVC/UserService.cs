using System.Collections.Generic;
using System.Threading.Tasks;

using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services.Default;
using IdentityServer3.Core.Services.InMemory;

namespace AllInOneMVC {
    public class UserService : InMemoryUserService {
        public UserService(List<InMemoryUser> users) : base(users) {}

        public override Task PreAuthenticateAsync(PreAuthenticationContext context) {
            // context.SignInMessage.IdP = "windows";

            return base.PreAuthenticateAsync(context);
        }

        public override Task AuthenticateExternalAsync(ExternalAuthenticationContext context) {
            return base.AuthenticateExternalAsync(context);
        }

        public override Task AuthenticateLocalAsync(LocalAuthenticationContext context) {
            return base.AuthenticateLocalAsync(context);
        }
    }
}