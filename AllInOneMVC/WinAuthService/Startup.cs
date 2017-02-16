using IdentityServer.WindowsAuthentication.Configuration;
using IdSrv.Shared;

using Owin;

namespace WinAuthService {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            app.UseWindowsAuthenticationService(new WindowsAuthenticationOptions {
                IdpRealm = "urn:idsrv3",
                // TODO: Extract to config
                IdpReplyUrl = "https://localhost:44319/identity",
                SigningCertificate = Certificate.Get(),
                EmitGroups = true
            });
        }
    }
}
