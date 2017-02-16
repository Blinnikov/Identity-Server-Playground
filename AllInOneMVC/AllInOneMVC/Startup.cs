using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web.Helpers;

using IdentityServer.WindowsAuthentication.Configuration;

using IdentityServer3.Core;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Services.InMemory;

using IdSrv.Shared;

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.WsFederation;

using Owin;

namespace AllInOneMVC {
    public class Startup {
        public void Configuration(IAppBuilder app) {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = Constants.ClaimTypes.Subject;
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.Map("/windows", this.ConfigureWindowsTokenProvider);

            var factory = new IdentityServerServiceFactory()
                // .UseInMemoryUsers(Users.Get())
                .UseInMemoryClients(Clients.Get())
                .UseInMemoryScopes(Scopes.Get());

            // factory.UserService = new Registration<IUserService>(context => new UserService(Users.Get()));

            factory.Register(new Registration<List<InMemoryUser>>(Users.Get()));
            factory.UserService = new Registration<IUserService, UserService>();

            var identityServerOptions = new IdentityServerOptions {
                // RequireSsl = false,
                SiteName = "Embedded IdentityServer",
                SigningCertificate = Certificate.Get(),

                Factory = factory,

                AuthenticationOptions = new AuthenticationOptions {
                    // EnableLocalLogin = false,
                    
                    EnablePostSignOutAutoRedirect = true,
                    IdentityProviders = this.ConfigureIdentityProviders
                }
            };

            app.Map("/identity", idsrvApp => {
                idsrvApp.UseIdentityServer(identityServerOptions);
            });

            app.UseResourceAuthorization(new AuthorizationManager());

            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                Authority = "https://localhost:44319/identity",
                ClientId = "mvc",
                Scope = "openid profile roles",
                RedirectUri = "https://localhost:44319/",
                ResponseType = "id_token",

                SignInAsAuthenticationType = "Cookies",
                UseTokenLifetime = false,

                Notifications = new OpenIdConnectAuthenticationNotifications {
                    SecurityTokenValidated = n =>
                    {
                        var id = n.AuthenticationTicket.Identity;

                        // we want to keep first name, last name, subject and roles
                        var givenName = id.FindFirst(Constants.ClaimTypes.GivenName);
                        var familyName = id.FindFirst(Constants.ClaimTypes.FamilyName);
                        var sub = id.FindFirst(Constants.ClaimTypes.Subject);
                        var roles = id.FindAll(Constants.ClaimTypes.Role);

                        // create new identity and set name and role claim type
                        var nid = new ClaimsIdentity(
                            id.AuthenticationType,
                            Constants.ClaimTypes.GivenName,
                            Constants.ClaimTypes.Role);

                        //nid.AddClaim(givenName);
                        //nid.AddClaim(familyName);
                        //nid.AddClaim(sub);
                        //nid.AddClaims(roles);

                        // add some other app specific claim
                        nid.AddClaim(new Claim("app_specific", "some data"));

                        nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                        //n.AuthenticationTicket = new AuthenticationTicket(
                        //    nid,
                        //    n.AuthenticationTicket.Properties);

                        return Task.FromResult(0);
                    },
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest) {
                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                            if (idTokenHint != null) {
                                n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                            }
                        }

                        return Task.FromResult(0);
                    }
                }
            });
        }

        private void ConfigureIdentityProviders(IAppBuilder app, string signInAsType) {
            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions {
                AuthenticationType = "Google",
                Caption = "Sign-in with Google",
                SignInAsAuthenticationType = signInAsType,

                ClientId = "658080129204-2osr9ots9lnmhnr0hi1niekb9bsrke76.apps.googleusercontent.com",
                ClientSecret = "2SZ8dGRyuyT6qykVoD-mFeVE"
            });

            var wsFederation = new WsFederationAuthenticationOptions {
                AuthenticationType = "windows",
                Caption = "Windows",
                SignInAsAuthenticationType = signInAsType,

                MetadataAddress = "https://localhost:44319/windows",
                Wtrealm = "urn:idsrv3"
            };
            app.UseWsFederationAuthentication(wsFederation);
        }

        X509Certificate2 LoadCertificate() {
            return new X509Certificate2($@"{AppDomain.CurrentDomain.BaseDirectory}\bin\IdentityServer.pfx", "IdentityServer");
        }

        private void ConfigureWindowsTokenProvider(IAppBuilder app) {
            app.UseWindowsAuthenticationService(new WindowsAuthenticationOptions {
                IdpRealm = "urn:idsrv3",
                IdpReplyUrl = "https://localhost:44319/identity",
                SigningCertificate = Certificate.Get(),
                EmitGroups = true
            });
        }
    }
}
