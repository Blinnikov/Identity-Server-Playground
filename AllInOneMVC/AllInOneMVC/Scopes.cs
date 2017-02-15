using System.Collections.Generic;

using IdentityServer3.Core.Models;

namespace AllInOneMVC {
    public static class Scopes {
        public static IEnumerable<Scope> Get() {
            var scopes = new List<Scope> {
                new Scope {
                    Enabled = true,
                    Name = "roles",
                    Type = ScopeType.Identity,
                    Claims = new List<ScopeClaim> {
                        new ScopeClaim("role")
                    }
                }
            };

            scopes.AddRange(StandardScopes.All);

            return scopes;
        }
    }
}
