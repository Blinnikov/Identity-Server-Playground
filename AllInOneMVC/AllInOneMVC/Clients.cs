﻿using System.Collections.Generic;

using IdentityServer3.Core.Models;

namespace AllInOneMVC {
    public static class Clients {
        public static IEnumerable<Client> Get() {
            return new[] {
                new Client {
                    Enabled = true,
                    ClientName = "MVC Client",
                    ClientId = "mvc",
                    RequireConsent = false,
                    Flow = Flows.Implicit,

                    RedirectUris = new List<string> {
                        "https://localhost:44319/"
                    },
                    PostLogoutRedirectUris = new List<string> {
                        "https://localhost:44319/"
                    },

                    AllowAccessToAllScopes = true
                }
            };
        }
    }
}