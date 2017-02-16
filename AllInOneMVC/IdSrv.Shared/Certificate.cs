using System.Security.Cryptography.X509Certificates;

namespace IdSrv.Shared
{
    public static class Certificate {
        public static X509Certificate2 Get() {
            return new X509Certificate2(Resources.Certificate, "IdentityServer");
        }
    }
}
