using JWTLib;
using Microsoft.IdentityModel.Logging;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace JWTLibTest
{
    class Program
    {
        static void RSA()
        {
            JWTClient client = new JWTClient(AlgType.RSA, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha384, 2, 2048);

            string jwksPublic = client.PublicJWKS.ToJSON();
            string jwksPrivate = client.PrivatePKWS.ToJSON();

            string kid = client.PrivatePKWS.keys.LastOrDefault().Kid;

            string jwt = JWTClient.GenerateJWTRSA("audience", "issuer", string.Empty, jwksPrivate, kid, new List<System.Security.Claims.Claim>() { new Claim("custom", Guid.NewGuid().ToString()) });

            IPrincipal principal = JWTServer.ValidateToken(jwt, jwksPublic, kid);
        }

        static void EC()
        {
            JWTClient clientEC = new JWTClient(AlgType.EC, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha384, 1, 384);
            string jwksPublic1 = clientEC.PublicJWKS.ToJSON();
            string jwksPrivate1 = clientEC.PrivatePKWS.ToJSON();
            string kid1 = clientEC.PrivatePKWS.keys.LastOrDefault().Kid;
            string jwt1 = JWTClient.GenerateJWTEC("audience",
               "issuer",
               string.Empty,
               jwksPrivate1,
               kid1,
               new List<System.Security.Claims.Claim>() { new Claim("custom", Guid.NewGuid().ToString()) });

            IPrincipal principal1 = JWTServer.ValidateToken(jwt1, jwksPublic1, kid1);
        }

        static void X509()
        {
            var privateKey = new X509Certificate2(@"C:\tmp\t\star.mysite2.com.pfx", "!QAZ2wsx", X509KeyStorageFlags.Exportable);
            JWTClient clientX509 = new JWTClient(new List<X509Certificate2> { privateKey });
            string jwksPublic1 = clientX509.PublicJWKS.ToJSON();
            string jwksPrivate1 = clientX509.PrivatePKWS.ToJSON();
            string kid1 = clientX509.PrivatePKWS.keys.LastOrDefault().Kid;

            string jwt1 = JWTClient.GenerateJWTX509(privateKey,
               "audience",
               "issuer",
               string.Empty,
               jwksPrivate1,
               kid1,
               new List<System.Security.Claims.Claim>() { new Claim("custom", Guid.NewGuid().ToString()) });
            IPrincipal principal2 = JWTServer.ValidateToken(jwt1, jwksPublic1, kid1);
        }


        static void Main(string[] args)
        {
            IdentityModelEventSource.ShowPII = true;
            X509();

            EC();

            RSA();

            //TestE2E();
            //TestURLBased();
        }

        static void TestE2E()
        {
            string jwksPrivate = File.ReadAllText(@"c:\projects\JWTLib\JWTLibTest\RS384.private.json");
            string jwksPublic = File.ReadAllText(@"c:\projects\JWTLib\JWTLibTest\RS384.public.json");

            MyJWK jwk = Utility.FindRandomPrivateJWKFromJWKS(jwksPrivate);

            string jwt = JWTClient.GenerateJWTRSA("audience",
                "issuer",
                string.Empty,
                jwksPrivate,
                jwk.Kid,
                new List<System.Security.Claims.Claim>() { new Claim("custom", Guid.NewGuid().ToString()) });

            JwtSecurityToken token = new JwtSecurityToken(jwt);

            if (token != null && token.Header.ContainsKey("kid"))
            {
                string kid = token.Header["kid"].ToString();
                IPrincipal principal = JWTServer.ValidateToken(jwt, jwksPublic, kid);
            }
        }

        static void TestURLBased()
        {
            string jwksPrivate = File.ReadAllText(@"c:\projects\JWTLib\JWTLibTest\RS384.private.json");

            MyJWK jwk = Utility.FindRandomPrivateJWKFromJWKS(jwksPrivate);

            string jwt = JWTClient.GenerateJWTRSA("audience",
                "issuer",
                "http://jwks.arundev.inetxperts.net/RS384.public.json",
                jwksPrivate,
                jwk.Kid,
                new List<System.Security.Claims.Claim>() { new Claim("custom", Guid.NewGuid().ToString()) });

            JwtSecurityToken token = new JwtSecurityToken(jwt);


            if (token != null
                && token.Header.ContainsKey("kid")
                && token.Header.ContainsKey("jku"))
            {
                string jwksPublic = JWTServer.GetJWKSFromJKU(token.Header["jku"].ToString());

                string kid = token.Header["kid"].ToString();
                IPrincipal principal = JWTServer.ValidateToken(jwt, jwksPublic, kid);
            }
        }
    }
}
