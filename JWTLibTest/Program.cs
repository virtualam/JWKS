using JWTLib;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace JWTLibTest
{
    class Program
    {
        static void Main(string[] args)
        {
            JWTClient client = new JWTClient(2);

            string jwksPublic = client.PublicJWKS.ToJSON();
            string jwksPrivate = client.PrivatePKWS.ToJSON();

            string kid = client.PrivatePKWS.keys.LastOrDefault().Kid;

            string jwt = JWTClient.GenerateJWT("audience", "issuer", jwksPrivate, kid, new List<System.Security.Claims.Claim>() { new Claim("custom", Guid.NewGuid().ToString()) });

            IPrincipal principal = JWTServer.ValidateToken(jwt, jwksPublic, kid);

            TestE2E();
            TestURLBased();
        }

        static void TestE2E()
        {
            string jwksPrivate = File.ReadAllText(@"c:\projects\JWTLib\JWTLibTest\RS384.private.json");
            string jwksPublic = File.ReadAllText(@"c:\projects\JWTLib\JWTLibTest\RS384.public.json");

            MyJWK jwk = Utility.FindRandomPrivateJWKFromJWKS(jwksPrivate);

            string jwt = JWTClient.GenerateJWT("audience", 
                "issuer", 
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
            string jwksPublic = JWTServer.GetJWKSFromJKU("http://jwks.arundev.inetxperts.net/RS384.public.json");

            MyJWK jwk = Utility.FindRandomPrivateJWKFromJWKS(jwksPrivate);

            string jwt = JWTClient.GenerateJWT("audience",
                "issuer",
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
    }
}
