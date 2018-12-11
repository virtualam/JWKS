using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace JWTLib
{
    public class JWTServer
    {
        public static string GetJWKSFromJKU(string url)
        {
            string jkws = string.Empty;
            using (WebClient wc = new WebClient())
            {
                jkws = wc.DownloadString(url);
            }

            return jkws;
        }

        public static IPrincipal ValidateTokenRSA(string jwt, string jwksJSON, string kid)
        {
            IPrincipal principal = null;
            string jwk = Utility.FindJWKFromJWKS(true, jwksJSON, kid);
            MyJWK publicJWK = MyJWK.Parse(jwk);
            RSAParameters publicRSAParams = new RSAParameters
            {
                Exponent = Base64UrlEncoder.DecodeBytes(publicJWK.E),
                Modulus = Base64UrlEncoder.DecodeBytes(publicJWK.N)
            };


            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicRSAParams);

                var signingKey = new RsaSecurityKey(rsa);

                var validationParameters = getValidationParameters(signingKey);

                var handler = new JwtSecurityTokenHandler();

                SecurityToken validatedToken;
                principal = handler.ValidateToken(jwt, validationParameters, out validatedToken);
            }

            return principal;
        }

        public static IPrincipal ValidateToken(string jwt, string jwksJSON, string kid)
        {
            IPrincipal principal = null;
            string strjwk = Utility.FindJWKFromJWKS(true, jwksJSON, kid);
            MyJWK publicJWK = MyJWK.Parse(strjwk);
            JsonWebKey jwk = new JsonWebKey(strjwk);

            var validationParameters = getValidationParameters(jwk);

            var handler = new JwtSecurityTokenHandler();
            
            SecurityToken validatedToken;
            principal = handler.ValidateToken(jwt, validationParameters, out validatedToken);

            return principal;
        }

        private static TokenValidationParameters getValidationParameters(SecurityKey key)
        {
            return new TokenValidationParameters()
            {
                IssuerSigningKey = key,
                ValidateAudience = false,
                ValidateIssuer = false
            };
        }
    }
}
