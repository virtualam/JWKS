using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JWTLib
{
    public class JWTClient
    {
        public MyJWKS PublicJWKS { get; private set; }

        public MyJWKS PrivatePKWS { get; private set; }
        public JWTClient(int iNumKeys)
        {
            List<MyJWK> listKeysPublic = new List<MyJWK>();
            List<MyJWK> listKeysPrivate = new List<MyJWK>();

            for (int i = 0; i < iNumKeys; i++)
            {
                MyJWK key = new MyJWK(true, SecurityAlgorithms.RsaSha384, 2048);


                string strJSONPublic = key.ToJSON(false);
                string strJSONPrivate = key.ToJSON(true);

                MyJWK publicJWK = MyJWK.Parse(strJSONPublic);
                MyJWK privateJWK = MyJWK.Parse(strJSONPrivate);

                listKeysPublic.Add(publicJWK);

                listKeysPrivate.Add(privateJWK);
            }

            PublicJWKS = new MyJWKS(listKeysPublic);
            PrivatePKWS = new MyJWKS(listKeysPrivate);
        }

        public static string GenerateJWT(string audience, string issuer, string privateJKWSJSON, string kid, List<Claim> additionalClaims)
        {
            string jwt = null;
            string jwks = Utility.FindJWKFromJWKS(false, privateJKWSJSON, kid);
            MyJWK privateJWK = MyJWK.Parse(jwks);

            RSAParameters privateRSAParams = new RSAParameters
            {
                D = Base64UrlEncoder.DecodeBytes(privateJWK.D),
                DP = Base64UrlEncoder.DecodeBytes(privateJWK.DP),
                DQ = Base64UrlEncoder.DecodeBytes(privateJWK.DQ),
                Exponent = Base64UrlEncoder.DecodeBytes(privateJWK.E),
                InverseQ = Base64UrlEncoder.DecodeBytes(privateJWK.QI),
                Modulus = Base64UrlEncoder.DecodeBytes(privateJWK.N),
                P = Base64UrlEncoder.DecodeBytes(privateJWK.P),
                Q = Base64UrlEncoder.DecodeBytes(privateJWK.Q),
            };

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateRSAParams);

                var signingKey = new RsaSecurityKey(rsa);

                var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha384);

                var header = new JwtHeader(signingCredentials);
                header.Add("kid", privateJWK.Kid);

                var now = DateTime.UtcNow;
                List<Claim> claims = new List<Claim>();
                claims.Add(new Claim("sub", issuer));
                claims.Add(new Claim("iat", Utility.ToUnixTime(now).ToString()));
                claims.Add(new Claim("jti", Guid.NewGuid().ToString()));//nonce

                if (additionalClaims != null)
                {
                    claims.AddRange(additionalClaims);
                }

                var payload = new JwtPayload(issuer: issuer
                    , audience: audience
                    , notBefore: null
                    , expires: now.AddMinutes(10)
                    , claims: claims);

                var token = new JwtSecurityToken(header, payload);

                var handler = new JwtSecurityTokenHandler();

                jwt = handler.WriteToken(token);
            }

            return jwt;
        }
    }
}
