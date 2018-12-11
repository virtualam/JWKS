using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace JWTLib
{
    public class JWTClient
    {
        public MyJWKS PublicJWKS { get; private set; }

        public MyJWKS PrivatePKWS { get; private set; }
        public JWTClient(AlgType algType, string signingAlg, int iNumKeys, int dwKeySize)
        {
            List<MyJWK> listKeysPublic = new List<MyJWK>();
            List<MyJWK> listKeysPrivate = new List<MyJWK>();

            for (int i = 0; i < iNumKeys; i++)
            {
                MyJWK key = new MyJWK(algType, signingAlg, dwKeySize);


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

        public JWTClient(List<X509Certificate2> certificates)
        {
            List<MyJWK> listKeysPublic = new List<MyJWK>();
            List<MyJWK> listKeysPrivate = new List<MyJWK>();

            foreach (X509Certificate2 cert in certificates)
            {
                MyJWK key = new MyJWK(cert);


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

        public static string GenerateJWTRSA(string audience, string issuer, string jku, string privateJKWSJSON, string kid, List<Claim> additionalClaims)
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

                var signingCredentials = new SigningCredentials(signingKey, privateJWK.Alg);

                var header = new JwtHeader(signingCredentials);
                header.Add("kid", privateJWK.Kid);
                if (!string.IsNullOrEmpty(jku))
                {
                    header.Add("jku", jku);
                }

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

        public static string GenerateJWTEC(string audience, string issuer, string jku, string privateJKWSJSON, string kid, List<Claim> additionalClaims)
        {
            string jwt = null;
            string strjwk = Utility.FindJWKFromJWKS(false, privateJKWSJSON, kid);
            MyJWK privateJWK = MyJWK.Parse(strjwk);

            JsonWebKey jwk = new JsonWebKey(strjwk);

            var signingCredentials = new SigningCredentials(jwk, privateJWK.Alg);

            var header = new JwtHeader(signingCredentials);
            //header.Add("kid", privateJWK.Kid);
            if (!string.IsNullOrEmpty(jku))
            {
                header.Add("jku", jku);
            }

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

            return jwt;
        }

        public static string GenerateJWTX509(string audience, string issuer, string jku, string privateJKWSJSON, string kid, List<Claim> additionalClaims)
        {
            string jwt = null;
            string jwks = Utility.FindJWKFromJWKS(false, privateJKWSJSON, kid);
            MyJWK privateJWK = MyJWK.Parse(jwks);

            JsonWebKey jwk = new JsonWebKey(jwks);

            X509Certificate2 cert1 = new X509Certificate2();
            cert1.Import(Base64UrlEncoder.DecodeBytes(privateJWK.D), Base64UrlEncoder.Decode(privateJWK.Custom), X509KeyStorageFlags.Exportable);

            var signingCredentials = new X509SigningCredentials(cert1, privateJWK.Alg);

            var header = new JwtHeader(signingCredentials);

            //header.Add("kid", privateJWK.Kid);
            if (!string.IsNullOrEmpty(jku))
            {
                header.Add("jku", jku);
            }

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

            return jwt;
        }
    }
}
