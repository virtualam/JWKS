using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JWTWithPEM
{
    class Program
    {
        static void Main(string[] args)
        {
            string certFolder = AppDomain.CurrentDomain.BaseDirectory;
            string publicKey = File.ReadAllText($"{certFolder}\\nhslogin_pb.pem");
            string privateKey = File.ReadAllText($"{certFolder}\\nhslogin_pv.pem");

            var payload = new Dictionary<string, object>()
            {
                { "sub", "mr.x@contoso.com" },
                { "exp", 1300819380 }
            };

            var headers = new Dictionary<string, object>()
            {
                 { "typ", "JWT" },
                 { "cty", "JWT" },
                 { "keyid", "111-222-333"}
            };

            var tokenJWT = CreateToken(payload, headers, privateKey);
            var decodedPayload = DecodeToken(tokenJWT, publicKey);
        }

        public static string CreateToken(Dictionary<string, object> payload, Dictionary<string, object> headers, string privateRsaKey)
        {
            RSAParameters rsaParams;
            using (var tr = new StringReader(privateRsaKey))
            {
                var pemReader = new PemReader(tr);
                var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                if (keyPair == null)
                {
                    throw new Exception("Could not read RSA private key");
                }
                var privateRsaParams = keyPair.Private as RsaPrivateCrtKeyParameters;
                rsaParams = DotNetUtilities.ToRSAParameters(privateRsaParams);
            }

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                //Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);

                return Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256, headers);
            }
        }

        public static string DecodeToken(string token, string publicRsaKey)
        {
            RSAParameters rsaParams;

            using (var tr = new StringReader(publicRsaKey))
            {
                var pemReader = new PemReader(tr);
                var publicKeyParams = pemReader.ReadObject() as RsaKeyParameters;
                if (publicKeyParams == null)
                {
                    throw new Exception("Could not read RSA public key");
                }
                rsaParams = DotNetUtilities.ToRSAParameters(publicKeyParams);
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                // This will throw if the signature is invalid
                return Jose.JWT.Decode(token, rsa, Jose.JwsAlgorithm.RS256);
            }
        }
    }
}
