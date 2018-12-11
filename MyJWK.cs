using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace JWTLib
{
    public class MyJWK
    {
        #region Members
        /// <summary>
        /// Gets or sets the 'kty' (Key Type)..
        /// </summary>
        [JsonProperty(Order = 1, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kty)]
        public string Kty { get; set; }

        /// <summary>
        /// Gets or sets the 'alg' (KeyType)..
        /// </summary>
        [JsonProperty(Order = 2, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Alg)]
        public string Alg { get; set; }

        /// <summary>
        /// Gets or sets the 'crv' (ECC - Curve)..
        /// </summary>
        [JsonProperty(Order = 3, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Crv)]
        public string Crv { get; set; }

        /// <summary>
        /// Gets or sets the 'x' (ECC - X Coordinate)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(Order = 4, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X)]
        public string X { get; set; }

        /// <summary>
        /// Gets or sets the 'y' (ECC - Y Coordinate)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(Order = 5, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Y)]
        public string Y { get; set; }

        /// <summary>
        /// Gets or sets the 'n' (RSA - Modulus)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(Order = 6, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.N)]
        public string N { get; set; }

        /// <summary>
        /// Gets or sets the 'e' (RSA - Exponent)..
        /// </summary>
        [JsonProperty(Order = 4, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.E)]
        public string E { get; set; }

        /// <summary>
        /// Gets or sets the 'd' (ECC - Private Key OR RSA - Private Exponent)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 7, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.D)]
        public string D { get; set; }

        /// <summary>
        /// Gets or sets the 'p' (RSA - First Prime Factor)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 8, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.P)]
        public string P { get; set; }

        /// <summary>
        /// Gets or sets the 'q' (RSA - Second  Prime Factor)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 9, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Q)]
        public string Q { get; set; }

        /// <summary>
        /// Gets or sets the 'dp' (RSA - First Factor CRT Exponent)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 10, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DP)]
        public string DP { get; set; }

        /// <summary>
        /// Gets or sets the 'dq' (RSA - Second Factor CRT Exponent)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 11, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DQ)]
        public string DQ { get; set; }

        /// <summary>
        /// Gets or sets the 'qi' (RSA - First CRT Coefficient)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 12, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.QI)]
        public string QI { get; set; }

        /// <summary>
        /// Gets the 'key_ops' (Key Operations)..
        /// </summary>
        [JsonProperty(Order = 13, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.KeyOps)]
        public IList<string> KeyOps { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'kty' (Key Type)..
        /// </summary>
        [JsonProperty(Order = 14, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "ext")]
        public string Ext { get; set; }

        /// <summary>
        /// Gets or sets the 'use' (Public Key Use)..
        /// </summary>
        [JsonProperty(Order = 15, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Use)]
        public string Use { get; set; }

        /// <summary>
        /// Gets or sets the 'kid' (Key ID)..
        /// </summary>
        [JsonProperty(Order = 16, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kid)]
        public string Kid { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain)..
        /// </summary>
        [JsonProperty(Order = 17, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5c)]
        public IList<string> X5c { get; private set; } = new List<string>();

        #endregion

        RsaSecurityKey securityKey;
        [JsonIgnore]
        public RsaSecurityKey SecurityKey
        {
            get
            {
                return securityKey;
            }
        }

        [JsonProperty("algType")]
        [JsonConverter(typeof(StringEnumConverter))]
        public AlgType AlgType
        {
            get;
            set;
        }

        [JsonProperty("c")]
        public string Custom
        {
            get;
            set;
        }

        public MyJWK()
        {

        }

        public MyJWK(AlgType algType, string signingAlg, int dwKeySize)
        {
            AlgType = algType;
            switch (algType)
            {
                case AlgType.RSA:
                    var provider = new RSACryptoServiceProvider(dwKeySize);
                    var parameters = provider.ExportParameters(true);
                    securityKey = new RsaSecurityKey(provider);
                    securityKey.KeyId = Guid.NewGuid().ToString();
                    JsonWebKey jkey = Microsoft.IdentityModel.Tokens.JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);

                    this.Kty = JsonWebAlgorithmsKeyTypes.RSA;
                    this.Kid = jkey.KeyId;

                    this.N = jkey.N;
                    this.E = jkey.E;
                    this.D = jkey.D;
                    this.P = jkey.P;
                    this.Q = jkey.Q;
                    this.DP = jkey.DP;
                    this.DQ = jkey.DQ;
                    this.QI = jkey.QI;

                    this.Alg = signingAlg;
                    break;
                case AlgType.EC:
                    var gen = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator("EC");

                    //Creating Random
                    var secureRandom = new SecureRandom();

                    //Parameters creation using the random and keysize
                    var keyGenParam = new KeyGenerationParameters(secureRandom, dwKeySize);

                    //Initializing generation algorithm with the Parameters--This method Init i modified
                    gen.Init(keyGenParam);

                    //Generation of Key Pair
                    var keyPair = gen.GenerateKeyPair();
                    this.D = Base64UrlEncoder.Encode((keyPair.Private as ECPrivateKeyParameters).D.ToByteArrayUnsigned());
                    this.X = Base64UrlEncoder.Encode((keyPair.Public as ECPublicKeyParameters).Q.XCoord.GetEncoded());
                    this.Y = Base64UrlEncoder.Encode((keyPair.Public as ECPublicKeyParameters).Q.YCoord.GetEncoded());
                    this.Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve;
                    this.Kid = Guid.NewGuid().ToString();
                    this.Alg = signingAlg;
                    this.Crv = JsonWebKeyECTypes.P384;
                    break;

            }
        }

        public MyJWK(X509Certificate2 certificate)
        {
            AlgType = AlgType.X509;
            RSACryptoServiceProvider key = certificate.PublicKey.Key as RSACryptoServiceProvider;
            if (key != null)
            {
                RSAParameters parameters = key.ExportParameters(false);

                this.E = Base64UrlEncoder.Encode(parameters.Exponent);
                this.N = Base64UrlEncoder.Encode(parameters.Modulus);
                this.Kty = JsonWebAlgorithmsKeyTypes.RSA;
                this.Kid = certificate.Thumbprint;
                switch (certificate.SignatureAlgorithm.Value)
                {
                    case "1.2.840.113549.1.1.12":
                        this.Alg = SecurityAlgorithms.RsaSha384;
                        break;
                }

                X509Certificate2Collection collection = new X509Certificate2Collection();
                collection.Import(certificate.RawData);

                List<X509Certificate2> listChain = new List<X509Certificate2>();
                foreach (X509Certificate2 cert in collection)
                {
                    listChain.Add(cert);
                }

                this.X5c = listChain.Select(c => Convert.ToBase64String(c.RawData)).ToList();

                string pwd = Guid.NewGuid().ToString();
                this.Custom = Base64UrlEncoder.Encode(pwd);
                byte[] b = certificate.Export(X509ContentType.Pfx, pwd);
                this.D = Base64UrlEncoder.Encode(b);
            }
        }

        public static MyJWK Parse(string json)
        {
            return JsonConvert.DeserializeObject<MyJWK>(json);
        }

        public string ToJSON(bool includePrivateKey)
        {
            if (this.AlgType == AlgType.RSA)
            {
                this.KeyOps = new List<string> {
                includePrivateKey ? "sign" : "verify"
                };
            }
            else if (this.AlgType == AlgType.EC)
            {
                this.Use = "sig";
            }

            string strJSON = null;
            if (includePrivateKey)
            {
                if (this.AlgType == AlgType.RSA)
                {
                    var jPrivate = new
                    {
                        kty = this.Kty,
                        alg = this.Alg,
                        n = this.N,
                        e = this.E,
                        d = this.D,
                        p = this.P,
                        q = this.Q,
                        dp = this.DP,
                        dq = this.DQ,
                        qi = this.QI,
                        key_ops = this.KeyOps,
                        ext = true.ToString().ToLower(),
                        kid = this.Kid,
                        AlgType = this.AlgType.ToString()
                    };
                    strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(jPrivate);
                }
                else if (this.AlgType == AlgType.EC)
                {
                    var jPrivate = new
                    {
                        kty = this.Kty,
                        alg = this.Alg,
                        X = this.X,
                        Y = this.Y,
                        D = this.D,
                        key_ops = this.KeyOps,
                        kid = this.Kid,
                        Crv = this.Crv,
                        AlgType = this.AlgType.ToString(),
                        Use = this.Use
                    };
                    strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(jPrivate);
                }
                else if (this.AlgType == AlgType.X509)
                {
                    var jPrivate = new
                    {
                        kty = this.Kty,
                        alg = this.Alg,
                        kid = this.Kid,
                        N = this.N,
                        E = this.E,
                        X5c = this.X5c,
                        D = this.D,
                        c = this.Custom,
                        AlgType = this.AlgType.ToString()
                    };
                    strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(jPrivate);
                }
            }
            else
            {
                if (this.AlgType == AlgType.RSA)
                {
                    var jPublic = new
                    {
                        kty = this.Kty,
                        alg = this.Alg,
                        n = this.N,
                        e = this.E,
                        key_ops = this.KeyOps,
                        ext = true.ToString().ToLower(),
                        kid = this.Kid,
                        AlgType = this.AlgType.ToString()
                    };
                    strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(jPublic);
                }
                else if (this.AlgType == AlgType.EC)
                {
                    var jPublic = new
                    {
                        kty = this.Kty,
                        alg = this.Alg,
                        X = this.X,
                        Y = this.Y,
                        key_ops = this.KeyOps,
                        kid = this.Kid,
                        Crv = this.Crv,
                        AlgType = this.AlgType.ToString(),
                        Use = this.Use
                    };
                    strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(jPublic);
                }
                else if (this.AlgType == AlgType.X509)
                {
                    var jPublic = new
                    {
                        kty = this.Kty,
                        alg = this.Alg,
                        kid = this.Kid,
                        N = this.N,
                        E = this.E,
                        AlgType = this.AlgType.ToString()
                    };
                    strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(jPublic);
                }
            }

            return strJSON;
        }
    }
}
