using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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
        /// Gets or sets the 'n' (RSA - Modulus)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(Order = 3, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.N)]
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
        [JsonProperty(Order = 5, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.D)]
        public string D { get; set; }

        /// <summary>
        /// Gets or sets the 'p' (RSA - First Prime Factor)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 6, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.P)]
        public string P { get; set; }

        /// <summary>
        /// Gets or sets the 'q' (RSA - Second  Prime Factor)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 7, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Q)]
        public string Q { get; set; }

        /// <summary>
        /// Gets or sets the 'dp' (RSA - First Factor CRT Exponent)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 8, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DP)]
        public string DP { get; set; }

        /// <summary>
        /// Gets or sets the 'dq' (RSA - Second Factor CRT Exponent)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 9, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DQ)]
        public string DQ { get; set; }

        /// <summary>
        /// Gets or sets the 'qi' (RSA - First CRT Coefficient)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(Order = 10, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.QI)]
        public string QI { get; set; }

        /// <summary>
        /// Gets the 'key_ops' (Key Operations)..
        /// </summary>
        [JsonProperty(Order = 11, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.KeyOps)]
        public IList<string> KeyOps { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the 'kty' (Key Type)..
        /// </summary>
        [JsonProperty(Order = 12, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = "ext")]
        public string Ext { get; set; }
        /// <summary>
        /// Gets or sets the 'kid' (Key ID)..
        /// </summary>
        [JsonProperty(Order = 13, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kid)]
        public string Kid { get; set; }

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

        public MyJWK()
        {
        }
        public MyJWK(bool loadRSAProvider, string signingAlg, int dwKeySize)
        {
            var provider = new RSACryptoServiceProvider(2048);
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
        }

        public static MyJWK Parse(string json)
        {
            return JsonConvert.DeserializeObject<MyJWK>(json);
        }

        public string ToJSON(bool includePrivateKey)
        {
            this.KeyOps = new List<string> {
                includePrivateKey ? "sign" : "verify"
            };

            string strJSON;
            if (includePrivateKey)
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
                    kid = this.Kid
                };
                strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(jPrivate);
            }
            else
            {
                var jPublic = new
                {
                    kty = this.Kty,
                    alg = this.Alg,
                    n = this.N,
                    e = this.E,
                    key_ops = this.KeyOps,
                    ext = true.ToString().ToLower(),
                    kid = this.Kid
                };
                strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(jPublic);
            }

            return strJSON;
        }
    }
}
