using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTLib
{
    public class Utility
    {
        public static long ToUnixTime(DateTime date)
        {
            DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return Convert.ToInt64((date.ToUniversalTime() - epoch).TotalSeconds);
        }

        public static string FindJWKFromJWKS(bool ispublic, string jwksJSON, string kid)
        {
            MyJWKS jwks = JsonConvert.DeserializeObject<MyJWKS>(jwksJSON);
            MyJWK jwk = jwks.keys.Where(k => k.Kid == kid).SingleOrDefault();
            if(jwk != null)
            {
                return jwk.ToJSON(!ispublic);
            }
            return string.Empty;
        }

        public static MyJWK FindRandomPrivateJWKFromJWKS(string jwksPrivate)
        {
            MyJWKS jwks = JsonConvert.DeserializeObject<MyJWKS>(jwksPrivate);
            Random rnd = new Random();
            int r = rnd.Next(jwks.keys.Count);
            MyJWK jwk = jwks.keys[r];
            return jwk;
        }
    }
}
