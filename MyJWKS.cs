using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTLib
{
    public class MyJWKS
    {
        public IList<MyJWK> keys { get; private set; } = new List<MyJWK>();
        public MyJWKS(List<MyJWK> keys)
        {
            this.keys = keys;
        }

        public string ToJSON()
        {
            string strJSON = Newtonsoft.Json.JsonConvert.SerializeObject(this);
            return strJSON;
        }
    }
}
