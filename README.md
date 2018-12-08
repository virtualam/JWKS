# JWKS
Library and test tools to publish and validate JWK


## USAGE - CLIENT

>create two JWKs(JSON Web Key) and generate JSON to publish

```c#
JWTClient client = new JWTClient(2);
```

>JWKS public JSON to be published to a URL or filesystem - e.g. "https://[HOST]/RS384.public.json"

```c# 
string jwksPublic = client.PublicJWKS.ToJSON();
```

>JWKS private JSON - e.g. RS384.private.json

```c#
string jwksPrivate = client.PrivatePKWS.ToJSON();
```

>get a kid to generate a JWT token signed by JWK

```c#
string jwksPrivate = File.ReadAllText(@"[File_Path]\RS384.private.json");
MyJWK jwk = Utility.FindRandomPrivateJWKFromJWKS(jwksPrivate);
string kid = jwk.Kid;
string jwt = JWTClient.GenerateJWT("audience", "issuer", jwksPrivate, kid, new List<System.Security.Claims.Claim>() { new Claim("custom", Guid.NewGuid().ToString()) });
```

## USAGE - SERVER

>Get the JWKS from the Client registered URL

```c#
string jwksPublic = JWTServer.GetJWKSFromJKU("https://[HOST]/RS384.public.json");
```

>validate client JWT using the public key

```c#
JwtSecurityToken token = new JwtSecurityToken(jwt);
if (token != null && token.Header.ContainsKey("kid"))
{
    string kid = token.Header["kid"].ToString();`   
    IPrincipal principal = JWTServer.ValidateToken(jwt, jwksPublic, kid);`   
}
```
