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

>Test it using [https://jwt.io](https://jwt.io/#debugger-io?token=eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjRiMmE3NTMxLTQ3OWMtNDU1Ni1hMzUzLTQwYjUwY2JkYzdiMCJ9.eyJzdWIiOiJpc3N1ZXIiLCJpYXQiOiIxNTQ0MjM1MTkxIiwianRpIjoiM2ZiZTRhM2UtMjY1YS00ZjA1LWE0ZGEtMDk5ZGNmY2VlYjQ0IiwiY3VzdG9tIjoiNWYwMTg1ZTUtMjZkMC00NGQxLWJmMDgtOTQ0M2Y4ZmQwM2FjIiwiZXhwIjoxNTQ0MjM1NzkwLCJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSJ9.R0w6IaE4K8vySKQPzIG-x7h2RPbiggFZxkw61f68Grd2QOjtDCyFrd61BtEfKvEIfgnpmURoyT_S4CPTey84STo8QX9bpPfMAK2Hnog7DkReNNrKyt9ZFMGXu_O4taqK-7fs9HinfwNdugNLMCvHom7rV1T-mRsdfMy-lvHtkOIV0EYF-4PAl6Uyk67KVXiHpfArseqzejapsQZcWeik-UedS4XyHm8sS0eqjREx0PJwrHkeubwtlDUV46tkCBVeIQZKnRDCkxCoskYbJ5_-cisi1MqTZb3Yy-voPBl_M-N62Jap_GFKOrQhbUOdeABObIm7RrUfFLXyfeI-WSAlXQ&publicKey=%7B%0A%20%20%20%20%20%20%22kty%22%3A%20%22RSA%22%2C%0A%20%20%20%20%20%20%22alg%22%3A%20%22RS384%22%2C%0A%20%20%20%20%20%20%22n%22%3A%20%22tFKPWVxujtWPgEBmhTGSdynoM6njjwR-one_SIUop6qh7rNJaO6Xw8aO9zvv6gHOfRhsv2mPa-mG-SUZM-gMOovtzlkG0sWAqh2AM8kFY7Hy8fd-ROKP18etEK3wFST5Vp4PD1J7F4VJIHny3Tf1xx_ZlaEVkjZnsTuZx2V52fYW9hiIwRoYYEcKbG7mTwkgcArlLJm5VDIzTSccsSmHyM2mYKePH-kL5UiOEUXz21qR89X3iUXosYGwCLRkq56w-TUQQdrZDsIanq8XdQoIBDgzKljK_TclKXLPhHkDWwWadonVkwcqrlI7uE21kFOOVSsHEf0M8lay-t8FlH5CQQ%22%2C%0A%20%20%20%20%20%20%22e%22%3A%20%22AQAB%22%2C%0A%20%20%20%20%20%20%22key_ops%22%3A%20%5B%20%22verify%22%20%5D%2C%0A%20%20%20%20%20%20%22ext%22%3A%20%22true%22%2C%0A%20%20%20%20%20%20%22kid%22%3A%20%224b2a7531-479c-4556-a353-40b50cbdc7b0%22%0A%20%20%20%20%7D)
*For some reason, this link doesn't automatically show the signature as valid, please copy and paste the public key on https://jwt.io agian to see the signature as verified.*


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
