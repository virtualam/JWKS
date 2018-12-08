# JWKS
Library and test tools to publish and validate JWK


## USAGE - CLIENT

>Create two JWKs (JSON Web Key) using RSA Crypto Provider and generate JSON to publish

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

>Get a kid to generate a JWT token signed by JWK

```c#
string jwksPrivate = File.ReadAllText(@"[File_Path]\RS384.private.json");
MyJWK jwk = Utility.FindRandomPrivateJWKFromJWKS(jwksPrivate);
string kid = jwk.Kid;
string jku = string.Empty;//JWKS URL if present (e.g. "https://[HOST]/RS384.public.json")
string jwt = JWTClient.GenerateJWT("audience", "issuer", jku, jwksPrivate, kid, new List<System.Security.Claims.Claim>() { new Claim("custom", Guid.NewGuid().ToString()) });
```

>Test it using [https://jwt.io](https://jwt.io/#debugger-io?token=eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjRiMmE3NTMxLTQ3OWMtNDU1Ni1hMzUzLTQwYjUwY2JkYzdiMCIsImprdSI6Imh0dHBzOi8vW0hPU1RdL1JTMzg0LnB1YmxpYy5qc29uIn0.eyJzdWIiOiJpc3N1ZXIiLCJpYXQiOiIxNTQ0MjQ3OTcxIiwianRpIjoiMDMxMjg0M2UtMmNkNC00MjIzLWEyMjktYzZhZmQ1MDE1ZDhiIiwiY3VzdG9tIjoiNzAwYzIxZDItZDM1My00MGRjLTg2MmMtN2Q2Zjg0YjMzYTNkIiwiZXhwIjoxNTQ0MjQ4NTcxLCJpc3MiOiJpc3N1ZXIiLCJhdWQiOiJhdWRpZW5jZSJ9.JPR0VTpUgI0Hkh-iGiZYqMVhOXszJI_ztuNDIa3PH0dWCUT09Z2Fs5LqFvN0b7d4JeuzR528-RfjowSxCUt3nlucbOzZ4Ic2ZDsIP4iU3V3M6K-RvHXFjc6oK7I9H8HQTI0-d27o2vw7lt0q-gwiqcFIF3QY7pxwC7odbCNbN8HL939U6xN3qFypwCi36jGQZz1wqsfKny4-H4zs8ej1N-hW6vzptllsHguaDijiL5NmN2DK0U8Iz9leY0YVwGl0SgVcggd1tzjOTDYlRpE9TbHY73_bvb-t_Qn3B1YOiHWOcEk1YedQiH8Bn4wgWQny3e5B7k49je2daNZmbplrLQ&publicKey=%7B%0A%20%20%20%20%20%20%22kty%22%3A%20%22RSA%22%2C%0A%20%20%20%20%20%20%22alg%22%3A%20%22RS384%22%2C%0A%20%20%20%20%20%20%22n%22%3A%20%22tFKPWVxujtWPgEBmhTGSdynoM6njjwR-one_SIUop6qh7rNJaO6Xw8aO9zvv6gHOfRhsv2mPa-mG-SUZM-gMOovtzlkG0sWAqh2AM8kFY7Hy8fd-ROKP18etEK3wFST5Vp4PD1J7F4VJIHny3Tf1xx_ZlaEVkjZnsTuZx2V52fYW9hiIwRoYYEcKbG7mTwkgcArlLJm5VDIzTSccsSmHyM2mYKePH-kL5UiOEUXz21qR89X3iUXosYGwCLRkq56w-TUQQdrZDsIanq8XdQoIBDgzKljK_TclKXLPhHkDWwWadonVkwcqrlI7uE21kFOOVSsHEf0M8lay-t8FlH5CQQ%22%2C%0A%20%20%20%20%20%20%22e%22%3A%20%22AQAB%22%2C%0A%20%20%20%20%20%20%22key_ops%22%3A%20%5B%20%22verify%22%20%5D%2C%0A%20%20%20%20%20%20%22ext%22%3A%20%22true%22%2C%0A%20%20%20%20%20%20%22kid%22%3A%20%224b2a7531-479c-4556-a353-40b50cbdc7b0%22%0A%20%20%20%20%7D)
*For some reason, this link doesn't automatically show the signature as valid, please copy and paste the public key on https://jwt.io agian to see the signature as verified.*


## USAGE - SERVER

>Get the JWKS from the Client registered URL

```c#
string jwksPublic = JWTServer.GetJWKSFromJKU("https://[HOST]/RS384.public.json");
```

>Validate client JWT using the public key

```c#
JwtSecurityToken token = new JwtSecurityToken(jwt);
if (token != null && token.Header.ContainsKey("kid"))
{
    string kid = token.Header["kid"].ToString();`   
    IPrincipal principal = JWTServer.ValidateToken(jwt, jwksPublic, kid);`   
}
```
