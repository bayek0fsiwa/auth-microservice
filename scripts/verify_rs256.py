from src.configs.config import get_settings
from src.auth.security import create_access_token, decode_token


settings = get_settings()
with open("private.pem", "r") as f:
    settings.JWT_PRIVATE_KEY = f.read()
with open("public.pem", "r") as f:
    settings.JWT_PUBLIC_KEY = f.read()
settings.JWT_ALGORITHM = "RS256"

print(f"Algorithm: {settings.JWT_ALGORITHM}")

# Create a token
data = {"sub": "testuser"}
token = create_access_token(data)
print(f"Generated Token: {token}")

# Decode the token
payload = decode_token(token)
print(f"Decoded Payload: {payload}")

assert payload["sub"] == "testuser"
assert payload["type"] == "access"
print("Verification Successful!")
