import jwt
from django.conf import settings
import datetime

class JWTHandler:
    __algorithm = settings.SETTING.JWT_ENCODE_ALGORITHM
    __private_key = settings.SETTING.JWT_PRIVATE_KEY
    __public_key = settings.SETTING.JWT_PUBLIC_KEY
    __token_validation_time = int(settings.SETTING.JWT_TOKEN_VALIDATION_TIME)

    def __generate(self, payload: dict) -> str:
        try:
            encoded_jwt = jwt.encode(payload, self.__private_key, algorithm=self.__algorithm)
            return encoded_jwt
        except Exception as e:
            raise e


    def generate_token(self, claims: dict, aud: str = None) -> str:
        if aud is not None:
            claims['aud'] = aud

        claims['iat'] = str(int(datetime.datetime.now().timestamp()))
        claims['exp'] = str(int((datetime.datetime.now() + datetime
                             .timedelta(seconds=self.__token_validation_time)).timestamp()))

        token = self.__generate(claims)
        return token

    def verify_token(self, token: str):
        try:
            payload = jwt.decode(token, self.__public_key, algorithms=[self.__algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False

    def decode_token(self, token: str) -> dict:
        return  jwt.decode(token, options={'verify_signature': False, 'verify_exp': False})
