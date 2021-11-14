from fastapi import FastAPI
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from auth import Auth
from models.user import AuthModel_User

app = FastAPI()

security = HTTPBearer()
auth_handler = Auth()

@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.post('/secret')
async def secret_data(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    if auth_handler.decode_token(token):
        return 'Top Secret data only authorized users can access this info'


@app.post('/login')
async def login(user_details : AuthModel_User):
    try:
        # TODO:// to implement a database to hold user email and hashpassword
        # user = users_db.get(user_details.email)
        # if user is None:
        #       return HTTPException(status_code=401, detail='Invalid email')
        hashed_password = auth_handler.encode_password(user_details.password)
        if user_details.email is None:
            return HTTPException(status_code=401, detail='Invalid email')
        if not auth_handler.verify_password(user_details.password, hashed_password):
            return HTTPException(status_code=401, detail='Invalid password')

        access_token = auth_handler.encode_token(user_details.email)
        refresh_token = auth_handler.encode_refresh_token(user_details.email)
        return {'access_token': access_token, 'refresh_token': refresh_token}
    except BaseException as e:
        print('Failed to do something: ' + str(e))
        error_msg = 'Failed to login user'
        return error_msg

