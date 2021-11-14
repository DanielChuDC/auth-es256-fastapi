import re
from typing import Optional
from pydantic import BaseModel, validator
from pydantic.dataclasses import dataclass

@dataclass
class DB_User_Model():
    key: str
    email: str
    hashed_password: str
    is_active: Optional[bool]
    is_verified: Optional[bool]
    is_superuser: Optional[bool]

class AuthModel_User(BaseModel):
    email: str
    password: str
    @validator('password')
    def passwords_validation(cls, v):
        if not custom_password_validator(v):
            raise ValueError("Password must have minimum 8 characters to maximum 20 characters, 1 capital letter, 1 small letter, and 1 special character from '!@#$%^&*()'")
        return v


def custom_password_validator(password):
    reg = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,20}$"
    pat = re.compile(reg)
    mat = re.search(pat, password)
    return mat
