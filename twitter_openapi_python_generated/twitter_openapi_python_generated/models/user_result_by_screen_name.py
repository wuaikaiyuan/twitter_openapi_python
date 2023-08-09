# coding: utf-8

"""
    Twitter OpenAPI

    Twitter OpenAPI(Swagger) specification

    The version of the OpenAPI document: 0.0.1
    Contact: yuki@yuki0311.com
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


from __future__ import annotations
import pprint
import re  # noqa: F401
import json



from pydantic import BaseModel, Field, constr, validator
from twitter_openapi_python_generated.models.user_result_by_screen_name_result import UserResultByScreenNameResult

class UserResultByScreenName(BaseModel):
    """
    UserResultByScreenName
    """
    id: constr(strict=True) = Field(...)
    result: UserResultByScreenNameResult = Field(...)
    __properties = ["id", "result"]

    @validator('id')
    def id_validate_regular_expression(cls, value):
        """Validates the regular expression"""
        if not re.match(r"^([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)?$", value):
            raise ValueError(r"must validate the regular expression /^([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)?$/")
        return value

    class Config:
        """Pydantic configuration"""
        allow_population_by_field_name = True
        validate_assignment = True

    def to_str(self) -> str:
        """Returns the string representation of the model using alias"""
        return pprint.pformat(self.dict(by_alias=True))

    def to_json(self) -> str:
        """Returns the JSON representation of the model using alias"""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> UserResultByScreenName:
        """Create an instance of UserResultByScreenName from a JSON string"""
        return cls.from_dict(json.loads(json_str))

    def to_dict(self):
        """Returns the dictionary representation of the model using alias"""
        _dict = self.dict(by_alias=True,
                          exclude={
                          },
                          exclude_none=True)
        # override the default output from pydantic by calling `to_dict()` of result
        if self.result:
            _dict['result'] = self.result.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: dict) -> UserResultByScreenName:
        """Create an instance of UserResultByScreenName from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return UserResultByScreenName.parse_obj(obj)

        _obj = UserResultByScreenName.parse_obj({
            "id": obj.get("id"),
            "result": UserResultByScreenNameResult.from_dict(obj.get("result")) if obj.get("result") is not None else None
        })
        return _obj


