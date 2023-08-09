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
from inspect import getfullargspec
import json
import pprint
import re  # noqa: F401

from typing import Any, List, Optional
from pydantic import BaseModel, Field, StrictStr, ValidationError, validator
from twitter_openapi_python_generated.models.errors import Errors
from twitter_openapi_python_generated.models.user_highlights_tweets_response import UserHighlightsTweetsResponse
from typing import Union, Any, List, TYPE_CHECKING
from pydantic import StrictStr, Field

GETUSERHIGHLIGHTSTWEETS200RESPONSE_ONE_OF_SCHEMAS = ["Errors", "UserHighlightsTweetsResponse"]

class GetUserHighlightsTweets200Response(BaseModel):
    """
    GetUserHighlightsTweets200Response
    """
    # data type: UserHighlightsTweetsResponse
    oneof_schema_1_validator: Optional[UserHighlightsTweetsResponse] = None
    # data type: Errors
    oneof_schema_2_validator: Optional[Errors] = None
    if TYPE_CHECKING:
        actual_instance: Union[Errors, UserHighlightsTweetsResponse]
    else:
        actual_instance: Any
    one_of_schemas: List[str] = Field(GETUSERHIGHLIGHTSTWEETS200RESPONSE_ONE_OF_SCHEMAS, const=True)

    class Config:
        validate_assignment = True

    def __init__(self, *args, **kwargs):
        if args:
            if len(args) > 1:
                raise ValueError("If a position argument is used, only 1 is allowed to set `actual_instance`")
            if kwargs:
                raise ValueError("If a position argument is used, keyword arguments cannot be used.")
            super().__init__(actual_instance=args[0])
        else:
            super().__init__(**kwargs)

    @validator('actual_instance')
    def actual_instance_must_validate_oneof(cls, v):
        instance = GetUserHighlightsTweets200Response.construct()
        error_messages = []
        match = 0
        # validate data type: UserHighlightsTweetsResponse
        if not isinstance(v, UserHighlightsTweetsResponse):
            error_messages.append(f"Error! Input type `{type(v)}` is not `UserHighlightsTweetsResponse`")
        else:
            match += 1
        # validate data type: Errors
        if not isinstance(v, Errors):
            error_messages.append(f"Error! Input type `{type(v)}` is not `Errors`")
        else:
            match += 1
        if match > 1:
            # more than 1 match
            raise ValueError("Multiple matches found when setting `actual_instance` in GetUserHighlightsTweets200Response with oneOf schemas: Errors, UserHighlightsTweetsResponse. Details: " + ", ".join(error_messages))
        elif match == 0:
            # no match
            raise ValueError("No match found when setting `actual_instance` in GetUserHighlightsTweets200Response with oneOf schemas: Errors, UserHighlightsTweetsResponse. Details: " + ", ".join(error_messages))
        else:
            return v

    @classmethod
    def from_dict(cls, obj: dict) -> GetUserHighlightsTweets200Response:
        return cls.from_json(json.dumps(obj))

    @classmethod
    def from_json(cls, json_str: str) -> GetUserHighlightsTweets200Response:
        """Returns the object represented by the json string"""
        instance = GetUserHighlightsTweets200Response.construct()
        error_messages = []
        match = 0

        # deserialize data into UserHighlightsTweetsResponse
        try:
            instance.actual_instance = UserHighlightsTweetsResponse.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into Errors
        try:
            instance.actual_instance = Errors.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))

        if match > 1:
            # more than 1 match
            raise ValueError("Multiple matches found when deserializing the JSON string into GetUserHighlightsTweets200Response with oneOf schemas: Errors, UserHighlightsTweetsResponse. Details: " + ", ".join(error_messages))
        elif match == 0:
            # no match
            raise ValueError("No match found when deserializing the JSON string into GetUserHighlightsTweets200Response with oneOf schemas: Errors, UserHighlightsTweetsResponse. Details: " + ", ".join(error_messages))
        else:
            return instance

    def to_json(self) -> str:
        """Returns the JSON representation of the actual instance"""
        if self.actual_instance is None:
            return "null"

        to_json = getattr(self.actual_instance, "to_json", None)
        if callable(to_json):
            return self.actual_instance.to_json()
        else:
            return json.dumps(self.actual_instance)

    def to_dict(self) -> dict:
        """Returns the dict representation of the actual instance"""
        if self.actual_instance is None:
            return None

        to_dict = getattr(self.actual_instance, "to_dict", None)
        if callable(to_dict):
            return self.actual_instance.to_dict()
        else:
            # primitive type
            return self.actual_instance

    def to_str(self) -> str:
        """Returns the string representation of the actual instance"""
        return pprint.pformat(self.dict())


