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
import json
import pprint
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError, field_validator
from typing import Any, List, Optional
from twitter_openapi_python_generated.models.errors import Errors
from twitter_openapi_python_generated.models.unfavorite_tweet_response_data import UnfavoriteTweetResponseData
from pydantic import StrictStr, Field
from typing import Union, List, Optional, Dict
from typing_extensions import Literal, Self

POSTUNFAVORITETWEET200RESPONSE_ONE_OF_SCHEMAS = ["Errors", "UnfavoriteTweetResponseData"]

class PostUnfavoriteTweet200Response(BaseModel):
    """
    PostUnfavoriteTweet200Response
    """
    # data type: UnfavoriteTweetResponseData
    oneof_schema_1_validator: Optional[UnfavoriteTweetResponseData] = None
    # data type: Errors
    oneof_schema_2_validator: Optional[Errors] = None
    actual_instance: Optional[Union[Errors, UnfavoriteTweetResponseData]] = None
    one_of_schemas: List[str] = Field(default=Literal["Errors", "UnfavoriteTweetResponseData"])

    model_config = ConfigDict(
        validate_assignment=True,
        protected_namespaces=(),
    )


    def __init__(self, *args, **kwargs) -> None:
        if args:
            if len(args) > 1:
                raise ValueError("If a position argument is used, only 1 is allowed to set `actual_instance`")
            if kwargs:
                raise ValueError("If a position argument is used, keyword arguments cannot be used.")
            super().__init__(actual_instance=args[0])
        else:
            super().__init__(**kwargs)

    @field_validator('actual_instance')
    def actual_instance_must_validate_oneof(cls, v):
        instance = PostUnfavoriteTweet200Response.model_construct()
        error_messages = []
        match = 0
        # validate data type: UnfavoriteTweetResponseData
        if not isinstance(v, UnfavoriteTweetResponseData):
            error_messages.append(f"Error! Input type `{type(v)}` is not `UnfavoriteTweetResponseData`")
        else:
            match += 1
        # validate data type: Errors
        if not isinstance(v, Errors):
            error_messages.append(f"Error! Input type `{type(v)}` is not `Errors`")
        else:
            match += 1
        if match > 1:
            # more than 1 match
            raise ValueError("Multiple matches found when setting `actual_instance` in PostUnfavoriteTweet200Response with oneOf schemas: Errors, UnfavoriteTweetResponseData. Details: " + ", ".join(error_messages))
        elif match == 0:
            # no match
            raise ValueError("No match found when setting `actual_instance` in PostUnfavoriteTweet200Response with oneOf schemas: Errors, UnfavoriteTweetResponseData. Details: " + ", ".join(error_messages))
        else:
            return v

    @classmethod
    def from_dict(cls, obj: Union[str, Dict[str, Any]]) -> Self:
        return cls.from_json(json.dumps(obj))

    @classmethod
    def from_json(cls, json_str: str) -> Self:
        """Returns the object represented by the json string"""
        instance = cls.model_construct()
        error_messages = []
        match = 0

        # deserialize data into UnfavoriteTweetResponseData
        try:
            instance.actual_instance = UnfavoriteTweetResponseData.from_json(json_str)
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
            raise ValueError("Multiple matches found when deserializing the JSON string into PostUnfavoriteTweet200Response with oneOf schemas: Errors, UnfavoriteTweetResponseData. Details: " + ", ".join(error_messages))
        elif match == 0:
            # no match
            raise ValueError("No match found when deserializing the JSON string into PostUnfavoriteTweet200Response with oneOf schemas: Errors, UnfavoriteTweetResponseData. Details: " + ", ".join(error_messages))
        else:
            return instance

    def to_json(self) -> str:
        """Returns the JSON representation of the actual instance"""
        if self.actual_instance is None:
            return "null"

        if hasattr(self.actual_instance, "to_json") and callable(self.actual_instance.to_json):
            return self.actual_instance.to_json()
        else:
            return json.dumps(self.actual_instance)

    def to_dict(self) -> Optional[Union[Dict[str, Any], Errors, UnfavoriteTweetResponseData]]:
        """Returns the dict representation of the actual instance"""
        if self.actual_instance is None:
            return None

        if hasattr(self.actual_instance, "to_dict") and callable(self.actual_instance.to_dict):
            return self.actual_instance.to_dict()
        else:
            # primitive type
            return self.actual_instance

    def to_str(self) -> str:
        """Returns the string representation of the actual instance"""
        return pprint.pformat(self.model_dump())


