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
from twitter_openapi_python_generated.models.tweet_tombstone import TweetTombstone
from pydantic import StrictStr, Field
from typing import Union, List, Set, Optional, Dict
from typing_extensions import Literal, Self

TWEETUNION_ONE_OF_SCHEMAS = ["Tweet", "TweetTombstone", "TweetWithVisibilityResults"]

class TweetUnion(BaseModel):
    """
    TweetUnion
    """
    # data type: Tweet
    oneof_schema_1_validator: Optional[Tweet] = None
    # data type: TweetWithVisibilityResults
    oneof_schema_2_validator: Optional[TweetWithVisibilityResults] = None
    # data type: TweetTombstone
    oneof_schema_3_validator: Optional[TweetTombstone] = None
    actual_instance: Optional[Union[Tweet, TweetTombstone, TweetWithVisibilityResults]] = None
    one_of_schemas: Set[str] = { "Tweet", "TweetTombstone", "TweetWithVisibilityResults" }

    model_config = ConfigDict(
        validate_assignment=True,
        protected_namespaces=(),
    )


    discriminator_value_class_map: Dict[str, str] = {
    }

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
        instance = TweetUnion.model_construct()
        error_messages = []
        match = 0
        # validate data type: Tweet
        if not isinstance(v, Tweet):
            error_messages.append(f"Error! Input type `{type(v)}` is not `Tweet`")
        else:
            match += 1
        # validate data type: TweetWithVisibilityResults
        if not isinstance(v, TweetWithVisibilityResults):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TweetWithVisibilityResults`")
        else:
            match += 1
        # validate data type: TweetTombstone
        if not isinstance(v, TweetTombstone):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TweetTombstone`")
        else:
            match += 1
        if match > 1:
            # more than 1 match
            raise ValueError("Multiple matches found when setting `actual_instance` in TweetUnion with oneOf schemas: Tweet, TweetTombstone, TweetWithVisibilityResults. Details: " + ", ".join(error_messages))
        elif match == 0:
            # no match
            raise ValueError("No match found when setting `actual_instance` in TweetUnion with oneOf schemas: Tweet, TweetTombstone, TweetWithVisibilityResults. Details: " + ", ".join(error_messages))
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

        # use oneOf discriminator to lookup the data type
        _data_type = json.loads(json_str).get("__typename")
        if not _data_type:
            raise ValueError("Failed to lookup data type from the field `__typename` in the input.")

        # check if data type is `Tweet`
        if _data_type == "Tweet":
            instance.actual_instance = Tweet.from_json(json_str)
            return instance

        # check if data type is `TweetTombstone`
        if _data_type == "TweetTombstone":
            instance.actual_instance = TweetTombstone.from_json(json_str)
            return instance

        # check if data type is `TweetWithVisibilityResults`
        if _data_type == "TweetWithVisibilityResults":
            instance.actual_instance = TweetWithVisibilityResults.from_json(json_str)
            return instance

        # deserialize data into Tweet
        try:
            instance.actual_instance = Tweet.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TweetWithVisibilityResults
        try:
            instance.actual_instance = TweetWithVisibilityResults.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TweetTombstone
        try:
            instance.actual_instance = TweetTombstone.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))

        if match > 1:
            # more than 1 match
            raise ValueError("Multiple matches found when deserializing the JSON string into TweetUnion with oneOf schemas: Tweet, TweetTombstone, TweetWithVisibilityResults. Details: " + ", ".join(error_messages))
        elif match == 0:
            # no match
            raise ValueError("No match found when deserializing the JSON string into TweetUnion with oneOf schemas: Tweet, TweetTombstone, TweetWithVisibilityResults. Details: " + ", ".join(error_messages))
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

    def to_dict(self) -> Optional[Union[Dict[str, Any], Tweet, TweetTombstone, TweetWithVisibilityResults]]:
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

from twitter_openapi_python_generated.models.tweet import Tweet
from twitter_openapi_python_generated.models.tweet_with_visibility_results import TweetWithVisibilityResults
# TODO: Rewrite to not use raise_errors
TweetUnion.model_rebuild(raise_errors=False)

