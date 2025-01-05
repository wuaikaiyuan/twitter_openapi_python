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

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator
from typing import Any, ClassVar, Dict, List
from typing_extensions import Annotated
from twitter_openapi_python_generated.models.tweet_preview_display_tweet_view_count import TweetPreviewDisplayTweetViewCount
from twitter_openapi_python_generated.models.user_result_core import UserResultCore
from typing import Optional, Set
from typing_extensions import Self

class TweetPreviewDisplayTweet(BaseModel):
    """
    TweetPreviewDisplayTweet
    """ # noqa: E501
    bookmark_count: StrictInt
    core: UserResultCore
    created_at: Annotated[str, Field(strict=True)]
    entities: Dict[str, Any]
    favorite_count: StrictInt
    quote_count: StrictInt
    reply_count: StrictInt
    rest_id: Annotated[str, Field(strict=True)]
    retweet_count: StrictInt
    text: StrictStr
    view_count: TweetPreviewDisplayTweetViewCount
    __properties: ClassVar[List[str]] = ["bookmark_count", "core", "created_at", "entities", "favorite_count", "quote_count", "reply_count", "rest_id", "retweet_count", "text", "view_count"]

    @field_validator('created_at')
    def created_at_validate_regular_expression(cls, value):
        """Validates the regular expression"""
        if not re.match(r"^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (0[1-9]|[12][0-9]|3[01]) (0[0-9]|1[0-9]|2[0-3])(: ?)([0-5][0-9])(: ?)([0-5][0-9]) ([+-][0-9]{4}) ([0-9]{4})$", value):
            raise ValueError(r"must validate the regular expression /^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (0[1-9]|[12][0-9]|3[01]) (0[0-9]|1[0-9]|2[0-3])(: ?)([0-5][0-9])(: ?)([0-5][0-9]) ([+-][0-9]{4}) ([0-9]{4})$/")
        return value

    @field_validator('rest_id')
    def rest_id_validate_regular_expression(cls, value):
        """Validates the regular expression"""
        if not re.match(r"^[0-9]+$", value):
            raise ValueError(r"must validate the regular expression /^[0-9]+$/")
        return value

    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        protected_namespaces=(),
    )


    def to_str(self) -> str:
        """Returns the string representation of the model using alias"""
        return pprint.pformat(self.model_dump(by_alias=True))

    def to_json(self) -> str:
        """Returns the JSON representation of the model using alias"""
        # TODO: pydantic v2: use .model_dump_json(by_alias=True, exclude_unset=True) instead
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> Optional[Self]:
        """Create an instance of TweetPreviewDisplayTweet from a JSON string"""
        return cls.from_dict(json.loads(json_str))

    def to_dict(self) -> Dict[str, Any]:
        """Return the dictionary representation of the model using alias.

        This has the following differences from calling pydantic's
        `self.model_dump(by_alias=True)`:

        * `None` is only added to the output dict for nullable fields that
          were set at model initialization. Other fields with value `None`
          are ignored.
        """
        excluded_fields: Set[str] = set([
        ])

        _dict = self.model_dump(
            by_alias=True,
            exclude=excluded_fields,
            exclude_none=True,
        )
        # override the default output from pydantic by calling `to_dict()` of core
        if self.core:
            _dict['core'] = self.core.to_dict()
        # override the default output from pydantic by calling `to_dict()` of view_count
        if self.view_count:
            _dict['view_count'] = self.view_count.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of TweetPreviewDisplayTweet from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "bookmark_count": obj.get("bookmark_count"),
            "core": UserResultCore.from_dict(obj["core"]) if obj.get("core") is not None else None,
            "created_at": obj.get("created_at"),
            "entities": obj.get("entities"),
            "favorite_count": obj.get("favorite_count"),
            "quote_count": obj.get("quote_count"),
            "reply_count": obj.get("reply_count"),
            "rest_id": obj.get("rest_id"),
            "retweet_count": obj.get("retweet_count"),
            "text": obj.get("text"),
            "view_count": TweetPreviewDisplayTweetViewCount.from_dict(obj["view_count"]) if obj.get("view_count") is not None else None
        })
        return _obj


