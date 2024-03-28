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

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator
from typing import Any, ClassVar, Dict, List, Optional
from twitter_openapi_python_generated.models.content_item_type import ContentItemType
from twitter_openapi_python_generated.models.highlight import Highlight
from twitter_openapi_python_generated.models.item_result import ItemResult
from twitter_openapi_python_generated.models.social_context_union import SocialContextUnion
from twitter_openapi_python_generated.models.type_name import TypeName
from typing import Optional, Set
from typing_extensions import Self

class TimelineTweet(BaseModel):
    """
    TimelineTweet
    """ # noqa: E501
    typename: TypeName = Field(alias="__typename")
    highlights: Optional[Highlight] = None
    item_type: ContentItemType = Field(alias="itemType")
    promoted_metadata: Optional[Dict[str, Any]] = Field(default=None, alias="promotedMetadata")
    social_context: Optional[SocialContextUnion] = Field(default=None, alias="socialContext")
    tweet_display_type: StrictStr = Field(alias="tweetDisplayType")
    tweet_results: ItemResult
    __properties: ClassVar[List[str]] = ["__typename", "highlights", "itemType", "promotedMetadata", "socialContext", "tweetDisplayType", "tweet_results"]

    @field_validator('tweet_display_type')
    def tweet_display_type_validate_enum(cls, value):
        """Validates the enum"""
        if value not in set(['Tweet', 'SelfThread', 'MediaGrid', 'CondensedTweet']):
            raise ValueError("must be one of enum values ('Tweet', 'SelfThread', 'MediaGrid', 'CondensedTweet')")
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
        """Create an instance of TimelineTweet from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of highlights
        if self.highlights:
            _dict['highlights'] = self.highlights.to_dict()
        # override the default output from pydantic by calling `to_dict()` of social_context
        if self.social_context:
            _dict['socialContext'] = self.social_context.to_dict()
        # override the default output from pydantic by calling `to_dict()` of tweet_results
        if self.tweet_results:
            _dict['tweet_results'] = self.tweet_results.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of TimelineTweet from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "__typename": obj.get("__typename"),
            "highlights": Highlight.from_dict(obj["highlights"]) if obj.get("highlights") is not None else None,
            "itemType": obj.get("itemType"),
            "promotedMetadata": obj.get("promotedMetadata"),
            "socialContext": SocialContextUnion.from_dict(obj["socialContext"]) if obj.get("socialContext") is not None else None,
            "tweetDisplayType": obj.get("tweetDisplayType"),
            "tweet_results": ItemResult.from_dict(obj["tweet_results"]) if obj.get("tweet_results") is not None else None
        })
        return _obj


