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

from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr
from typing import Any, ClassVar, Dict, List, Optional
from twitter_openapi_python_generated.models.post_create_tweet_request_variables_media import PostCreateTweetRequestVariablesMedia
from twitter_openapi_python_generated.models.post_create_tweet_request_variables_reply import PostCreateTweetRequestVariablesReply
from typing import Optional, Set
from typing_extensions import Self

class PostCreateTweetRequestVariables(BaseModel):
    """
    PostCreateTweetRequestVariables
    """ # noqa: E501
    dark_request: StrictBool
    media: PostCreateTweetRequestVariablesMedia
    reply: Optional[PostCreateTweetRequestVariablesReply] = None
    semantic_annotation_ids: List[Dict[str, Any]]
    tweet_text: StrictStr
    __properties: ClassVar[List[str]] = ["dark_request", "media", "reply", "semantic_annotation_ids", "tweet_text"]

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
        """Create an instance of PostCreateTweetRequestVariables from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of media
        if self.media:
            _dict['media'] = self.media.to_dict()
        # override the default output from pydantic by calling `to_dict()` of reply
        if self.reply:
            _dict['reply'] = self.reply.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of PostCreateTweetRequestVariables from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "dark_request": obj.get("dark_request") if obj.get("dark_request") is not None else False,
            "media": PostCreateTweetRequestVariablesMedia.from_dict(obj["media"]) if obj.get("media") is not None else None,
            "reply": PostCreateTweetRequestVariablesReply.from_dict(obj["reply"]) if obj.get("reply") is not None else None,
            "semantic_annotation_ids": obj.get("semantic_annotation_ids"),
            "tweet_text": obj.get("tweet_text") if obj.get("tweet_text") is not None else 'test'
        })
        return _obj


