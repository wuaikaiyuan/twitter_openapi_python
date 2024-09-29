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

from pydantic import BaseModel, ConfigDict, StrictBool
from typing import Any, ClassVar, Dict, List
from twitter_openapi_python_generated.models.post_create_tweet_request_variables_media_media_entities_inner import PostCreateTweetRequestVariablesMediaMediaEntitiesInner
from typing import Optional, Set
from typing_extensions import Self

class PostCreateTweetRequestVariablesMedia(BaseModel):
    """
    PostCreateTweetRequestVariablesMedia
    """ # noqa: E501
    media_entities: List[PostCreateTweetRequestVariablesMediaMediaEntitiesInner]
    possibly_sensitive: StrictBool
    __properties: ClassVar[List[str]] = ["media_entities", "possibly_sensitive"]

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
        """Create an instance of PostCreateTweetRequestVariablesMedia from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of each item in media_entities (list)
        _items = []
        if self.media_entities:
            for _item_media_entities in self.media_entities:
                if _item_media_entities:
                    _items.append(_item_media_entities.to_dict())
            _dict['media_entities'] = _items
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of PostCreateTweetRequestVariablesMedia from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "media_entities": [PostCreateTweetRequestVariablesMediaMediaEntitiesInner.from_dict(_item) for _item in obj["media_entities"]] if obj.get("media_entities") is not None else None,
            "possibly_sensitive": obj.get("possibly_sensitive") if obj.get("possibly_sensitive") is not None else False
        })
        return _obj


