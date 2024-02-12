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

from pydantic import BaseModel
from typing import Any, ClassVar, Dict, List, Optional
from twitter_openapi_python_generated.models.media import Media
from twitter_openapi_python_generated.models.url import Url
from typing import Optional, Set
from typing_extensions import Self

class Entities(BaseModel):
    """
    Entities
    """ # noqa: E501
    hashtags: List[Dict[str, Any]]
    media: Optional[List[Media]] = None
    symbols: List[Dict[str, Any]]
    urls: List[Url]
    user_mentions: List[Dict[str, Any]]
    __properties: ClassVar[List[str]] = ["hashtags", "media", "symbols", "urls", "user_mentions"]

    model_config = {
        "populate_by_name": True,
        "validate_assignment": True,
        "protected_namespaces": (),
    }


    def to_str(self) -> str:
        """Returns the string representation of the model using alias"""
        return pprint.pformat(self.model_dump(by_alias=True))

    def to_json(self) -> str:
        """Returns the JSON representation of the model using alias"""
        # TODO: pydantic v2: use .model_dump_json(by_alias=True, exclude_unset=True) instead
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> Optional[Self]:
        """Create an instance of Entities from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of each item in media (list)
        _items = []
        if self.media:
            for _item in self.media:
                if _item:
                    _items.append(_item.to_dict())
            _dict['media'] = _items
        # override the default output from pydantic by calling `to_dict()` of each item in urls (list)
        _items = []
        if self.urls:
            for _item in self.urls:
                if _item:
                    _items.append(_item.to_dict())
            _dict['urls'] = _items
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of Entities from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "hashtags": obj.get("hashtags"),
            "media": [Media.from_dict(_item) for _item in obj["media"]] if obj.get("media") is not None else None,
            "symbols": obj.get("symbols"),
            "urls": [Url.from_dict(_item) for _item in obj["urls"]] if obj.get("urls") is not None else None,
            "user_mentions": obj.get("user_mentions")
        })
        return _obj


