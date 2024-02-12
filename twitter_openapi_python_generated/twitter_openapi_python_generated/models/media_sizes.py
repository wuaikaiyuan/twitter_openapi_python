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
from typing import Any, ClassVar, Dict, List
from twitter_openapi_python_generated.models.media_size import MediaSize
from typing import Optional, Set
from typing_extensions import Self

class MediaSizes(BaseModel):
    """
    MediaSizes
    """ # noqa: E501
    large: MediaSize
    medium: MediaSize
    small: MediaSize
    thumb: MediaSize
    __properties: ClassVar[List[str]] = ["large", "medium", "small", "thumb"]

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
        """Create an instance of MediaSizes from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of large
        if self.large:
            _dict['large'] = self.large.to_dict()
        # override the default output from pydantic by calling `to_dict()` of medium
        if self.medium:
            _dict['medium'] = self.medium.to_dict()
        # override the default output from pydantic by calling `to_dict()` of small
        if self.small:
            _dict['small'] = self.small.to_dict()
        # override the default output from pydantic by calling `to_dict()` of thumb
        if self.thumb:
            _dict['thumb'] = self.thumb.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of MediaSizes from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "large": MediaSize.from_dict(obj["large"]) if obj.get("large") is not None else None,
            "medium": MediaSize.from_dict(obj["medium"]) if obj.get("medium") is not None else None,
            "small": MediaSize.from_dict(obj["small"]) if obj.get("small") is not None else None,
            "thumb": MediaSize.from_dict(obj["thumb"]) if obj.get("thumb") is not None else None
        })
        return _obj


