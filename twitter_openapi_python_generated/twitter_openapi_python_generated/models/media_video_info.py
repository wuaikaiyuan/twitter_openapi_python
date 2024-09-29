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

from pydantic import BaseModel, ConfigDict, StrictInt
from typing import Any, ClassVar, Dict, List, Optional
from twitter_openapi_python_generated.models.media_video_info_variant import MediaVideoInfoVariant
from typing import Optional, Set
from typing_extensions import Self

class MediaVideoInfo(BaseModel):
    """
    MediaVideoInfo
    """ # noqa: E501
    aspect_ratio: List[StrictInt]
    duration_millis: Optional[StrictInt] = None
    variants: List[MediaVideoInfoVariant]
    __properties: ClassVar[List[str]] = ["aspect_ratio", "duration_millis", "variants"]

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
        """Create an instance of MediaVideoInfo from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of each item in variants (list)
        _items = []
        if self.variants:
            for _item_variants in self.variants:
                if _item_variants:
                    _items.append(_item_variants.to_dict())
            _dict['variants'] = _items
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of MediaVideoInfo from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "aspect_ratio": obj.get("aspect_ratio"),
            "duration_millis": obj.get("duration_millis"),
            "variants": [MediaVideoInfoVariant.from_dict(_item) for _item in obj["variants"]] if obj.get("variants") is not None else None
        })
        return _obj


