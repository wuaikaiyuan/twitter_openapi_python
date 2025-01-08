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

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, field_validator
from typing import Any, ClassVar, Dict, List
from twitter_openapi_python_generated.models.callback import Callback
from twitter_openapi_python_generated.models.cover_cta import CoverCta
from twitter_openapi_python_generated.models.text import Text
from typing import Optional, Set
from typing_extensions import Self

class TimelineHalfCover(BaseModel):
    """
    TimelineHalfCover
    """ # noqa: E501
    dismissible: StrictBool
    half_cover_display_type: StrictStr = Field(alias="halfCoverDisplayType")
    impression_callbacks: List[Callback] = Field(alias="impressionCallbacks")
    primary_cover_cta: CoverCta = Field(alias="primaryCoverCta")
    primary_text: Text = Field(alias="primaryText")
    secondary_text: Text = Field(alias="secondaryText")
    type: StrictStr
    __properties: ClassVar[List[str]] = ["dismissible", "halfCoverDisplayType", "impressionCallbacks", "primaryCoverCta", "primaryText", "secondaryText", "type"]

    @field_validator('half_cover_display_type')
    def half_cover_display_type_validate_enum(cls, value):
        """Validates the enum"""
        if value not in set(['Cover']):
            raise ValueError("must be one of enum values ('Cover')")
        return value

    @field_validator('type')
    def type_validate_enum(cls, value):
        """Validates the enum"""
        if value not in set(['TimelineHalfCover']):
            raise ValueError("must be one of enum values ('TimelineHalfCover')")
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
        """Create an instance of TimelineHalfCover from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of each item in impression_callbacks (list)
        _items = []
        if self.impression_callbacks:
            for _item_impression_callbacks in self.impression_callbacks:
                if _item_impression_callbacks:
                    _items.append(_item_impression_callbacks.to_dict())
            _dict['impressionCallbacks'] = _items
        # override the default output from pydantic by calling `to_dict()` of primary_cover_cta
        if self.primary_cover_cta:
            _dict['primaryCoverCta'] = self.primary_cover_cta.to_dict()
        # override the default output from pydantic by calling `to_dict()` of primary_text
        if self.primary_text:
            _dict['primaryText'] = self.primary_text.to_dict()
        # override the default output from pydantic by calling `to_dict()` of secondary_text
        if self.secondary_text:
            _dict['secondaryText'] = self.secondary_text.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of TimelineHalfCover from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "dismissible": obj.get("dismissible"),
            "halfCoverDisplayType": obj.get("halfCoverDisplayType"),
            "impressionCallbacks": [Callback.from_dict(_item) for _item in obj["impressionCallbacks"]] if obj.get("impressionCallbacks") is not None else None,
            "primaryCoverCta": CoverCta.from_dict(obj["primaryCoverCta"]) if obj.get("primaryCoverCta") is not None else None,
            "primaryText": Text.from_dict(obj["primaryText"]) if obj.get("primaryText") is not None else None,
            "secondaryText": Text.from_dict(obj["secondaryText"]) if obj.get("secondaryText") is not None else None,
            "type": obj.get("type")
        })
        return _obj


