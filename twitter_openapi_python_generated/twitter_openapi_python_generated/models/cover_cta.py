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

from pydantic import BaseModel, Field, StrictStr, field_validator
from typing import Any, ClassVar, Dict, List, Optional
from twitter_openapi_python_generated.models.callback import Callback
from twitter_openapi_python_generated.models.cta_client_event_info import CtaClientEventInfo
from twitter_openapi_python_generated.models.timeline_cover_behavior import TimelineCoverBehavior
from typing import Optional, Set
from typing_extensions import Self

class CoverCta(BaseModel):
    """
    CoverCta
    """ # noqa: E501
    text: Optional[StrictStr] = Field(default=None, alias="Text")
    button_style: Optional[StrictStr] = Field(default=None, alias="buttonStyle")
    callbacks: List[Callback]
    client_event_info: CtaClientEventInfo = Field(alias="clientEventInfo")
    cta_behavior: TimelineCoverBehavior = Field(alias="ctaBehavior")
    __properties: ClassVar[List[str]] = ["Text", "buttonStyle", "callbacks", "clientEventInfo", "ctaBehavior"]

    @field_validator('button_style')
    def button_style_validate_enum(cls, value):
        """Validates the enum"""
        if value is None:
            return value

        if value not in set(['Primary']):
            raise ValueError("must be one of enum values ('Primary')")
        return value

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
        """Create an instance of CoverCta from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of each item in callbacks (list)
        _items = []
        if self.callbacks:
            for _item in self.callbacks:
                if _item:
                    _items.append(_item.to_dict())
            _dict['callbacks'] = _items
        # override the default output from pydantic by calling `to_dict()` of client_event_info
        if self.client_event_info:
            _dict['clientEventInfo'] = self.client_event_info.to_dict()
        # override the default output from pydantic by calling `to_dict()` of cta_behavior
        if self.cta_behavior:
            _dict['ctaBehavior'] = self.cta_behavior.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of CoverCta from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "Text": obj.get("Text"),
            "buttonStyle": obj.get("buttonStyle"),
            "callbacks": [Callback.from_dict(_item) for _item in obj["callbacks"]] if obj.get("callbacks") is not None else None,
            "clientEventInfo": CtaClientEventInfo.from_dict(obj["clientEventInfo"]) if obj.get("clientEventInfo") is not None else None,
            "ctaBehavior": TimelineCoverBehavior.from_dict(obj["ctaBehavior"]) if obj.get("ctaBehavior") is not None else None
        })
        return _obj


