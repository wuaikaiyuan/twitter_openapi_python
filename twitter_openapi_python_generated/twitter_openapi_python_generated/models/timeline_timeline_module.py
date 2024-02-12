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
from twitter_openapi_python_generated.models.content_entry_type import ContentEntryType
from twitter_openapi_python_generated.models.feedback_info import FeedbackInfo
from twitter_openapi_python_generated.models.module_item import ModuleItem
from typing import Optional, Set
from typing_extensions import Self

class TimelineTimelineModule(BaseModel):
    """
    TimelineTimelineModule
    """ # noqa: E501
    typename: StrictStr = Field(alias="__typename")
    client_event_info: Dict[str, Any] = Field(alias="clientEventInfo")
    display_type: StrictStr = Field(alias="displayType")
    entry_type: ContentEntryType = Field(alias="entryType")
    feedback_info: Optional[FeedbackInfo] = Field(default=None, alias="feedbackInfo")
    footer: Optional[Dict[str, Any]] = None
    header: Optional[Dict[str, Any]] = None
    items: Optional[List[ModuleItem]] = None
    metadata: Optional[Dict[str, Any]] = None
    __properties: ClassVar[List[str]] = ["__typename", "clientEventInfo", "displayType", "entryType", "feedbackInfo", "footer", "header", "items", "metadata"]

    @field_validator('display_type')
    def display_type_validate_enum(cls, value):
        """Validates the enum"""
        if value not in set(['Vertical', 'VerticalConversation', 'VerticalGrid', 'Carousel']):
            raise ValueError("must be one of enum values ('Vertical', 'VerticalConversation', 'VerticalGrid', 'Carousel')")
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
        """Create an instance of TimelineTimelineModule from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of feedback_info
        if self.feedback_info:
            _dict['feedbackInfo'] = self.feedback_info.to_dict()
        # override the default output from pydantic by calling `to_dict()` of each item in items (list)
        _items = []
        if self.items:
            for _item in self.items:
                if _item:
                    _items.append(_item.to_dict())
            _dict['items'] = _items
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of TimelineTimelineModule from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "__typename": obj.get("__typename"),
            "clientEventInfo": obj.get("clientEventInfo"),
            "displayType": obj.get("displayType"),
            "entryType": obj.get("entryType"),
            "feedbackInfo": FeedbackInfo.from_dict(obj["feedbackInfo"]) if obj.get("feedbackInfo") is not None else None,
            "footer": obj.get("footer"),
            "header": obj.get("header"),
            "items": [ModuleItem.from_dict(_item) for _item in obj["items"]] if obj.get("items") is not None else None,
            "metadata": obj.get("metadata")
        })
        return _obj


