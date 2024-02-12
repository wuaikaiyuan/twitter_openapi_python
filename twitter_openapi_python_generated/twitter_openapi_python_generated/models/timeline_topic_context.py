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
from twitter_openapi_python_generated.models.social_context_union_type import SocialContextUnionType
from twitter_openapi_python_generated.models.topic_context import TopicContext
from typing import Optional, Set
from typing_extensions import Self

class TimelineTopicContext(BaseModel):
    """
    TimelineTopicContext
    """ # noqa: E501
    functionality_type: Optional[StrictStr] = Field(default=None, alias="functionalityType")
    topic: Optional[TopicContext] = None
    type: Optional[SocialContextUnionType] = None
    __properties: ClassVar[List[str]] = ["functionalityType", "topic", "type"]

    @field_validator('functionality_type')
    def functionality_type_validate_enum(cls, value):
        """Validates the enum"""
        if value is None:
            return value

        if value not in set(['Basic']):
            raise ValueError("must be one of enum values ('Basic')")
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
        """Create an instance of TimelineTopicContext from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of topic
        if self.topic:
            _dict['topic'] = self.topic.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of TimelineTopicContext from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "functionalityType": obj.get("functionalityType"),
            "topic": TopicContext.from_dict(obj["topic"]) if obj.get("topic") is not None else None,
            "type": obj.get("type")
        })
        return _obj


