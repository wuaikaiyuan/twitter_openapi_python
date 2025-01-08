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
from twitter_openapi_python_generated.models.additional_media_info_call_to_actions import AdditionalMediaInfoCallToActions
from twitter_openapi_python_generated.models.user_result_core import UserResultCore
from typing import Optional, Set
from typing_extensions import Self

class AdditionalMediaInfo(BaseModel):
    """
    AdditionalMediaInfo
    """ # noqa: E501
    call_to_actions: Optional[AdditionalMediaInfoCallToActions] = None
    description: Optional[StrictStr] = None
    embeddable: Optional[StrictBool] = None
    monetizable: StrictBool
    source_user: Optional[UserResultCore] = None
    title: Optional[StrictStr] = None
    __properties: ClassVar[List[str]] = ["call_to_actions", "description", "embeddable", "monetizable", "source_user", "title"]

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
        """Create an instance of AdditionalMediaInfo from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of call_to_actions
        if self.call_to_actions:
            _dict['call_to_actions'] = self.call_to_actions.to_dict()
        # override the default output from pydantic by calling `to_dict()` of source_user
        if self.source_user:
            _dict['source_user'] = self.source_user.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of AdditionalMediaInfo from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "call_to_actions": AdditionalMediaInfoCallToActions.from_dict(obj["call_to_actions"]) if obj.get("call_to_actions") is not None else None,
            "description": obj.get("description"),
            "embeddable": obj.get("embeddable"),
            "monetizable": obj.get("monetizable"),
            "source_user": UserResultCore.from_dict(obj["source_user"]) if obj.get("source_user") is not None else None,
            "title": obj.get("title")
        })
        return _obj


