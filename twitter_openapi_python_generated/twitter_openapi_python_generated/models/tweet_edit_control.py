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

from pydantic import BaseModel, Field, StrictBool, field_validator
from typing import Any, ClassVar, Dict, List, Optional
from typing_extensions import Annotated
from twitter_openapi_python_generated.models.tweet_edit_control_initial import TweetEditControlInitial
from typing import Optional, Set
from typing_extensions import Self

class TweetEditControl(BaseModel):
    """
    TweetEditControl
    """ # noqa: E501
    edit_control_initial: Optional[TweetEditControlInitial] = None
    edit_tweet_ids: Optional[List[Annotated[str, Field(strict=True)]]] = None
    editable_until_msecs: Optional[Annotated[str, Field(strict=True)]] = None
    edits_remaining: Optional[Annotated[str, Field(strict=True)]] = None
    initial_tweet_id: Optional[Annotated[str, Field(strict=True)]] = None
    is_edit_eligible: Optional[StrictBool] = None
    __properties: ClassVar[List[str]] = ["edit_control_initial", "edit_tweet_ids", "editable_until_msecs", "edits_remaining", "initial_tweet_id", "is_edit_eligible"]

    @field_validator('editable_until_msecs')
    def editable_until_msecs_validate_regular_expression(cls, value):
        """Validates the regular expression"""
        if value is None:
            return value

        if not re.match(r"^[0-9]+$", value):
            raise ValueError(r"must validate the regular expression /^[0-9]+$/")
        return value

    @field_validator('edits_remaining')
    def edits_remaining_validate_regular_expression(cls, value):
        """Validates the regular expression"""
        if value is None:
            return value

        if not re.match(r"^[0-9]+$", value):
            raise ValueError(r"must validate the regular expression /^[0-9]+$/")
        return value

    @field_validator('initial_tweet_id')
    def initial_tweet_id_validate_regular_expression(cls, value):
        """Validates the regular expression"""
        if value is None:
            return value

        if not re.match(r"^[0-9]+$", value):
            raise ValueError(r"must validate the regular expression /^[0-9]+$/")
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
        """Create an instance of TweetEditControl from a JSON string"""
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
        # override the default output from pydantic by calling `to_dict()` of edit_control_initial
        if self.edit_control_initial:
            _dict['edit_control_initial'] = self.edit_control_initial.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of TweetEditControl from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "edit_control_initial": TweetEditControlInitial.from_dict(obj["edit_control_initial"]) if obj.get("edit_control_initial") is not None else None,
            "edit_tweet_ids": obj.get("edit_tweet_ids"),
            "editable_until_msecs": obj.get("editable_until_msecs"),
            "edits_remaining": obj.get("edits_remaining"),
            "initial_tweet_id": obj.get("initial_tweet_id"),
            "is_edit_eligible": obj.get("is_edit_eligible")
        })
        return _obj


