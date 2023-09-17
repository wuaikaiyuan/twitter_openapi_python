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
from inspect import getfullargspec
import json
import pprint
import re  # noqa: F401

from typing import Any, List, Optional
from pydantic import BaseModel, Field, StrictStr, ValidationError, validator
from twitter_openapi_python_generated.models.timeline_add_entries import TimelineAddEntries
from twitter_openapi_python_generated.models.timeline_add_to_module import TimelineAddToModule
from twitter_openapi_python_generated.models.timeline_clear_cache import TimelineClearCache
from twitter_openapi_python_generated.models.timeline_pin_entry import TimelinePinEntry
from twitter_openapi_python_generated.models.timeline_replace_entry import TimelineReplaceEntry
from twitter_openapi_python_generated.models.timeline_show_alert import TimelineShowAlert
from twitter_openapi_python_generated.models.timeline_show_cover import TimelineShowCover
from twitter_openapi_python_generated.models.timeline_terminate_timeline import TimelineTerminateTimeline
from typing import Union, Any, List, TYPE_CHECKING
from pydantic import StrictStr, Field

INSTRUCTIONUNION_ONE_OF_SCHEMAS = ["TimelineAddEntries", "TimelineAddToModule", "TimelineClearCache", "TimelinePinEntry", "TimelineReplaceEntry", "TimelineShowAlert", "TimelineShowCover", "TimelineTerminateTimeline"]

class InstructionUnion(BaseModel):
    """
    InstructionUnion
    """
    # data type: TimelineAddEntries
    oneof_schema_1_validator: Optional[TimelineAddEntries] = None
    # data type: TimelineAddToModule
    oneof_schema_2_validator: Optional[TimelineAddToModule] = None
    # data type: TimelineClearCache
    oneof_schema_3_validator: Optional[TimelineClearCache] = None
    # data type: TimelinePinEntry
    oneof_schema_4_validator: Optional[TimelinePinEntry] = None
    # data type: TimelineReplaceEntry
    oneof_schema_5_validator: Optional[TimelineReplaceEntry] = None
    # data type: TimelineShowAlert
    oneof_schema_6_validator: Optional[TimelineShowAlert] = None
    # data type: TimelineTerminateTimeline
    oneof_schema_7_validator: Optional[TimelineTerminateTimeline] = None
    # data type: TimelineShowCover
    oneof_schema_8_validator: Optional[TimelineShowCover] = None
    if TYPE_CHECKING:
        actual_instance: Union[TimelineAddEntries, TimelineAddToModule, TimelineClearCache, TimelinePinEntry, TimelineReplaceEntry, TimelineShowAlert, TimelineShowCover, TimelineTerminateTimeline]
    else:
        actual_instance: Any
    one_of_schemas: List[str] = Field(INSTRUCTIONUNION_ONE_OF_SCHEMAS, const=True)

    class Config:
        validate_assignment = True

    discriminator_value_class_map = {
    }

    def __init__(self, *args, **kwargs):
        if args:
            if len(args) > 1:
                raise ValueError("If a position argument is used, only 1 is allowed to set `actual_instance`")
            if kwargs:
                raise ValueError("If a position argument is used, keyword arguments cannot be used.")
            super().__init__(actual_instance=args[0])
        else:
            super().__init__(**kwargs)

    @validator('actual_instance')
    def actual_instance_must_validate_oneof(cls, v):
        instance = InstructionUnion.construct()
        error_messages = []
        match = 0
        # validate data type: TimelineAddEntries
        if not isinstance(v, TimelineAddEntries):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TimelineAddEntries`")
        else:
            match += 1
        # validate data type: TimelineAddToModule
        if not isinstance(v, TimelineAddToModule):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TimelineAddToModule`")
        else:
            match += 1
        # validate data type: TimelineClearCache
        if not isinstance(v, TimelineClearCache):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TimelineClearCache`")
        else:
            match += 1
        # validate data type: TimelinePinEntry
        if not isinstance(v, TimelinePinEntry):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TimelinePinEntry`")
        else:
            match += 1
        # validate data type: TimelineReplaceEntry
        if not isinstance(v, TimelineReplaceEntry):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TimelineReplaceEntry`")
        else:
            match += 1
        # validate data type: TimelineShowAlert
        if not isinstance(v, TimelineShowAlert):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TimelineShowAlert`")
        else:
            match += 1
        # validate data type: TimelineTerminateTimeline
        if not isinstance(v, TimelineTerminateTimeline):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TimelineTerminateTimeline`")
        else:
            match += 1
        # validate data type: TimelineShowCover
        if not isinstance(v, TimelineShowCover):
            error_messages.append(f"Error! Input type `{type(v)}` is not `TimelineShowCover`")
        else:
            match += 1
        if match > 1:
            # more than 1 match
            raise ValueError("Multiple matches found when setting `actual_instance` in InstructionUnion with oneOf schemas: TimelineAddEntries, TimelineAddToModule, TimelineClearCache, TimelinePinEntry, TimelineReplaceEntry, TimelineShowAlert, TimelineShowCover, TimelineTerminateTimeline. Details: " + ", ".join(error_messages))
        elif match == 0:
            # no match
            raise ValueError("No match found when setting `actual_instance` in InstructionUnion with oneOf schemas: TimelineAddEntries, TimelineAddToModule, TimelineClearCache, TimelinePinEntry, TimelineReplaceEntry, TimelineShowAlert, TimelineShowCover, TimelineTerminateTimeline. Details: " + ", ".join(error_messages))
        else:
            return v

    @classmethod
    def from_dict(cls, obj: dict) -> InstructionUnion:
        return cls.from_json(json.dumps(obj))

    @classmethod
    def from_json(cls, json_str: str) -> InstructionUnion:
        """Returns the object represented by the json string"""
        instance = InstructionUnion.construct()
        error_messages = []
        match = 0

        # use oneOf discriminator to lookup the data type
        _data_type = json.loads(json_str).get("type")
        if not _data_type:
            raise ValueError("Failed to lookup data type from the field `type` in the input.")

        # check if data type is `TimelineAddEntries`
        if _data_type == "TimelineAddEntries":
            instance.actual_instance = TimelineAddEntries.from_json(json_str)
            return instance

        # check if data type is `TimelineAddToModule`
        if _data_type == "TimelineAddToModule":
            instance.actual_instance = TimelineAddToModule.from_json(json_str)
            return instance

        # check if data type is `TimelineClearCache`
        if _data_type == "TimelineClearCache":
            instance.actual_instance = TimelineClearCache.from_json(json_str)
            return instance

        # check if data type is `TimelinePinEntry`
        if _data_type == "TimelinePinEntry":
            instance.actual_instance = TimelinePinEntry.from_json(json_str)
            return instance

        # check if data type is `TimelineReplaceEntry`
        if _data_type == "TimelineReplaceEntry":
            instance.actual_instance = TimelineReplaceEntry.from_json(json_str)
            return instance

        # check if data type is `TimelineShowAlert`
        if _data_type == "TimelineShowAlert":
            instance.actual_instance = TimelineShowAlert.from_json(json_str)
            return instance

        # check if data type is `TimelineShowCover`
        if _data_type == "TimelineShowCover":
            instance.actual_instance = TimelineShowCover.from_json(json_str)
            return instance

        # check if data type is `TimelineTerminateTimeline`
        if _data_type == "TimelineTerminateTimeline":
            instance.actual_instance = TimelineTerminateTimeline.from_json(json_str)
            return instance

        # deserialize data into TimelineAddEntries
        try:
            instance.actual_instance = TimelineAddEntries.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TimelineAddToModule
        try:
            instance.actual_instance = TimelineAddToModule.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TimelineClearCache
        try:
            instance.actual_instance = TimelineClearCache.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TimelinePinEntry
        try:
            instance.actual_instance = TimelinePinEntry.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TimelineReplaceEntry
        try:
            instance.actual_instance = TimelineReplaceEntry.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TimelineShowAlert
        try:
            instance.actual_instance = TimelineShowAlert.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TimelineTerminateTimeline
        try:
            instance.actual_instance = TimelineTerminateTimeline.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))
        # deserialize data into TimelineShowCover
        try:
            instance.actual_instance = TimelineShowCover.from_json(json_str)
            match += 1
        except (ValidationError, ValueError) as e:
            error_messages.append(str(e))

        if match > 1:
            # more than 1 match
            raise ValueError("Multiple matches found when deserializing the JSON string into InstructionUnion with oneOf schemas: TimelineAddEntries, TimelineAddToModule, TimelineClearCache, TimelinePinEntry, TimelineReplaceEntry, TimelineShowAlert, TimelineShowCover, TimelineTerminateTimeline. Details: " + ", ".join(error_messages))
        elif match == 0:
            # no match
            raise ValueError("No match found when deserializing the JSON string into InstructionUnion with oneOf schemas: TimelineAddEntries, TimelineAddToModule, TimelineClearCache, TimelinePinEntry, TimelineReplaceEntry, TimelineShowAlert, TimelineShowCover, TimelineTerminateTimeline. Details: " + ", ".join(error_messages))
        else:
            return instance

    def to_json(self) -> str:
        """Returns the JSON representation of the actual instance"""
        if self.actual_instance is None:
            return "null"

        to_json = getattr(self.actual_instance, "to_json", None)
        if callable(to_json):
            return self.actual_instance.to_json()
        else:
            return json.dumps(self.actual_instance)

    def to_dict(self) -> dict:
        """Returns the dict representation of the actual instance"""
        if self.actual_instance is None:
            return None

        to_dict = getattr(self.actual_instance, "to_dict", None)
        if callable(to_dict):
            return self.actual_instance.to_dict()
        else:
            # primitive type
            return self.actual_instance

    def to_str(self) -> str:
        """Returns the string representation of the actual instance"""
        return pprint.pformat(self.dict())


