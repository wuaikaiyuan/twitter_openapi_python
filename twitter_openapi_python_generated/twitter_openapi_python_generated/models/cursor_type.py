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
import json
from enum import Enum
from typing_extensions import Self


class CursorType(str, Enum):
    """
    CursorType
    """

    """
    allowed enum values
    """
    TOP = 'Top'
    BOTTOM = 'Bottom'
    SHOWMORE = 'ShowMore'
    SHOWMORETHREADS = 'ShowMoreThreads'
    GAP = 'Gap'

    @classmethod
    def from_json(cls, json_str: str) -> Self:
        """Create an instance of CursorType from a JSON string"""
        return cls(json.loads(json_str))


