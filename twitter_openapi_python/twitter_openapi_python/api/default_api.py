import twitter_openapi_python_generated as twitter
import twitter_openapi_python_generated.models as models
from typing import Any, Callable, Optional, Type, TypeVar, Union
import json

from twitter_openapi_python.models import (
    ApiUtilsHeader,
    TwitterApiUtilsResponse,
)
from twitter_openapi_python.utils.api import build_response


T1 = TypeVar("T1")
T2 = TypeVar("T2")


ApiFnType = Union[
    Callable[[str, str, str], twitter.ApiResponse],
    Callable[[str, str, str, str], twitter.ApiResponse],
]


class DefaultApiUtils:
    api: twitter.DefaultApi
    flag: dict[str, Any]

    def __init__(self, api: twitter.DefaultApi, flag: dict[str, Any]):
        self.api = api
        self.flag = flag

    def request(
        self,
        apiFn: ApiFnType,
        convertFn: Callable[[T1], T2],
        type1: Type[T1],
        type2: Type[T2],
        key: str,
        param: dict[str, Any],
    ) -> TwitterApiUtilsResponse[T2, ApiUtilsHeader]:
        assert key in self.flag.keys()

        args: list[str] = [
            self.flag[key]["queryId"],
            json.dumps(self.flag[key]["variables"] | param),
            json.dumps(self.flag[key]["features"]),
        ]

        if "fieldToggles" in self.flag[key].keys():
            args.append(json.dumps(self.flag[key]["fieldToggles"]))

        res = apiFn(*args.values())
        if res.data is None:
            raise Exception("No data")
        if isinstance(res.data.actual_instance, models.Errors):
            errors: models.Errors = res.data.actual_instance
            raise Exception(errors)

        data = convertFn(res.data.actual_instance)

        return build_response(
            response=res,
            data=data,
            type=ApiUtilsHeader,
        )

    def get_profile_spotlights_query(
        self,
        screen_name: Optional[str] = None,
        extra_param: Optional[dict[str, Any]] = None,
    ) -> TwitterApiUtilsResponse[models.UserResultByScreenName, ApiUtilsHeader]:
        param: dict[str, Any] = {}
        if screen_name is not None:
            param["screen_name"] = screen_name
        if extra_param is not None:
            param.update(extra_param)

        response = self.request(
            apiFn=self.api.get_profile_spotlights_query_with_http_info,
            convertFn=lambda x: x.data.user_result_by_screen_name,
            type1=models.ProfileResponse,
            type2=models.UserResultByScreenName,
            key="ProfileSpotlightsQuery",
            param=param,
        )
        return response
