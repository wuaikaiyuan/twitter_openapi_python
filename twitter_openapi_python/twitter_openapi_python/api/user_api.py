import twitter_openapi_python_generated as twitter
import twitter_openapi_python_generated.models as models
from twitter_openapi_python.models import TwitterApiUtilsResponse, ApiUtilsHeader
from twitter_openapi_python.utils.api import build_response
from typing import Any, Callable, Type, TypeVar, Optional, Union
import json

T = TypeVar("T")
ResponseType = TwitterApiUtilsResponse[models.User, ApiUtilsHeader]


ApiFnType = Union[
    Callable[[str, str, str], twitter.ApiResponse],
    Callable[[str, str, str, str], twitter.ApiResponse],
]


class UserApiUtils:
    api: twitter.UserApi
    flag: dict[str, Any]

    def __init__(self, api: twitter.UserApi, flag: dict[str, Any]):
        self.api = api
        self.flag = flag

    def request(
        self,
        apiFn: ApiFnType,
        convertFn: Callable[[T], models.UserResults],
        type: Type[T],
        key: str,
        param: dict[str, Any],
    ) -> ResponseType:
        assert key in self.flag.keys()

        args: list[str] = [
            self.flag[key]["queryId"],
            json.dumps(self.flag[key]["variables"] | param),
            json.dumps(self.flag[key]["features"]),
        ]

        if "fieldToggles" in self.flag[key].keys():
            args.append(json.dumps(self.flag[key]["fieldToggles"]))

        res = apiFn(*args)
        if res.data is None:
            raise Exception("No data")

        if isinstance(res.data.actual_instance, models.Errors):
            errors: models.Errors = res.data.actual_instance
            raise Exception(errors)
        user = convertFn(res.data.actual_instance).result

        return build_response(
            response=res,
            data=user,
            type=ApiUtilsHeader,
        )

    def get_user_by_screen_name(
        self,
        screen_name: str,
        extra_param: Optional[dict[str, Any]] = None,
    ) -> ResponseType:
        param: dict[str, Any] = {
            "screen_name": screen_name,
        }
        if extra_param is not None:
            param.update(extra_param)
        return self.request(
            apiFn=self.api.get_user_by_screen_name_with_http_info,
            convertFn=lambda e: e.data.user,
            type=models.UserResponse,
            key="UserByScreenName",
            param=param,
        )

    def get_user_by_rest_id(
        self,
        user_id: str,
        extra_param: Optional[dict[str, Any]] = None,
    ) -> ResponseType:
        param: dict[str, Any] = {
            "userId": user_id,
        }
        if extra_param is not None:
            param.update(extra_param)
        return self.request(
            apiFn=self.api.get_user_by_rest_id_with_http_info,
            convertFn=lambda e: e.data.user,
            type=models.UserResponse,
            key="UserByRestId",
            param=param,
        )

    def get_users_by_rest_ids(
        self,
        user_ids: list[str],
        extra_param: Optional[dict[str, Any]] = None,
    ) -> ResponseType:
        param: dict[str, Any] = {
            "userIds": user_ids,
        }
        if extra_param is not None:
            param.update(extra_param)
        return self.request(
            apiFn=self.api.get_users_by_rest_ids_with_http_info,
            convertFn=lambda e: e.data.users[0],
            type=models.UsersResponse,
            key="UsersByRestIds",
            param=param,
        )
