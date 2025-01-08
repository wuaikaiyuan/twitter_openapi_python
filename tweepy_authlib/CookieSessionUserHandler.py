import binascii
import js2py
import json
import random
import re
import requests
import time
import tweepy
from js2py.base import JsObjectWrapper
from requests.auth import AuthBase
from requests.cookies import RequestsCookieJar
from requests.models import PreparedRequest
from typing import Any, cast, Dict, Optional, TypeVar

Self = TypeVar("Self", bound="CookieSessionUserHandler")


class CookieSessionUserHandler(AuthBase):
    """
    使用 Twitter Web App 的内部 API，通过 Cookie 登录来使用 Twitter API 的认证处理程序

    认证流程是基于 2023 年 2 月 Twitter Web App (Chrome Desktop) 的行为而设计
    继承了 requests.auth.AuthBase，因此可以作为参数传递给 tweepy.API 的 auth 参数

    ref: https://github.com/mikf/gallery-dl/blob/master/gallery_dl/extractor/twitter.py
    ref: https://github.com/fa0311/TwitterFrontendFlow/blob/master/TwitterFrontendFlow/TwitterFrontendFlow.py
    """

    # 将 User-Agent 和 Sec-CH-UA 伪装成 Chrome 129
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    SEC_CH_UA = '"Not)A;Brand";v="99", "Google Chrome";v="129", "Chromium";v="129"'

    # Twitter Web App (GraphQL API) の Bearer 令牌
    TWITTER_WEB_APP_BEARER_TOKEN = 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'

    # 旧 TweetDeck (Twitter API v1.1) の Bearer 令牌
    TWEETDECK_BEARER_TOKEN = 'Bearer AAAAAAAAAAAAAAAAAAAAAFQODgEAAAAAVHTp76lzh3rFzcHbmHVvQxYYpTw%3DckAlMINMjmCwxUcaXbAN4XqJVdgMJaHqNOFgPMK0zN1qLqLQCF'

    def __init__(self, cookies: Optional[RequestsCookieJar] = None, screen_name: Optional[str] = None, 
                 password: Optional[str] = None) -> None:
        """
        初始化CookieSessionUserHandler
        需要指定cookies或screen_name和password中的一个

        Args:
            cookies (Optional[RequestsCookieJar], optional): 请求时使用的Cookie. 默认为None.
            screen_name (Optional[str], optional): Twitter的用户名 (不包含@). 默认为None.
            password (Optional[str], optional): Twitter的密码. 默认为None.

        Raises:
            ValueError: 未指定Cookie但同时未指定用户名或密码(或两者都未指定)
            ValueError: 用户名为空字符串
            ValueError: 密码为空字符串
            tweepy.BadRequest: 用户名或密码错误
            tweepy.HTTPException: 由于服务器错误等问题导致登录失败
            tweepy.TweepyException: 认证流程中发生错误导致登录失败
        """

        self.screen_name = screen_name
        self.password = password

        # 当未指定Cookie但同时未指定用户名或密码(或两者都未指定)时
        if cookies is None and (self.screen_name is None or self.password is None):
            raise ValueError('Either cookie or screen_name and password must be specified.')

        # 用户名为空字符串
        if self.screen_name == '':
            raise ValueError('screen_name must not be empty string.')

        # 密码为空字符串
        if self.password == '':
            raise ValueError('password must not be empty string.')

        # 获取HTML时的HTTP请求头
        self._html_headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ja',
            'sec-ch-ua': self.SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': self.USER_AGENT,
        }

        # 获取JavaScript时的HTTP请求头
        self._js_headers = self._html_headers.copy()
        self._js_headers['accept'] = '*/*'
        self._js_headers['referer'] = 'https://x.com/'
        self._js_headers['sec-fetch-dest'] = 'script'
        self._js_headers['sec-fetch-mode'] = 'no-cors'
        self._js_headers['sec-fetch-site'] = 'cross-site'
        del self._js_headers['sec-fetch-user']

        # 认证流程API访问时的HTTP请求头
        self._auth_flow_api_headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ja',
            'authorization': self.TWITTER_WEB_APP_BEARER_TOKEN,
            'content-type': 'application/json',
            'origin': 'https://x.com',
            'referer': 'https://x.com/',
            'sec-ch-ua': self.SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.USER_AGENT,
            'x-csrf-token': None,  # ここは後でセットする
            'x-guest-token': None,  # ここは後でセットする
            'x-twitter-active-user': 'yes',
            'x-twitter-client-language': 'ja',
        }

        # GraphQL API (Twitter Web App API)访问时的HTTP请求头
        ## GraphQL API は https://x.com/i/api/graphql/下且属于同一域名，因此故意省略origin和referer
        self._graphql_api_headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ja',
            'authorization': self.TWITTER_WEB_APP_BEARER_TOKEN,
            'content-type': 'application/json',
            'sec-ch-ua': self.SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.USER_AGENT,
            'x-csrf-token': None,  # 这里稍后设置
            'x-twitter-active-user': 'yes',
            'x-twitter-auth-type': 'OAuth2Session',
            'x-twitter-client-language': 'ja',
        }

        # 创建用于Cookie登录的会话
        ## 实际的Twitter API请求使用tweepy.API创建的会话
        ## 在__call__()中，会用tweepy.API创建的会话的请求头和Cookie覆盖
        self._session = requests.Session()

        # 当从API收到响应时自动更新CSRF令牌
        ## 当认证成功时，Cookie中的"ct0"值(CSRF令牌)会从客户端生成的值更新为服务器端生成的值
        self._session.hooks['response'].append(self._on_response_received)

        # 如果指定了Cookie，则将其设置到会话中(跳过重新登录)
        if cookies is not None:
            self._session.cookies = cookies

        # 如果未指定Cookie，则尝试登录
        else:
            self._login()

        # 如果无法从Cookie中获取auth_token或ct0时
        ## 由于auth_token和ct0都是认证所必需的Cookie，因此如果无法获取则视为认证失败
        if self._session.cookies.get('auth_token', default=None) is None or self._session.cookies.get('ct0',
                                                                                                      default=None) is None:
            raise tweepy.TweepyException('Failed to get auth_token or ct0 from Cookie')

        # 将Cookie中的"gt"值(访客令牌)设置到认证流程API用的请求头中
        guest_token = self._session.cookies.get('gt')
        if guest_token:
            self._auth_flow_api_headers['x-guest-token'] = guest_token

        # 将Cookie中的"ct0"值(CSRF令牌)设置到GraphQL API用的请求头中
        csrf_token = self._session.cookies.get('ct0')
        if csrf_token:
            self._auth_flow_api_headers['x-csrf-token'] = csrf_token
            self._graphql_api_headers['x-csrf-token'] = csrf_token

        # 将会话的请求头替换为GraphQL API用的请求头
        ## 之前使用旧TweetDeck API的请求头，但由于旧TweetDeck完全停用
        ## 反而可能引起怀疑，因此改为使用GraphQL API的请求头
        ## 设置cross_origin=True以模拟从x.com向api.x.com发送跨域请求时的请求头
        self._session.headers.clear()
        self._session.headers.update(self.get_graphql_api_headers(cross_origin=True))

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        """
        在requests库开始请求时被调用的钩子

        Args:
            request (PreparedRequest): PreparedRequest对象

        Returns:
            PreparedRequest: 添加了认证信息的PreparedRequest对象
        """

        # 将请求头替换为认证用会话的请求头
        # 为了不覆盖content-type，先保存content-type然后再替换
        content_type = request.headers.get('content-type', None)
        request.headers.update(self._session.headers)  # type: ignore
        if content_type is not None:
            request.headers['content-type'] = content_type  # 恢复原来的content-type

        # 如果请求仍然指向*.twitter.com，则替换为*.x.com
        ## 虽然为了兼容性，第三方API应该仍然可以通过api.twitter.com访问
        ## 但由于tweepy-authlib访问的是内部API，如果继续使用api.twitter.com可能会引起怀疑
        assert request.url is not None
        request.url = request.url.replace('twitter.com/', 'x.com/')

        # 有些Twitter API v1.1的API必须使用旧TweetDeck的Bearer令牌才能访问
        # 仅对这些API使用旧TweetDeck的Bearer令牌，其他API继续使用Twitter Web App的Bearer令牌
        # 这样可以降低被识别为可疑的可能性
        ## 在OldTweetDeck的interception.js中列出的API中，只有明确设置了PUBLIC_TOKENS[1]的API才需要
        ## ref: https://github.com/dimdenGD/OldTweetDeck/blob/main/src/interception.js
        TWEETDECK_BEARER_TOKEN_REQUIRED_APIS = [
            '/1.1/statuses/home_timeline.json',
            '/1.1/lists/statuses.json',
            '/1.1/activity/about_me.json',
            '/1.1/statuses/mentions_timeline.json',
            '/1.1/favorites/',
            '/1.1/collections/',
            '/1.1/users/show.json',
            '/1.1/account/verify_credentials.json',
        ]
        if any(api_url in request.url for api_url in TWEETDECK_BEARER_TOKEN_REQUIRED_APIS):
            request.headers['authorization'] = self.TWEETDECK_BEARER_TOKEN

        # 只对upload.twitter.com或upload.x.com下的API，按照Twitter Web App的行为添加或删除一些请求头
        if 'upload.twitter.com' in request.url or 'upload.x.com' in request.url:
            # 从x.com角度看，对upload.x.com的API请求是跨域的，因此需要添加Origin和Referer
            request.headers['origin'] = 'https://x.com'
            request.headers['referer'] = 'https://x.com/'
            # 以下请求头在对upload.x.com的API请求中不存在
            request.headers.pop('x-client-transaction-id', None)  # 为未来实现预留
            request.headers.pop('x-twitter-active-user', None)
            request.headers.pop('x-twitter-client-language', None)

        # 将Cookie替换为认证用会话的Cookie
        request._cookies.update(self._session.cookies)  # type: ignore
        cookie_header = ''
        for key, value in self._session.cookies.get_dict().items():
            cookie_header += f'{key}={value}; '
        request.headers['cookie'] = cookie_header.rstrip('; ')

        # 当从API收到响应时自动更新CSRF令牌
        ## 虽然可能不做也没问题，但为了以防万一
        request.hooks['response'].append(self._on_response_received)

        # 返回添加了认证信息的PreparedRequest对象
        return request

    def apply_auth(self: Self) -> Self:
        """
        在初始化tweepy.API时应用认证处理程序的方法
        返回自身实例作为认证处理程序

        Args:
            self (Self): 自身实例

        Returns:
            Self: 自身实例
        """

        return self

    def get_cookies(self) -> RequestsCookieJar:
        """
        获取当前登录会话的Cookie
        可以将返回的RequestsCookieJar通过pickle等方式保存，以便下次无需重新登录继续使用会话

        Returns:
            RequestsCookieJar: Cookie
        """

        return self._session.cookies

    def get_cookies_as_dict(self) -> Dict[str, str]:
        """
        以dict形式获取当前登录会话的Cookie
        可以保存返回的dict，以便下次无需重新登录继续使用会话

        Returns:
            Dict[str, str]: Cookie
        """

        return self._session.cookies.get_dict()

    def get_html_headers(self) -> Dict[str, str]:
        """
        获取用于访问 Twitter Web App HTML 的 HTTP 请求头
        主要用于在发送 HTTP 请求获取 Cookie 和令牌等信息时访问 HTML 页面

        Returns:
            Dict[str, str]: 用于访问 HTML 的 HTTP 请求头
        """

        return self._html_headers.copy()

    def get_js_headers(self, cross_origin: bool = False) -> Dict[str, str]:
        """
        获取用于访问 Twitter Web App JavaScript 的 HTTP 请求头
        主要用于在发送 HTTP 请求获取 Challenge 相关代码时访问 JavaScript 文件
        设置 cross_origin=True 时，可以获取用于访问例如 https://abs.twimg.com/ 下 JavaScript 文件的请求头

        Args:
            cross_origin (bool, optional): 是否为发送到 x.com 以外源的 HTTP 请求头. Defaults to False.

        Returns:
            Dict[str, str]: 用于访问 JavaScript 的 HTTP 请求头
        """

        headers = self._js_headers.copy()
        if cross_origin is True:
            headers['sec-fetch-mode'] = 'cors'
        return headers

    def get_graphql_api_headers(self, cross_origin: bool = False) -> Dict[str, str]:
        """
        获取用于访问 GraphQL API (Twitter Web App API) 的 HTTP 请求头
        使用此请求头自行发送 API 请求时，
        必须确保 x-csrf-token 头的值始终与 Cookie 中的 "ct0" 值保持一致
        在用于 Twitter API v1.1 时需要指定 cross_origin=True（因为 api.x.com 对于 x.com 来说是跨源的）
        相反，在用于 GraphQL API 时必须设置 cross_origin=False（因为 GraphQL API 对于 x.com 来说是同源的）

        Args:
            cross_origin (bool, optional): 返回的请求头是否用于发送到 x.com 以外的源. Defaults to False.

        Returns:
            Dict[str, str]: 用于访问 GraphQL API (Twitter Web App API) 的 HTTP 请求头
        """

        headers = self._graphql_api_headers.copy()

        # 为跨源请求添加 origin 和 referer
        # 模拟从 Twitter Web App 向 api.x.com 发送跨源请求时的请求头
        if cross_origin is True:
            headers['origin'] = 'https://x.com'
            headers['referer'] = 'https://x.com/'

        return headers

    def logout(self) -> None:
        """
        执行登出操作，断开与 Twitter 的会话连接
        仅仅删除 Cookie 的话会导致会话在 Twitter 端持续存在，因此如果之后不打算登录的话，应该明确调用此方法
        调用此方法后，将无法使用已获取的 Cookie 重新认证

        Raises:
            tweepy.HTTPException: 由于服务器错误等问题导致登出失败
            tweepy.TweepyException: 登出处理过程中发生错误
        """

        # 登出 API 专用请求头
        ## 与 self._graphql_api_headers 基本相同，仅将 content-type 更改为 application/x-www-form-urlencoded
        logout_headers = self._graphql_api_headers.copy()
        logout_headers['content-type'] = 'application/x-www-form-urlencoded'

        # 向登出 API 发送登出请求
        ## 执行此 API 后，服务器端会断开会话，并删除之前持有的大部分 Cookie
        logout_api_response = self._session.post('https://api.x.com/1.1/account/logout.json', headers=logout_headers,
                                                 data={
                                                     'redirectAfterLogout': 'https://x.com/account/switch',
                                                 })
        if logout_api_response.status_code != 200:
            raise self._get_tweepy_exception(logout_api_response)

        # 虽然看起来是固定值所以可能不需要，但为了以防万一还是检查状态
        try:
            status = logout_api_response.json()['status']
        except:
            raise tweepy.TweepyException('Failed to logout (failed to parse response)')
        if status != 'ok':
            raise tweepy.TweepyException(f'Failed to logout (status: {status})')

    def _on_response_received(self, response: requests.Response, *args, **kwargs) -> None:
        """
        收到响应时自动更新 CSRF 令牌的回调函数

        Args:
            response (requests.Response): 响应对象
        """

        csrf_token = response.cookies.get('ct0')
        if csrf_token:
            if self._session.cookies.get('ct0') != csrf_token:
                self._session.cookies.set('ct0', csrf_token, domain='.x.com')
            self._auth_flow_api_headers['x-csrf-token'] = csrf_token
            self._graphql_api_headers['x-csrf-token'] = csrf_token
            self._session.headers['x-csrf-token'] = csrf_token

    def _get_tweepy_exception(self, response: requests.Response) -> tweepy.TweepyException:
        """
        获取与状态码相对应的继承自 TweepyException 的异常类

        Args:
            status_code (int): 状态码

        Returns:
            tweepy.TweepyException: 异常对象
        """

        if response.status_code == 400:
            return tweepy.BadRequest(response)
        elif response.status_code == 401:
            return tweepy.Unauthorized(response)
        elif response.status_code == 403:
            return tweepy.Forbidden(response)
        elif response.status_code == 404:
            return tweepy.NotFound(response)
        elif response.status_code == 429:
            return tweepy.TooManyRequests(response)
        elif 500 <= response.status_code <= 599:
            return tweepy.TwitterServerError(response)
        else:
            return tweepy.TweepyException(response)

    def _generate_csrf_token(self, size: int = 16) -> str:
        """
        生成 Twitter 的 CSRF 令牌（Cookie 中的 "ct0" 值）

        Args:
            size (int, optional): 令牌大小. Defaults to 16.

        Returns:
            str: 生成的令牌
        """

        data = random.getrandbits(size * 8).to_bytes(size, "big")
        return binascii.hexlify(data).decode()

    def _get_guest_token(self) -> str:
        """
        获取访客令牌（Cookie 中的 "gt" 值）

        Returns:
            str: 获取的令牌
        """

        # HTTP 请求头基本使用认证会话的请求头
        headers = self._auth_flow_api_headers.copy()
        headers.pop('x-csrf-token')
        headers.pop('x-guest-token')

        # 从 API 获取访客令牌
        # ref: https://github.com/fa0311/TwitterFrontendFlow/blob/master/TwitterFrontendFlow/TwitterFrontendFlow.py#L26-L36
        guest_token_response = self._session.post('https://api.x.com/1.1/guest/activate.json', headers=headers)
        if guest_token_response.status_code != 200:
            raise self._get_tweepy_exception(guest_token_response)
        try:
            guest_token = guest_token_response.json()['guest_token']
        except:
            raise tweepy.TweepyException('Failed to get guest token')

        return guest_token

    def _get_ui_metrics(self, js_inst: str) -> Dict[str, Any]:
        """
        从 https://x.com/i/js_inst?c_name=ui_metrics 获取混淆的 JavaScript 中的 ui_metrics
        参考: https://github.com/hfthair/TweetScraper/blob/master/TweetScraper/spiders/following.py#L50-L94

        Args:
            js_inst (str): 混淆的 JavaScript

        Returns:
            dict[str, Any]: 获取的 ui_metrics
        """

        # 从混淆的 JavaScript 中提取获取 ui_metrics 的函数
        js_inst_function = js_inst.split('\n')[2]
        js_inst_function_name = re.search(re.compile(r'function [a-zA-Z]+'), js_inst_function).group().replace(
            'function ', '')  # type: ignore

        # 模拟 DOM API 以执行混淆的 JavaScript
        ## 暂时只模拟最基本的必要功能
        js_dom_mock = """
            var _element = {
                appendChild: function(x) {
                    // do nothing
                },
                removeChild: function(x) {
                    // do nothing
                },
                setAttribute: function(x, y) {
                    // do nothing
                },
                innerText: '',
                innerHTML: '',
                outerHTML: '',
                tagName: '',
                textContent: '',
            }
            _element['children'] = [_element];
            _element['firstElementChild'] = _element;
            _element['lastElementChild'] = _element;
            _element['nextSibling'] = _element;
            _element['nextElementSibling'] = _element;
            _element['parentNode'] = _element;
            _element['previousSibling'] = _element;
            _element['previousElementSibling'] = _element;
            document = {
                createElement: function(x) {
                    return _element;
                },
                getElementById: function(x) {
                    return _element;
                },
                getElementsByClassName: function(x) {
                    return [_element];
                },
                getElementsByName: function(x) {
                    return [_element];
                },
                getElementsByTagName: function(x) {
                    return [_element];
                },
                getElementsByTagNameNS: function(x, y) {
                    return [_element];
                },
                querySelector: function(x) {
                    return _element;
                },
                querySelectorAll: function(x) {
                    return [_element];
                },
            }
            """

        # 执行混淆的 JavaScript
        js_context = js2py.EvalJs()
        js_context.execute(js_dom_mock)
        js_context.execute(js_inst_function)
        js_context.execute(f'var ui_metrics = {js_inst_function_name}()')

        # 获取 ui_metrics
        ui_metrics = cast(JsObjectWrapper, js_context.ui_metrics)
        return cast(Dict[str, Any], ui_metrics.to_dict())

    def _login(self) -> None:
        """
        使用用户名和密码进行认证并登录

        Raises:
            tweepy.BadRequest: 用户名或密码错误
            tweepy.HTTPException: 由于服务器错误等问题导致登录失败
            tweepy.TweepyException: 认证流程中发生错误导致登录失败
        """

        def get_flow_token(response: requests.Response) -> str:
            try:
                data = response.json()
            except Exception:
                pass
            else:
                if response.status_code < 400:
                    return data['flow_token']
            raise self._get_tweepy_exception(response)

        def get_excepted_subtask(response: requests.Response, subtask_id: str) -> Dict[str, Any]:
            try:
                data = response.json()
                print(f'get_excepted_subtask: {data}')
            except Exception:
                pass
            else:
                if response.status_code < 400:
                    for subtask in data['subtasks']:
                        if subtask['subtask_id'] == subtask_id:
                            return subtask
                    raise tweepy.TweepyException(f'{subtask_id} not found in response')
            raise self._get_tweepy_exception(response)

        # 清除 Cookie
        self._session.cookies.clear()

        # 先访问 https://x.com/ 以设置 Cookie
        ## 获取的 HTML 用于获取访客令牌
        html_response = self._session.get('https://x.com/i/flow/login', headers=self._html_headers)
        if html_response.status_code != 200:
            raise self._get_tweepy_exception(html_response)

        # 生成 CSRF 令牌并作为 "ct0" 保存到会话的 Cookie 中
        ## 同时也设置到认证流程 API 的 HTTP 请求头中（"ct0" 和 "x-csrf-token" 值相同）
        csrf_token = self._generate_csrf_token()
        self._session.cookies.set('ct0', csrf_token, domain='.x.com')
        self._auth_flow_api_headers['x-csrf-token'] = csrf_token

        # 仅在尚未获取时，获取访客令牌并作为 "gt" 保存到会话的 Cookie 中
        if self._session.cookies.get('gt', default=None) is None:
            guest_token = self._get_guest_token()
            self._session.cookies.set('gt', guest_token, domain='.x.com')

        ## 将访客令牌也设置到认证流程 API 的 HTTP 请求头中（"gt" 和 "x-guest-token" 值相同）
        self._auth_flow_api_headers['x-guest-token'] = self._session.cookies.get('gt')

        # 此后基本只访问认证流程 API，所以将会话的请求头替换为认证流程 API 专用的请求头
        self._session.headers.clear()
        self._session.headers.update(self._auth_flow_api_headers)

        # 为了尽可能模拟官方 Twitter Web App 而发送的虚拟请求
        self._session.get('https://api.x.com/1.1/hashflags.json')

        # 向 https://api.x.com/1.1/onboarding/task.json?task=login 发送 POST 请求以开始认证流程
        ## 开始认证流程需要在 Cookie 中设置 "ct0" 和 "gt"
        ## 模拟 2024年5月时的 Twitter Web App 发送的 JSON 参数
        flow_01_response = self._session.post('https://api.x.com/1.1/onboarding/task.json?flow_name=login', json={
            'input_flow_data': {
                'flow_context': {
                    'debug_overrides': {},
                    'start_location': {
                        'location': 'manual_link',
                    }
                }
            },
            'subtask_versions': {
                'action_list': 2,
                'alert_dialog': 1,
                'app_download_cta': 1,
                'check_logged_in_account': 1,
                'choice_selection': 3,
                'contacts_live_sync_permission_prompt': 0,
                'cta': 7,
                'email_verification': 2,
                'end_flow': 1,
                'enter_date': 1,
                'enter_email': 2,
                'enter_password': 5,
                'enter_phone': 2,
                'enter_recaptcha': 1,
                'enter_text': 5,
                'enter_username': 2,
                'generic_urt': 3,
                'in_app_notification': 1,
                'interest_picker': 3,
                'js_instrumentation': 1,
                'menu_dialog': 1,
                'notifications_permission_prompt': 2,
                'open_account': 2,
                'open_home_timeline': 1,
                'open_link': 1,
                'phone_verification': 4,
                'privacy_options': 1,
                'security_key': 3,
                'select_avatar': 4,
                'select_banner': 2,
                'settings_list': 7,
                'show_code': 1,
                'sign_up': 2,
                'sign_up_review': 4,
                'tweet_selection_urt': 1,
                'update_users': 1,
                'upload_media': 1,
                'user_recommendations_list': 4,
                'user_recommendations_urt': 1,
                'wait_spinner': 3,
                'web_modal': 1,
            }
        })
        if flow_01_response.status_code != 200:
            raise self._get_tweepy_exception(flow_01_response)

        # 从 flow_01 响应中获取 js_inst 的 URL
        # 如果 subtasks 中不包含 LoginJsInstrumentationSubtask，则抛出异常
        js_inst_subtask = get_excepted_subtask(flow_01_response, 'LoginJsInstrumentationSubtask')
        js_inst_url = js_inst_subtask['js_instrumentation']['url']

        # 获取 js_inst（混淆的 JavaScript，需要将其执行结果发送到认证流程）
        js_inst_response = self._session.get(js_inst_url, headers=self._js_headers)
        if js_inst_response.status_code != 200:
            raise tweepy.TweepyException('Failed to get js_inst')

        # 执行 js_inst 的 JavaScript 并获取 ui_metrics 对象
        ui_metrics = self._get_ui_metrics(js_inst_response.text)

        # 将获取的 ui_metrics 发送到认证流程
        flow_02_response = self._session.post('https://api.x.com/1.1/onboarding/task.json', json={
            'flow_token': get_flow_token(flow_01_response),
            'subtask_inputs': [
                {
                    'subtask_id': 'LoginJsInstrumentationSubtask',
                    'js_instrumentation': {
                        'response': json.dumps(ui_metrics),
                        'link': 'next_link',
                    }
                },
            ]
        })
        if flow_02_response.status_code != 200:
            raise self._get_tweepy_exception(flow_02_response)

        # 如果 subtasks 中不包含 LoginEnterUserIdentifierSSO，则抛出异常
        get_excepted_subtask(flow_02_response, 'LoginEnterUserIdentifierSSO')

        # 为了尽可能模拟官方 Twitter Web App 而发送的虚拟请求
        self._session.post('https://api.x.com/1.1/onboarding/sso_init.json', json={'provider': 'apple'})

        # 为避免可疑，随机等待1-3秒
        time.sleep(random.uniform(1.0, 3.0))

        # 将用户名发送到认证流程
        flow_03_response = self._session.post('https://api.x.com/1.1/onboarding/task.json', json={
            'flow_token': get_flow_token(flow_02_response),
            'subtask_inputs': [
                {
                    'subtask_id': 'LoginEnterUserIdentifierSSO',
                    'settings_list': {
                        'setting_responses': [
                            {
                                'key': 'user_identifier',
                                'response_data': {
                                    'text_data': {
                                        'result': self.screen_name,
                                    }
                                }
                            },
                        ],
                        'link': 'next_link',
                    }
                },
            ]
        })
        if flow_03_response.status_code != 200:
            raise self._get_tweepy_exception(flow_03_response)

        # 如果 subtasks 中不包含 LoginEnterPassword，则抛出异常
        get_excepted_subtask(flow_03_response, 'LoginEnterPassword')

        # 为避免可疑，随机等待2-4秒
        time.sleep(random.uniform(2.0, 4.0))

        # 将密码发送到认证流程
        flow_04_response = self._session.post('https://api.x.com/1.1/onboarding/task.json', json={
            'flow_token': get_flow_token(flow_03_response),
            'subtask_inputs': [
                {
                    'subtask_id': 'LoginEnterPassword',
                    'enter_password': {
                        'password': self.password,
                        'link': 'next_link',
                    }
                },
            ]
        })
        if flow_04_response.status_code != 200:
            raise self._get_tweepy_exception(flow_04_response)

        # 登录失败
        if flow_04_response.json()['status'] != 'success':
            raise tweepy.TweepyException(f'Failed to login (status: {flow_04_response.json()["status"]})')

        # 如果 subtasks 中不包含 SuccessExit，则抛出异常
        get_excepted_subtask(flow_04_response, 'LoginAcid')

        print(find_dict(flow_04_response.json(), 'secondary_text', find_one=True)[0]['text'])

        # 为避免可疑，随机等待3-5秒
        time.sleep(random.uniform(3.0, 5.0))

        flow_05_response = self._session.post('https://api.x.com/1.1/onboarding/task.json', json={
            'flow_token': get_flow_token(flow_04_response),
            'subtask_inputs': [
                {
                    'subtask_id': 'LoginAcid',
                    'enter_text': {
                        # 电子邮箱认证
                        'text': input('>>> '),
                        'link': 'next_link',
                    }
                },
            ]
        })
        if flow_05_response.status_code != 200:
            raise self._get_tweepy_exception(flow_05_response)

        # 在最后进行终结化处理
        ## 通过这个请求，auth_token 将被设置到 Cookie 中
        ## 在这个时机，Cookie 中的 "ct0" 值(CSRF令牌)会从客户端生成的值更新为服务器端生成的值
        # flow_05_response = self._session.post('https://api.x.com/1.1/onboarding/task.json', json={
        #     'flow_token': get_flow_token(flow_04_response),
        #     'subtask_inputs': [],
        # })
        # if flow_05_response.status_code != 200:
        #     raise self._get_tweepy_exception(flow_05_response)

        # 到这一步应该已经登录成功了
        ## Cookie 中包含了登录所需的信息
        ## 实际上认证最低限度只需要 "auth_token" 和 "ct0" 这两个 Cookie（不过如果只发送这两个可能会显得可疑，所以也会发送其他值）
        ## 参考: https://qiita.com/SNQ-2001/items/182b278e1e8aaaa21a13

def find_dict(obj: list | dict, key: str | int, find_one: bool = False) -> list[Any]:
    """
    Retrieves elements from a nested dictionary.
    """
    results = []
    if isinstance(obj, dict):
        if key in obj:
            results.append(obj.get(key))
            if find_one:
                return results
    if isinstance(obj, (list, dict)):
        for elem in (obj if isinstance(obj, list) else obj.values()):
            r = find_dict(elem, key, find_one)
            results += r
            if r and find_one:
                return results
    return results
