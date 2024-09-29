# coding: utf-8

"""
    Twitter OpenAPI

    Twitter OpenAPI(Swagger) specification

    The version of the OpenAPI document: 0.0.1
    Contact: yuki@yuki0311.com
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


import unittest

from twitter_openapi_python_generated.models.get_profile_spotlights_query200_response import GetProfileSpotlightsQuery200Response

class TestGetProfileSpotlightsQuery200Response(unittest.TestCase):
    """GetProfileSpotlightsQuery200Response unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> GetProfileSpotlightsQuery200Response:
        """Test GetProfileSpotlightsQuery200Response
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `GetProfileSpotlightsQuery200Response`
        """
        model = GetProfileSpotlightsQuery200Response()
        if include_optional:
            return GetProfileSpotlightsQuery200Response(
                data = twitter_openapi_python_generated.models.profile_response_data.ProfileResponseData(
                    user_result_by_screen_name = twitter_openapi_python_generated.models.user_result_by_screen_name.UserResultByScreenName(
                        id = 'zA9LCSLv1C1ylmgd0/Y2TA5TkIRHRRA401iz1CiIykN3HUO6XMsJPGh8AsaLONiNuo2ZPKNpkAmJHONf1Elbsh0SR//=', 
                        result = twitter_openapi_python_generated.models.user_result_by_screen_name_result.UserResultByScreenNameResult(
                            __typename = 'TimelineTweet', 
                            id = 'G', 
                            legacy = twitter_openapi_python_generated.models.user_result_by_screen_name_legacy.UserResultByScreenNameLegacy(
                                blocked_by = True, 
                                blocking = True, 
                                followed_by = True, 
                                following = True, 
                                name = '', 
                                protected = True, 
                                screen_name = '', ), 
                            profilemodules = { }, 
                            rest_id = '4', ), ), ),
                errors = [
                    twitter_openapi_python_generated.models.error.Error(
                        code = 56, 
                        extensions = twitter_openapi_python_generated.models.error_extensions.ErrorExtensions(
                            code = 56, 
                            kind = '', 
                            name = '', 
                            retry_after = 56, 
                            source = '', 
                            tracing = twitter_openapi_python_generated.models.tracing.Tracing(
                                trace_id = 'bf325375e030fccb', ), ), 
                        kind = '', 
                        locations = [
                            twitter_openapi_python_generated.models.location.Location(
                                column = 56, 
                                line = 56, )
                            ], 
                        message = '', 
                        name = '', 
                        path = [
                            ''
                            ], 
                        retry_after = 56, 
                        source = '', 
                        tracing = twitter_openapi_python_generated.models.tracing.Tracing(
                            trace_id = 'bf325375e030fccb', ), )
                    ]
            )
        else:
            return GetProfileSpotlightsQuery200Response(
                data = twitter_openapi_python_generated.models.profile_response_data.ProfileResponseData(
                    user_result_by_screen_name = twitter_openapi_python_generated.models.user_result_by_screen_name.UserResultByScreenName(
                        id = 'zA9LCSLv1C1ylmgd0/Y2TA5TkIRHRRA401iz1CiIykN3HUO6XMsJPGh8AsaLONiNuo2ZPKNpkAmJHONf1Elbsh0SR//=', 
                        result = twitter_openapi_python_generated.models.user_result_by_screen_name_result.UserResultByScreenNameResult(
                            __typename = 'TimelineTweet', 
                            id = 'G', 
                            legacy = twitter_openapi_python_generated.models.user_result_by_screen_name_legacy.UserResultByScreenNameLegacy(
                                blocked_by = True, 
                                blocking = True, 
                                followed_by = True, 
                                following = True, 
                                name = '', 
                                protected = True, 
                                screen_name = '', ), 
                            profilemodules = { }, 
                            rest_id = '4', ), ), ),
                errors = [
                    twitter_openapi_python_generated.models.error.Error(
                        code = 56, 
                        extensions = twitter_openapi_python_generated.models.error_extensions.ErrorExtensions(
                            code = 56, 
                            kind = '', 
                            name = '', 
                            retry_after = 56, 
                            source = '', 
                            tracing = twitter_openapi_python_generated.models.tracing.Tracing(
                                trace_id = 'bf325375e030fccb', ), ), 
                        kind = '', 
                        locations = [
                            twitter_openapi_python_generated.models.location.Location(
                                column = 56, 
                                line = 56, )
                            ], 
                        message = '', 
                        name = '', 
                        path = [
                            ''
                            ], 
                        retry_after = 56, 
                        source = '', 
                        tracing = twitter_openapi_python_generated.models.tracing.Tracing(
                            trace_id = 'bf325375e030fccb', ), )
                    ],
        )
        """

    def testGetProfileSpotlightsQuery200Response(self):
        """Test GetProfileSpotlightsQuery200Response"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
