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

from twitter_openapi_python_generated.models.get_followers200_response import GetFollowers200Response

class TestGetFollowers200Response(unittest.TestCase):
    """GetFollowers200Response unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> GetFollowers200Response:
        """Test GetFollowers200Response
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `GetFollowers200Response`
        """
        model = GetFollowers200Response()
        if include_optional:
            return GetFollowers200Response(
                data = twitter_openapi_python_generated.models.follow_response_data.FollowResponseData(
                    user = twitter_openapi_python_generated.models.follow_response_user.FollowResponseUser(
                        result = twitter_openapi_python_generated.models.follow_response_result.FollowResponseResult(
                            __typename = 'TimelineTweet', 
                            timeline = twitter_openapi_python_generated.models.follow_timeline.FollowTimeline(
                                timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                                    instructions = [
                                        null
                                        ], 
                                    metadata = { }, 
                                    response_objects = { }, ), ), ), ), ),
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
            return GetFollowers200Response(
                data = twitter_openapi_python_generated.models.follow_response_data.FollowResponseData(
                    user = twitter_openapi_python_generated.models.follow_response_user.FollowResponseUser(
                        result = twitter_openapi_python_generated.models.follow_response_result.FollowResponseResult(
                            __typename = 'TimelineTweet', 
                            timeline = twitter_openapi_python_generated.models.follow_timeline.FollowTimeline(
                                timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                                    instructions = [
                                        null
                                        ], 
                                    metadata = { }, 
                                    response_objects = { }, ), ), ), ), ),
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

    def testGetFollowers200Response(self):
        """Test GetFollowers200Response"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
