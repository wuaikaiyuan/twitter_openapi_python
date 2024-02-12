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

from twitter_openapi_python_generated.models.follow_response_result import FollowResponseResult

class TestFollowResponseResult(unittest.TestCase):
    """FollowResponseResult unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> FollowResponseResult:
        """Test FollowResponseResult
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `FollowResponseResult`
        """
        model = FollowResponseResult()
        if include_optional:
            return FollowResponseResult(
                typename = 'TimelineTweet',
                timeline = twitter_openapi_python_generated.models.follow_timeline.FollowTimeline(
                    timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                        instructions = [
                            null
                            ], 
                        metadata = { }, 
                        response_objects = { }, ), )
            )
        else:
            return FollowResponseResult(
                typename = 'TimelineTweet',
                timeline = twitter_openapi_python_generated.models.follow_timeline.FollowTimeline(
                    timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                        instructions = [
                            null
                            ], 
                        metadata = { }, 
                        response_objects = { }, ), ),
        )
        """

    def testFollowResponseResult(self):
        """Test FollowResponseResult"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
