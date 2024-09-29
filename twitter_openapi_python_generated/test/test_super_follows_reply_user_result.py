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

from twitter_openapi_python_generated.models.super_follows_reply_user_result import SuperFollowsReplyUserResult

class TestSuperFollowsReplyUserResult(unittest.TestCase):
    """SuperFollowsReplyUserResult unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> SuperFollowsReplyUserResult:
        """Test SuperFollowsReplyUserResult
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `SuperFollowsReplyUserResult`
        """
        model = SuperFollowsReplyUserResult()
        if include_optional:
            return SuperFollowsReplyUserResult(
                result = twitter_openapi_python_generated.models.super_follows_reply_user_result_data.SuperFollowsReplyUserResultData(
                    __typename = 'TimelineTweet', 
                    legacy = twitter_openapi_python_generated.models.super_follows_reply_user_result_legacy.SuperFollowsReplyUserResultLegacy(
                        screen_name = '', ), )
            )
        else:
            return SuperFollowsReplyUserResult(
                result = twitter_openapi_python_generated.models.super_follows_reply_user_result_data.SuperFollowsReplyUserResultData(
                    __typename = 'TimelineTweet', 
                    legacy = twitter_openapi_python_generated.models.super_follows_reply_user_result_legacy.SuperFollowsReplyUserResultLegacy(
                        screen_name = '', ), ),
        )
        """

    def testSuperFollowsReplyUserResult(self):
        """Test SuperFollowsReplyUserResult"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
