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

from twitter_openapi_python_generated.models.community_actions import CommunityActions

class TestCommunityActions(unittest.TestCase):
    """CommunityActions unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> CommunityActions:
        """Test CommunityActions
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `CommunityActions`
        """
        model = CommunityActions()
        if include_optional:
            return CommunityActions(
                delete_action_result = twitter_openapi_python_generated.models.community_delete_action_result.CommunityDeleteActionResult(
                    __typename = 'TimelineTweet', 
                    reason = 'Unavailable', ),
                join_action_result = twitter_openapi_python_generated.models.community_join_action_result.CommunityJoinActionResult(
                    __typename = 'TimelineTweet', ),
                leave_action_result = twitter_openapi_python_generated.models.community_leave_action_result.CommunityLeaveActionResult(
                    __typename = 'TimelineTweet', 
                    message = '', 
                    reason = 'ViewerNotMember', ),
                pin_action_result = twitter_openapi_python_generated.models.community_pin_action_result.CommunityPinActionResult(
                    __typename = 'TimelineTweet', )
            )
        else:
            return CommunityActions(
                delete_action_result = twitter_openapi_python_generated.models.community_delete_action_result.CommunityDeleteActionResult(
                    __typename = 'TimelineTweet', 
                    reason = 'Unavailable', ),
                join_action_result = twitter_openapi_python_generated.models.community_join_action_result.CommunityJoinActionResult(
                    __typename = 'TimelineTweet', ),
                leave_action_result = twitter_openapi_python_generated.models.community_leave_action_result.CommunityLeaveActionResult(
                    __typename = 'TimelineTweet', 
                    message = '', 
                    reason = 'ViewerNotMember', ),
                pin_action_result = twitter_openapi_python_generated.models.community_pin_action_result.CommunityPinActionResult(
                    __typename = 'TimelineTweet', ),
        )
        """

    def testCommunityActions(self):
        """Test CommunityActions"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
