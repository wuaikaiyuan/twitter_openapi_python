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

from twitter_openapi_python_generated.models.community_data import CommunityData

class TestCommunityData(unittest.TestCase):
    """CommunityData unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> CommunityData:
        """Test CommunityData
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `CommunityData`
        """
        model = CommunityData()
        if include_optional:
            return CommunityData(
                typename = 'TimelineTweet',
                actions = twitter_openapi_python_generated.models.community_actions.CommunityActions(
                    delete_action_result = twitter_openapi_python_generated.models.community_delete_action_result.CommunityDeleteActionResult(
                        __typename = 'TimelineTweet', 
                        reason = 'Unavailable', ), 
                    join_action_result = twitter_openapi_python_generated.models.community_join_action_result.CommunityJoinActionResult(
                        __typename = 'TimelineTweet', ), 
                    leave_action_result = twitter_openapi_python_generated.models.community_leave_action_result.CommunityLeaveActionResult(
                        __typename = , 
                        message = '', 
                        reason = 'ViewerNotMember', ), 
                    pin_action_result = twitter_openapi_python_generated.models.community_pin_action_result.CommunityPinActionResult(
                        __typename = , ), ),
                admin_results = twitter_openapi_python_generated.models.user_results.UserResults(
                    result = null, ),
                created_at = 56,
                creator_results = twitter_openapi_python_generated.models.user_results.UserResults(
                    result = null, ),
                custom_banner_media = { },
                default_banner_media = { },
                description = '',
                id_str = '4',
                invites_policy = 'MemberInvitesAllowed',
                invites_result = twitter_openapi_python_generated.models.community_invites_result.CommunityInvitesResult(
                    __typename = 'TimelineTweet', 
                    message = '', 
                    reason = 'Unavailable', ),
                is_pinned = True,
                join_policy = 'Open',
                join_requests_result = twitter_openapi_python_generated.models.community_join_requests_result.CommunityJoinRequestsResult(
                    __typename = 'TimelineTweet', ),
                member_count = 56,
                members_facepile_results = [
                    twitter_openapi_python_generated.models.user_results.UserResults(
                        result = null, )
                    ],
                moderator_count = 56,
                name = '',
                primary_community_topic = twitter_openapi_python_generated.models.primary_community_topic.PrimaryCommunityTopic(
                    topic_id = '4', 
                    topic_name = '', ),
                question = '',
                role = 'NonMember',
                rules = [
                    twitter_openapi_python_generated.models.community_rule.CommunityRule(
                        description = '', 
                        name = '', 
                        rest_id = '4', )
                    ],
                search_tags = [
                    ''
                    ],
                show_only_users_to_display = [
                    ''
                    ],
                urls = twitter_openapi_python_generated.models.community_urls.CommunityUrls(
                    permalink = twitter_openapi_python_generated.models.community_urls_permalink.CommunityUrlsPermalink(
                        url = '', ), ),
                viewer_relationship = { }
            )
        else:
            return CommunityData(
                typename = 'TimelineTweet',
                actions = twitter_openapi_python_generated.models.community_actions.CommunityActions(
                    delete_action_result = twitter_openapi_python_generated.models.community_delete_action_result.CommunityDeleteActionResult(
                        __typename = 'TimelineTweet', 
                        reason = 'Unavailable', ), 
                    join_action_result = twitter_openapi_python_generated.models.community_join_action_result.CommunityJoinActionResult(
                        __typename = 'TimelineTweet', ), 
                    leave_action_result = twitter_openapi_python_generated.models.community_leave_action_result.CommunityLeaveActionResult(
                        __typename = , 
                        message = '', 
                        reason = 'ViewerNotMember', ), 
                    pin_action_result = twitter_openapi_python_generated.models.community_pin_action_result.CommunityPinActionResult(
                        __typename = , ), ),
                admin_results = twitter_openapi_python_generated.models.user_results.UserResults(
                    result = null, ),
                creator_results = twitter_openapi_python_generated.models.user_results.UserResults(
                    result = null, ),
                description = '',
                id_str = '4',
                invites_policy = 'MemberInvitesAllowed',
                invites_result = twitter_openapi_python_generated.models.community_invites_result.CommunityInvitesResult(
                    __typename = 'TimelineTweet', 
                    message = '', 
                    reason = 'Unavailable', ),
                is_pinned = True,
                join_policy = 'Open',
                member_count = 56,
                members_facepile_results = [
                    twitter_openapi_python_generated.models.user_results.UserResults(
                        result = null, )
                    ],
                moderator_count = 56,
                name = '',
                primary_community_topic = twitter_openapi_python_generated.models.primary_community_topic.PrimaryCommunityTopic(
                    topic_id = '4', 
                    topic_name = '', ),
                question = '',
                role = 'NonMember',
                rules = [
                    twitter_openapi_python_generated.models.community_rule.CommunityRule(
                        description = '', 
                        name = '', 
                        rest_id = '4', )
                    ],
                search_tags = [
                    ''
                    ],
        )
        """

    def testCommunityData(self):
        """Test CommunityData"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
