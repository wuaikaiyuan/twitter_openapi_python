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

from twitter_openapi_python_generated.models.author_community_relationship import AuthorCommunityRelationship

class TestAuthorCommunityRelationship(unittest.TestCase):
    """AuthorCommunityRelationship unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> AuthorCommunityRelationship:
        """Test AuthorCommunityRelationship
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `AuthorCommunityRelationship`
        """
        model = AuthorCommunityRelationship()
        if include_optional:
            return AuthorCommunityRelationship(
                community_results = twitter_openapi_python_generated.models.community.Community(
                    result = twitter_openapi_python_generated.models.community_data.CommunityData(
                        __typename = 'TimelineTweet', 
                        actions = twitter_openapi_python_generated.models.community_actions.CommunityActions(
                            delete_action_result = twitter_openapi_python_generated.models.community_delete_action_result.CommunityDeleteActionResult(
                                __typename = 'TimelineTweet', 
                                reason = 'Unavailable', ), 
                            join_action_result = twitter_openapi_python_generated.models.community_join_action_result.CommunityJoinActionResult(
                                __typename = , ), 
                            leave_action_result = twitter_openapi_python_generated.models.community_leave_action_result.CommunityLeaveActionResult(
                                __typename = , 
                                message = '', 
                                reason = 'ViewerNotMember', ), 
                            pin_action_result = twitter_openapi_python_generated.models.community_pin_action_result.CommunityPinActionResult(
                                __typename = , ), ), 
                        admin_results = twitter_openapi_python_generated.models.user_results.UserResults(), 
                        created_at = 56, 
                        creator_results = twitter_openapi_python_generated.models.user_results.UserResults(), 
                        custom_banner_media = { }, 
                        default_banner_media = { }, 
                        description = '', 
                        id_str = '4', 
                        invites_policy = 'MemberInvitesAllowed', 
                        invites_result = twitter_openapi_python_generated.models.community_invites_result.CommunityInvitesResult(
                            __typename = , 
                            message = '', 
                            reason = 'Unavailable', ), 
                        is_pinned = True, 
                        join_policy = 'Open', 
                        join_requests_result = twitter_openapi_python_generated.models.community_join_requests_result.CommunityJoinRequestsResult(
                            __typename = , ), 
                        member_count = 56, 
                        members_facepile_results = [
                            
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
                        viewer_relationship = { }, ), ),
                role = 'Member',
                user_results = twitter_openapi_python_generated.models.user_results.UserResults(
                    result = null, )
            )
        else:
            return AuthorCommunityRelationship(
                community_results = twitter_openapi_python_generated.models.community.Community(
                    result = twitter_openapi_python_generated.models.community_data.CommunityData(
                        __typename = 'TimelineTweet', 
                        actions = twitter_openapi_python_generated.models.community_actions.CommunityActions(
                            delete_action_result = twitter_openapi_python_generated.models.community_delete_action_result.CommunityDeleteActionResult(
                                __typename = 'TimelineTweet', 
                                reason = 'Unavailable', ), 
                            join_action_result = twitter_openapi_python_generated.models.community_join_action_result.CommunityJoinActionResult(
                                __typename = , ), 
                            leave_action_result = twitter_openapi_python_generated.models.community_leave_action_result.CommunityLeaveActionResult(
                                __typename = , 
                                message = '', 
                                reason = 'ViewerNotMember', ), 
                            pin_action_result = twitter_openapi_python_generated.models.community_pin_action_result.CommunityPinActionResult(
                                __typename = , ), ), 
                        admin_results = twitter_openapi_python_generated.models.user_results.UserResults(), 
                        created_at = 56, 
                        creator_results = twitter_openapi_python_generated.models.user_results.UserResults(), 
                        custom_banner_media = { }, 
                        default_banner_media = { }, 
                        description = '', 
                        id_str = '4', 
                        invites_policy = 'MemberInvitesAllowed', 
                        invites_result = twitter_openapi_python_generated.models.community_invites_result.CommunityInvitesResult(
                            __typename = , 
                            message = '', 
                            reason = 'Unavailable', ), 
                        is_pinned = True, 
                        join_policy = 'Open', 
                        join_requests_result = twitter_openapi_python_generated.models.community_join_requests_result.CommunityJoinRequestsResult(
                            __typename = , ), 
                        member_count = 56, 
                        members_facepile_results = [
                            
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
                        viewer_relationship = { }, ), ),
        )
        """

    def testAuthorCommunityRelationship(self):
        """Test AuthorCommunityRelationship"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
