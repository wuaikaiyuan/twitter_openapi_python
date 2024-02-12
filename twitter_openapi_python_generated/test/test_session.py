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

from twitter_openapi_python_generated.models.session import Session

class TestSession(unittest.TestCase):
    """Session unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> Session:
        """Test Session
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `Session`
        """
        model = Session()
        if include_optional:
            return Session(
                sso_init_tokens = twitter_openapi_python_generated.models.sso_init_tokens.SsoInitTokens(),
                communities_actions = twitter_openapi_python_generated.models.communities_actions.CommunitiesActions(
                    create = True, ),
                country = 'AE',
                guest_id = '4',
                has_community_memberships = True,
                is_active_creator = True,
                is_restricted_session = True,
                is_super_follow_subscriber = True,
                language = 'ae',
                one_factor_login_eligibility = twitter_openapi_python_generated.models.one_factor_login_eligibility.OneFactorLoginEligibility(
                    fetch_status = '', ),
                super_followers_count = 56,
                super_follows_application_status = 'NotStarted',
                user_features = twitter_openapi_python_generated.models.user_features.UserFeatures(
                    mediatool_studio_library = True, ),
                user_id = '4'
            )
        else:
            return Session(
                communities_actions = twitter_openapi_python_generated.models.communities_actions.CommunitiesActions(
                    create = True, ),
                country = 'AE',
                guest_id = '4',
                has_community_memberships = True,
                is_active_creator = True,
                is_restricted_session = True,
                is_super_follow_subscriber = True,
                language = 'ae',
                one_factor_login_eligibility = twitter_openapi_python_generated.models.one_factor_login_eligibility.OneFactorLoginEligibility(
                    fetch_status = '', ),
                super_followers_count = 56,
                super_follows_application_status = 'NotStarted',
                user_features = twitter_openapi_python_generated.models.user_features.UserFeatures(
                    mediatool_studio_library = True, ),
                user_id = '4',
        )
        """

    def testSession(self):
        """Test Session"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
