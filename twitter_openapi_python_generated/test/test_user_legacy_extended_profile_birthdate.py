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

from twitter_openapi_python_generated.models.user_legacy_extended_profile_birthdate import UserLegacyExtendedProfileBirthdate

class TestUserLegacyExtendedProfileBirthdate(unittest.TestCase):
    """UserLegacyExtendedProfileBirthdate unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> UserLegacyExtendedProfileBirthdate:
        """Test UserLegacyExtendedProfileBirthdate
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `UserLegacyExtendedProfileBirthdate`
        """
        model = UserLegacyExtendedProfileBirthdate()
        if include_optional:
            return UserLegacyExtendedProfileBirthdate(
                day = 56,
                month = 56,
                visibility = 'Self',
                year = 56,
                year_visibility = 'Self'
            )
        else:
            return UserLegacyExtendedProfileBirthdate(
                day = 56,
                month = 56,
                visibility = 'Self',
                year = 56,
                year_visibility = 'Self',
        )
        """

    def testUserLegacyExtendedProfileBirthdate(self):
        """Test UserLegacyExtendedProfileBirthdate"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
