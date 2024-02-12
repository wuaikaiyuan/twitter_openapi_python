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

from twitter_openapi_python_generated.models.social_context_landing_url import SocialContextLandingUrl

class TestSocialContextLandingUrl(unittest.TestCase):
    """SocialContextLandingUrl unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> SocialContextLandingUrl:
        """Test SocialContextLandingUrl
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `SocialContextLandingUrl`
        """
        model = SocialContextLandingUrl()
        if include_optional:
            return SocialContextLandingUrl(
                url = '',
                url_type = 'DeepLink',
                urt_endpoint_options = twitter_openapi_python_generated.models.urt_endpoint_options.UrtEndpointOptions(
                    request_params = [
                        twitter_openapi_python_generated.models.urt_endpoint_request_params.UrtEndpointRequestParams(
                            key = '', 
                            value = '', )
                        ], 
                    title = '', )
            )
        else:
            return SocialContextLandingUrl(
        )
        """

    def testSocialContextLandingUrl(self):
        """Test SocialContextLandingUrl"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
