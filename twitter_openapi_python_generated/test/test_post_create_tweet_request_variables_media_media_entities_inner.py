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

from twitter_openapi_python_generated.models.post_create_tweet_request_variables_media_media_entities_inner import PostCreateTweetRequestVariablesMediaMediaEntitiesInner

class TestPostCreateTweetRequestVariablesMediaMediaEntitiesInner(unittest.TestCase):
    """PostCreateTweetRequestVariablesMediaMediaEntitiesInner unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> PostCreateTweetRequestVariablesMediaMediaEntitiesInner:
        """Test PostCreateTweetRequestVariablesMediaMediaEntitiesInner
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `PostCreateTweetRequestVariablesMediaMediaEntitiesInner`
        """
        model = PostCreateTweetRequestVariablesMediaMediaEntitiesInner()
        if include_optional:
            return PostCreateTweetRequestVariablesMediaMediaEntitiesInner(
                media_id = '1111111111111111111',
                tagged_users = [
                    None
                    ]
            )
        else:
            return PostCreateTweetRequestVariablesMediaMediaEntitiesInner(
                media_id = '1111111111111111111',
                tagged_users = [
                    None
                    ],
        )
        """

    def testPostCreateTweetRequestVariablesMediaMediaEntitiesInner(self):
        """Test PostCreateTweetRequestVariablesMediaMediaEntitiesInner"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
