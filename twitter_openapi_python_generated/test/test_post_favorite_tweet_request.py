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

from twitter_openapi_python_generated.models.post_favorite_tweet_request import PostFavoriteTweetRequest

class TestPostFavoriteTweetRequest(unittest.TestCase):
    """PostFavoriteTweetRequest unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> PostFavoriteTweetRequest:
        """Test PostFavoriteTweetRequest
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `PostFavoriteTweetRequest`
        """
        model = PostFavoriteTweetRequest()
        if include_optional:
            return PostFavoriteTweetRequest(
                query_id = 'lI07N6Otwv1PhnEgXILM7A',
                variables = twitter_openapi_python_generated.models.post_create_retweet_request_variables.postCreateRetweet_request_variables(
                    dark_request = False, 
                    tweet_id = '1349129669258448897', )
            )
        else:
            return PostFavoriteTweetRequest(
                query_id = 'lI07N6Otwv1PhnEgXILM7A',
                variables = twitter_openapi_python_generated.models.post_create_retweet_request_variables.postCreateRetweet_request_variables(
                    dark_request = False, 
                    tweet_id = '1349129669258448897', ),
        )
        """

    def testPostFavoriteTweetRequest(self):
        """Test PostFavoriteTweetRequest"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
