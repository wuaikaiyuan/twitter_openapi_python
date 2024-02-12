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

from twitter_openapi_python_generated.models.favorite_tweet_response_data import FavoriteTweetResponseData

class TestFavoriteTweetResponseData(unittest.TestCase):
    """FavoriteTweetResponseData unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> FavoriteTweetResponseData:
        """Test FavoriteTweetResponseData
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `FavoriteTweetResponseData`
        """
        model = FavoriteTweetResponseData()
        if include_optional:
            return FavoriteTweetResponseData(
                data = twitter_openapi_python_generated.models.favorite_tweet.FavoriteTweet(
                    favorite_tweet = '', )
            )
        else:
            return FavoriteTweetResponseData(
                data = twitter_openapi_python_generated.models.favorite_tweet.FavoriteTweet(
                    favorite_tweet = '', ),
        )
        """

    def testFavoriteTweetResponseData(self):
        """Test FavoriteTweetResponseData"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
