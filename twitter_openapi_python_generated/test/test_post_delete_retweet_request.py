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

from twitter_openapi_python_generated.models.post_delete_retweet_request import PostDeleteRetweetRequest

class TestPostDeleteRetweetRequest(unittest.TestCase):
    """PostDeleteRetweetRequest unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> PostDeleteRetweetRequest:
        """Test PostDeleteRetweetRequest
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `PostDeleteRetweetRequest`
        """
        model = PostDeleteRetweetRequest()
        if include_optional:
            return PostDeleteRetweetRequest(
                query_id = 'iQtK4dl5hBmXewYZuEOKVw',
                variables = twitter_openapi_python_generated.models.post_delete_retweet_request_variables.postDeleteRetweet_request_variables(
                    dark_request = False, 
                    source_tweet_id = '1349129669258448897', )
            )
        else:
            return PostDeleteRetweetRequest(
                query_id = 'iQtK4dl5hBmXewYZuEOKVw',
                variables = twitter_openapi_python_generated.models.post_delete_retweet_request_variables.postDeleteRetweet_request_variables(
                    dark_request = False, 
                    source_tweet_id = '1349129669258448897', ),
        )
        """

    def testPostDeleteRetweetRequest(self):
        """Test PostDeleteRetweetRequest"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
