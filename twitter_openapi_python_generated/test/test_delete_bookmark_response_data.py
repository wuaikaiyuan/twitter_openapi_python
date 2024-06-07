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

from twitter_openapi_python_generated.models.delete_bookmark_response_data import DeleteBookmarkResponseData

class TestDeleteBookmarkResponseData(unittest.TestCase):
    """DeleteBookmarkResponseData unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> DeleteBookmarkResponseData:
        """Test DeleteBookmarkResponseData
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `DeleteBookmarkResponseData`
        """
        model = DeleteBookmarkResponseData()
        if include_optional:
            return DeleteBookmarkResponseData(
                tweet_bookmark_delete = ''
            )
        else:
            return DeleteBookmarkResponseData(
                tweet_bookmark_delete = '',
        )
        """

    def testDeleteBookmarkResponseData(self):
        """Test DeleteBookmarkResponseData"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
