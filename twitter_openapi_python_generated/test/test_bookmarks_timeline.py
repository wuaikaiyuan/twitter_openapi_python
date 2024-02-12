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

from twitter_openapi_python_generated.models.bookmarks_timeline import BookmarksTimeline

class TestBookmarksTimeline(unittest.TestCase):
    """BookmarksTimeline unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> BookmarksTimeline:
        """Test BookmarksTimeline
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `BookmarksTimeline`
        """
        model = BookmarksTimeline()
        if include_optional:
            return BookmarksTimeline(
                timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                    instructions = [
                        null
                        ], 
                    metadata = { }, 
                    response_objects = { }, )
            )
        else:
            return BookmarksTimeline(
                timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                    instructions = [
                        null
                        ], 
                    metadata = { }, 
                    response_objects = { }, ),
        )
        """

    def testBookmarksTimeline(self):
        """Test BookmarksTimeline"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
