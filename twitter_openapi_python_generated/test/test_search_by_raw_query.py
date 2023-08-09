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
import datetime

import twitter_openapi_python_generated
from twitter_openapi_python_generated.models.search_by_raw_query import SearchByRawQuery  # noqa: E501
from twitter_openapi_python_generated.rest import ApiException

class TestSearchByRawQuery(unittest.TestCase):
    """SearchByRawQuery unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test SearchByRawQuery
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `SearchByRawQuery`
        """
        model = twitter_openapi_python_generated.models.search_by_raw_query.SearchByRawQuery()  # noqa: E501
        if include_optional :
            return SearchByRawQuery(
                search_timeline = twitter_openapi_python_generated.models.search_timeline.SearchTimeline(
                    timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                        instructions = [
                            null
                            ], 
                        metadata = { }, 
                        response_objects = { }, ), )
            )
        else :
            return SearchByRawQuery(
                search_timeline = twitter_openapi_python_generated.models.search_timeline.SearchTimeline(
                    timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                        instructions = [
                            null
                            ], 
                        metadata = { }, 
                        response_objects = { }, ), ),
        )
        """

    def testSearchByRawQuery(self):
        """Test SearchByRawQuery"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
