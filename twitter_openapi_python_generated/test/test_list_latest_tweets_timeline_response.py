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
from twitter_openapi_python_generated.models.list_latest_tweets_timeline_response import ListLatestTweetsTimelineResponse  # noqa: E501
from twitter_openapi_python_generated.rest import ApiException

class TestListLatestTweetsTimelineResponse(unittest.TestCase):
    """ListLatestTweetsTimelineResponse unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test ListLatestTweetsTimelineResponse
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `ListLatestTweetsTimelineResponse`
        """
        model = twitter_openapi_python_generated.models.list_latest_tweets_timeline_response.ListLatestTweetsTimelineResponse()  # noqa: E501
        if include_optional :
            return ListLatestTweetsTimelineResponse(
                data = twitter_openapi_python_generated.models.list_tweets_timeline_data.ListTweetsTimelineData(
                    list = twitter_openapi_python_generated.models.list_tweets_timeline_list.ListTweetsTimelineList(
                        tweets_timeline = twitter_openapi_python_generated.models.list_tweets_timeline.ListTweetsTimeline(
                            timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                                instructions = [
                                    null
                                    ], 
                                metadata = { }, 
                                response_objects = { }, ), ), ), )
            )
        else :
            return ListLatestTweetsTimelineResponse(
                data = twitter_openapi_python_generated.models.list_tweets_timeline_data.ListTweetsTimelineData(
                    list = twitter_openapi_python_generated.models.list_tweets_timeline_list.ListTweetsTimelineList(
                        tweets_timeline = twitter_openapi_python_generated.models.list_tweets_timeline.ListTweetsTimeline(
                            timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                                instructions = [
                                    null
                                    ], 
                                metadata = { }, 
                                response_objects = { }, ), ), ), ),
        )
        """

    def testListLatestTweetsTimelineResponse(self):
        """Test ListLatestTweetsTimelineResponse"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
