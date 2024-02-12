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

from twitter_openapi_python_generated.models.get_search_timeline200_response import GetSearchTimeline200Response

class TestGetSearchTimeline200Response(unittest.TestCase):
    """GetSearchTimeline200Response unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> GetSearchTimeline200Response:
        """Test GetSearchTimeline200Response
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `GetSearchTimeline200Response`
        """
        model = GetSearchTimeline200Response()
        if include_optional:
            return GetSearchTimeline200Response(
                data = twitter_openapi_python_generated.models.search_timeline_data.SearchTimelineData(
                    search_by_raw_query = twitter_openapi_python_generated.models.search_by_raw_query.SearchByRawQuery(
                        search_timeline = twitter_openapi_python_generated.models.search_timeline.SearchTimeline(
                            timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                                instructions = [
                                    null
                                    ], 
                                metadata = { }, 
                                response_objects = { }, ), ), ), ),
                errors = [
                    twitter_openapi_python_generated.models.error.Error(
                        code = 56, 
                        extensions = twitter_openapi_python_generated.models.error_extensions.ErrorExtensions(
                            code = 56, 
                            kind = '', 
                            name = '', 
                            retry_after = 56, 
                            source = '', 
                            tracing = twitter_openapi_python_generated.models.tracing.Tracing(
                                trace_id = 'bf325375e030fccb', ), ), 
                        kind = '', 
                        locations = [
                            twitter_openapi_python_generated.models.location.Location(
                                column = 56, 
                                line = 56, )
                            ], 
                        message = '', 
                        name = '', 
                        path = [
                            ''
                            ], 
                        retry_after = 56, 
                        source = '', 
                        tracing = twitter_openapi_python_generated.models.tracing.Tracing(
                            trace_id = 'bf325375e030fccb', ), )
                    ]
            )
        else:
            return GetSearchTimeline200Response(
                data = twitter_openapi_python_generated.models.search_timeline_data.SearchTimelineData(
                    search_by_raw_query = twitter_openapi_python_generated.models.search_by_raw_query.SearchByRawQuery(
                        search_timeline = twitter_openapi_python_generated.models.search_timeline.SearchTimeline(
                            timeline = twitter_openapi_python_generated.models.timeline.Timeline(
                                instructions = [
                                    null
                                    ], 
                                metadata = { }, 
                                response_objects = { }, ), ), ), ),
                errors = [
                    twitter_openapi_python_generated.models.error.Error(
                        code = 56, 
                        extensions = twitter_openapi_python_generated.models.error_extensions.ErrorExtensions(
                            code = 56, 
                            kind = '', 
                            name = '', 
                            retry_after = 56, 
                            source = '', 
                            tracing = twitter_openapi_python_generated.models.tracing.Tracing(
                                trace_id = 'bf325375e030fccb', ), ), 
                        kind = '', 
                        locations = [
                            twitter_openapi_python_generated.models.location.Location(
                                column = 56, 
                                line = 56, )
                            ], 
                        message = '', 
                        name = '', 
                        path = [
                            ''
                            ], 
                        retry_after = 56, 
                        source = '', 
                        tracing = twitter_openapi_python_generated.models.tracing.Tracing(
                            trace_id = 'bf325375e030fccb', ), )
                    ],
        )
        """

    def testGetSearchTimeline200Response(self):
        """Test GetSearchTimeline200Response"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
