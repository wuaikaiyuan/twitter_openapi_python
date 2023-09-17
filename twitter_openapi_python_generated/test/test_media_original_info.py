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
from twitter_openapi_python_generated.models.media_original_info import MediaOriginalInfo  # noqa: E501
from twitter_openapi_python_generated.rest import ApiException

class TestMediaOriginalInfo(unittest.TestCase):
    """MediaOriginalInfo unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test MediaOriginalInfo
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `MediaOriginalInfo`
        """
        model = twitter_openapi_python_generated.models.media_original_info.MediaOriginalInfo()  # noqa: E501
        if include_optional :
            return MediaOriginalInfo(
                focus_rects = [
                    twitter_openapi_python_generated.models.media_original_info_focus_rect.MediaOriginalInfoFocusRect(
                        h = 56, 
                        w = 56, 
                        x = 56, 
                        y = 56, )
                    ], 
                height = 56, 
                width = 56
            )
        else :
            return MediaOriginalInfo(
                height = 56,
                width = 56,
        )
        """

    def testMediaOriginalInfo(self):
        """Test MediaOriginalInfo"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
