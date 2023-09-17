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
from twitter_openapi_python_generated.models.module_item import ModuleItem  # noqa: E501
from twitter_openapi_python_generated.rest import ApiException

class TestModuleItem(unittest.TestCase):
    """ModuleItem unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test ModuleItem
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `ModuleItem`
        """
        model = twitter_openapi_python_generated.models.module_item.ModuleItem()  # noqa: E501
        if include_optional :
            return ModuleItem(
                entry_id = '25375e030fccba00917317c574773100bf03b5f', 
                item = twitter_openapi_python_generated.models.module_entry.ModuleEntry(
                    client_event_info = twitter_openapi_python_generated.models.client_event_info.ClientEventInfo(
                        component = '', 
                        details = { }, 
                        element = '', ), 
                    item_content = null, )
            )
        else :
            return ModuleItem(
                entry_id = '25375e030fccba00917317c574773100bf03b5f',
                item = twitter_openapi_python_generated.models.module_entry.ModuleEntry(
                    client_event_info = twitter_openapi_python_generated.models.client_event_info.ClientEventInfo(
                        component = '', 
                        details = { }, 
                        element = '', ), 
                    item_content = null, ),
        )
        """

    def testModuleItem(self):
        """Test ModuleItem"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
