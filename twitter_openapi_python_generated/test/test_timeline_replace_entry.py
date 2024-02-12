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

from twitter_openapi_python_generated.models.timeline_replace_entry import TimelineReplaceEntry

class TestTimelineReplaceEntry(unittest.TestCase):
    """TimelineReplaceEntry unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> TimelineReplaceEntry:
        """Test TimelineReplaceEntry
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `TimelineReplaceEntry`
        """
        model = TimelineReplaceEntry()
        if include_optional:
            return TimelineReplaceEntry(
                entry = twitter_openapi_python_generated.models.timeline_add_entry.TimelineAddEntry(
                    content = null, 
                    entry_id = '25375e030fccba00917317c574773100bf03b5f', 
                    sort_index = '4', ),
                entry_id_to_replace = '',
                type = 'TimelineAddEntries'
            )
        else:
            return TimelineReplaceEntry(
                entry = twitter_openapi_python_generated.models.timeline_add_entry.TimelineAddEntry(
                    content = null, 
                    entry_id = '25375e030fccba00917317c574773100bf03b5f', 
                    sort_index = '4', ),
                entry_id_to_replace = '',
                type = 'TimelineAddEntries',
        )
        """

    def testTimelineReplaceEntry(self):
        """Test TimelineReplaceEntry"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
