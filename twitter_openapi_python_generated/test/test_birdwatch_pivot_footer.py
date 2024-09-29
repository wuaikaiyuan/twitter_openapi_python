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

from twitter_openapi_python_generated.models.birdwatch_pivot_footer import BirdwatchPivotFooter

class TestBirdwatchPivotFooter(unittest.TestCase):
    """BirdwatchPivotFooter unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> BirdwatchPivotFooter:
        """Test BirdwatchPivotFooter
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `BirdwatchPivotFooter`
        """
        model = BirdwatchPivotFooter()
        if include_optional:
            return BirdwatchPivotFooter(
                entities = [
                    twitter_openapi_python_generated.models.birdwatch_entity.BirdwatchEntity(
                        from_index = 56, 
                        ref = twitter_openapi_python_generated.models.birdwatch_entity_ref.BirdwatchEntityRef(
                            text = '', 
                            type = 'TimelineUrl', 
                            url = '', 
                            url_type = 'ExternalUrl', ), 
                        to_index = 56, )
                    ],
                text = ''
            )
        else:
            return BirdwatchPivotFooter(
                entities = [
                    twitter_openapi_python_generated.models.birdwatch_entity.BirdwatchEntity(
                        from_index = 56, 
                        ref = twitter_openapi_python_generated.models.birdwatch_entity_ref.BirdwatchEntityRef(
                            text = '', 
                            type = 'TimelineUrl', 
                            url = '', 
                            url_type = 'ExternalUrl', ), 
                        to_index = 56, )
                    ],
                text = '',
        )
        """

    def testBirdwatchPivotFooter(self):
        """Test BirdwatchPivotFooter"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
