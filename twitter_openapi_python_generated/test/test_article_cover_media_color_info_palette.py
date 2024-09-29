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

from twitter_openapi_python_generated.models.article_cover_media_color_info_palette import ArticleCoverMediaColorInfoPalette

class TestArticleCoverMediaColorInfoPalette(unittest.TestCase):
    """ArticleCoverMediaColorInfoPalette unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> ArticleCoverMediaColorInfoPalette:
        """Test ArticleCoverMediaColorInfoPalette
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `ArticleCoverMediaColorInfoPalette`
        """
        model = ArticleCoverMediaColorInfoPalette()
        if include_optional:
            return ArticleCoverMediaColorInfoPalette(
                percentage = 1.337,
                rgb = twitter_openapi_python_generated.models.article_cover_media_color_info_palette_rgb.ArticleCoverMediaColorInfoPaletteRGB(
                    blue = 56, 
                    green = 56, 
                    red = 56, )
            )
        else:
            return ArticleCoverMediaColorInfoPalette(
                percentage = 1.337,
                rgb = twitter_openapi_python_generated.models.article_cover_media_color_info_palette_rgb.ArticleCoverMediaColorInfoPaletteRGB(
                    blue = 56, 
                    green = 56, 
                    red = 56, ),
        )
        """

    def testArticleCoverMediaColorInfoPalette(self):
        """Test ArticleCoverMediaColorInfoPalette"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
