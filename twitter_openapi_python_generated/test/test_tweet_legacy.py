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
from twitter_openapi_python_generated.models.tweet_legacy import TweetLegacy  # noqa: E501
from twitter_openapi_python_generated.rest import ApiException

class TestTweetLegacy(unittest.TestCase):
    """TweetLegacy unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test TweetLegacy
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `TweetLegacy`
        """
        model = twitter_openapi_python_generated.models.tweet_legacy.TweetLegacy()  # noqa: E501
        if include_optional :
            return TweetLegacy(
                bookmark_count = 56, 
                bookmarked = True, 
                conversation_id_str = '4', 
                created_at = 'Sat Dec 31 23:59:59 +0000 2023', 
                display_text_range = [
                    56
                    ], 
                entities = twitter_openapi_python_generated.models.entities.Entities(
                    hashtags = [
                        { }
                        ], 
                    media = [
                        twitter_openapi_python_generated.models.media.Media(
                            display_url = '', 
                            expanded_url = '', 
                            ext_media_availability = { }, 
                            id_str = '4', 
                            indices = [
                                56
                                ], 
                            media_key = '4_072888001528021798096225500850762068629', 
                            media_url_https = '', 
                            original_info = twitter_openapi_python_generated.models.media_original_info.Media_original_info(
                                focus_rects = [
                                    { }
                                    ], 
                                height = 56, 
                                width = 56, ), 
                            sizes = { }, 
                            type = '', 
                            url = '', )
                        ], 
                    symbols = [
                        { }
                        ], 
                    urls = [
                        twitter_openapi_python_generated.models.url.Url(
                            display_url = '', 
                            expanded_url = '', 
                            indices = [
                                56
                                ], 
                            url = '', )
                        ], 
                    user_mentions = [
                        { }
                        ], ), 
                extended_entities = twitter_openapi_python_generated.models.extended_entities.ExtendedEntities(
                    media = [
                        twitter_openapi_python_generated.models.media.Media(
                            display_url = '', 
                            expanded_url = '', 
                            ext_media_availability = { }, 
                            id_str = '4', 
                            indices = [
                                56
                                ], 
                            media_key = '4_072888001528021798096225500850762068629', 
                            media_url_https = '', 
                            original_info = twitter_openapi_python_generated.models.media_original_info.Media_original_info(
                                focus_rects = [
                                    { }
                                    ], 
                                height = 56, 
                                width = 56, ), 
                            sizes = { }, 
                            type = '', 
                            url = '', )
                        ], ), 
                favorite_count = 56, 
                favorited = True, 
                full_text = '', 
                id_str = '4', 
                is_quote_status = True, 
                lang = '', 
                possibly_sensitive = True, 
                possibly_sensitive_editable = True, 
                quote_count = 56, 
                reply_count = 56, 
                retweet_count = 56, 
                retweeted = True, 
                retweeted_status_result = twitter_openapi_python_generated.models.item_result.ItemResult(
                    __typename = 'TimelineTweet', 
                    result = null, ), 
                self_thread = twitter_openapi_python_generated.models.tweet_legacy_self_thread.TweetLegacy_self_thread(
                    id_str = '4', ), 
                user_id_str = '4'
            )
        else :
            return TweetLegacy(
                bookmark_count = 56,
                bookmarked = True,
                conversation_id_str = '4',
                created_at = 'Sat Dec 31 23:59:59 +0000 2023',
                display_text_range = [
                    56
                    ],
                entities = twitter_openapi_python_generated.models.entities.Entities(
                    hashtags = [
                        { }
                        ], 
                    media = [
                        twitter_openapi_python_generated.models.media.Media(
                            display_url = '', 
                            expanded_url = '', 
                            ext_media_availability = { }, 
                            id_str = '4', 
                            indices = [
                                56
                                ], 
                            media_key = '4_072888001528021798096225500850762068629', 
                            media_url_https = '', 
                            original_info = twitter_openapi_python_generated.models.media_original_info.Media_original_info(
                                focus_rects = [
                                    { }
                                    ], 
                                height = 56, 
                                width = 56, ), 
                            sizes = { }, 
                            type = '', 
                            url = '', )
                        ], 
                    symbols = [
                        { }
                        ], 
                    urls = [
                        twitter_openapi_python_generated.models.url.Url(
                            display_url = '', 
                            expanded_url = '', 
                            indices = [
                                56
                                ], 
                            url = '', )
                        ], 
                    user_mentions = [
                        { }
                        ], ),
                favorite_count = 56,
                favorited = True,
                full_text = '',
                id_str = '4',
                is_quote_status = True,
                lang = '',
                quote_count = 56,
                reply_count = 56,
                retweet_count = 56,
                retweeted = True,
                user_id_str = '4',
        )
        """

    def testTweetLegacy(self):
        """Test TweetLegacy"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
