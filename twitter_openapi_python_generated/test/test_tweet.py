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
from twitter_openapi_python_generated.models.tweet import Tweet  # noqa: E501
from twitter_openapi_python_generated.rest import ApiException

class TestTweet(unittest.TestCase):
    """Tweet unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional):
        """Test Tweet
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `Tweet`
        """
        model = twitter_openapi_python_generated.models.tweet.Tweet()  # noqa: E501
        if include_optional :
            return Tweet(
                typename = 'TimelineTweet', 
                card = twitter_openapi_python_generated.models.tweet_card.TweetCard(
                    legacy = twitter_openapi_python_generated.models.tweet_card_legacy.TweetCardLegacy(
                        binding_values = [
                            twitter_openapi_python_generated.models.tweet_card_legacy_binding_value.TweetCardLegacyBindingValue(
                                key = '', 
                                value = twitter_openapi_python_generated.models.tweet_card_legacy_binding_value_data.TweetCardLegacyBindingValueData(
                                    boolean_value = True, 
                                    scribe_key = '', 
                                    string_value = '', 
                                    type = '', ), )
                            ], 
                        name = '', 
                        url = '', ), 
                    rest_id = '', ), 
                core = twitter_openapi_python_generated.models.user_result_core.UserResultCore(
                    user_results = twitter_openapi_python_generated.models.user_results.UserResults(
                        result = null, ), ), 
                edit_control = twitter_openapi_python_generated.models.tweet_edit_control.TweetEditControl(
                    edit_control_initial = twitter_openapi_python_generated.models.tweet_edit_control_initial.TweetEditControlInitial(
                        edit_tweet_ids = [
                            '4'
                            ], 
                        editable_until_msecs = '4', 
                        edits_remaining = '4', 
                        is_edit_eligible = True, ), 
                    edit_tweet_ids = [
                        '4'
                        ], 
                    editable_until_msecs = '4', 
                    edits_remaining = '4', 
                    initial_tweet_id = '4', 
                    is_edit_eligible = True, ), 
                edit_prespective = twitter_openapi_python_generated.models.tweet_edit_prespective.TweetEditPrespective(
                    favorited = True, 
                    retweeted = True, ), 
                is_translatable = True, 
                legacy = twitter_openapi_python_generated.models.tweet_legacy.TweetLegacy(
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
                                features = twitter_openapi_python_generated.models.features.features(), 
                                id_str = '4', 
                                indices = [
                                    56
                                    ], 
                                media_url_https = '', 
                                original_info = twitter_openapi_python_generated.models.media_original_info.MediaOriginalInfo(
                                    focus_rects = [
                                        twitter_openapi_python_generated.models.media_original_info_focus_rect.MediaOriginalInfoFocusRect(
                                            h = 56, 
                                            w = 56, 
                                            x = 56, 
                                            y = 56, )
                                        ], 
                                    height = 56, 
                                    width = 56, ), 
                                sizes = twitter_openapi_python_generated.models.media_sizes.MediaSizes(
                                    large = twitter_openapi_python_generated.models.media_size.MediaSize(
                                        h = 56, 
                                        resize = 'crop', 
                                        w = 56, ), 
                                    medium = twitter_openapi_python_generated.models.media_size.MediaSize(
                                        h = 56, 
                                        resize = 'crop', 
                                        w = 56, ), 
                                    small = , 
                                    thumb = , ), 
                                type = 'photo', 
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
                            twitter_openapi_python_generated.models.media_extended.MediaExtended(
                                additional_media_info = twitter_openapi_python_generated.models.additional_media_info.AdditionalMediaInfo(
                                    monetizable = True, ), 
                                display_url = '', 
                                expanded_url = '', 
                                ext_media_availability = twitter_openapi_python_generated.models.ext_media_availability.extMediaAvailability(
                                    status = 'Available', ), 
                                features = twitter_openapi_python_generated.models.features.features(), 
                                id_str = '4', 
                                indices = , 
                                media_stats = twitter_openapi_python_generated.models.media_stats.mediaStats(
                                    view_count = 56, ), 
                                media_key = '', 
                                media_url_https = '', 
                                original_info = twitter_openapi_python_generated.models.media_original_info.MediaOriginalInfo(
                                    height = 56, 
                                    width = 56, ), 
                                sizes = twitter_openapi_python_generated.models.media_sizes.MediaSizes(
                                    large = , 
                                    medium = , 
                                    small = , 
                                    thumb = , ), 
                                type = 'photo', 
                                url = '', 
                                video_info = twitter_openapi_python_generated.models.media_video_info.MediaVideoInfo(
                                    aspect_ratio = [
                                        56
                                        ], 
                                    duration_millis = 56, 
                                    variants = [
                                        twitter_openapi_python_generated.models.media_video_info_variant.MediaVideoInfoVariant(
                                            bitrate = 56, 
                                            content_type = '', 
                                            url = '', )
                                        ], ), )
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
                    self_thread = twitter_openapi_python_generated.models.self_thread.SelfThread(
                        id_str = '4', ), 
                    user_id_str = '4', ), 
                quoted_status_result = twitter_openapi_python_generated.models.item_result.ItemResult(
                    __typename = 'TimelineTweet', 
                    result = null, ), 
                rest_id = '4', 
                source = '', 
                unmention_data = { }, 
                views = twitter_openapi_python_generated.models.tweet_view.TweetView(
                    count = '4', 
                    state = 'EnabledWithCount', )
            )
        else :
            return Tweet(
                edit_control = twitter_openapi_python_generated.models.tweet_edit_control.TweetEditControl(
                    edit_control_initial = twitter_openapi_python_generated.models.tweet_edit_control_initial.TweetEditControlInitial(
                        edit_tweet_ids = [
                            '4'
                            ], 
                        editable_until_msecs = '4', 
                        edits_remaining = '4', 
                        is_edit_eligible = True, ), 
                    edit_tweet_ids = [
                        '4'
                        ], 
                    editable_until_msecs = '4', 
                    edits_remaining = '4', 
                    initial_tweet_id = '4', 
                    is_edit_eligible = True, ),
                is_translatable = True,
                rest_id = '4',
                views = twitter_openapi_python_generated.models.tweet_view.TweetView(
                    count = '4', 
                    state = 'EnabledWithCount', ),
        )
        """

    def testTweet(self):
        """Test Tweet"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
