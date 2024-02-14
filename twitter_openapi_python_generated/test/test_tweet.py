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

from twitter_openapi_python_generated.models.tweet import Tweet

class TestTweet(unittest.TestCase):
    """Tweet unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> Tweet:
        """Test Tweet
            include_option is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `Tweet`
        """
        model = Tweet()
        if include_optional:
            return Tweet(
                typename = 'TimelineTweet',
                author_community_relationship = twitter_openapi_python_generated.models.author_community_relationship.AuthorCommunityRelationship(
                    community_results = twitter_openapi_python_generated.models.community.Community(
                        result = twitter_openapi_python_generated.models.community_data.CommunityData(
                            __typename = 'TimelineTweet', 
                            actions = twitter_openapi_python_generated.models.community_actions.CommunityActions(
                                delete_action_result = twitter_openapi_python_generated.models.community_delete_action_result.CommunityDeleteActionResult(
                                    __typename = 'TimelineTweet', 
                                    reason = 'Unavailable', ), 
                                join_action_result = twitter_openapi_python_generated.models.community_join_action_result.CommunityJoinActionResult(
                                    __typename = , ), 
                                leave_action_result = twitter_openapi_python_generated.models.community_leave_action_result.CommunityLeaveActionResult(
                                    __typename = , 
                                    message = '', 
                                    reason = 'ViewerNotMember', ), 
                                pin_action_result = twitter_openapi_python_generated.models.community_pin_action_result.CommunityPinActionResult(
                                    __typename = , ), ), 
                            admin_results = twitter_openapi_python_generated.models.user_results.UserResults(), 
                            created_at = 56, 
                            creator_results = twitter_openapi_python_generated.models.user_results.UserResults(), 
                            custom_banner_media = { }, 
                            default_banner_media = { }, 
                            description = '', 
                            id_str = '4', 
                            invites_policy = 'MemberInvitesAllowed', 
                            invites_result = twitter_openapi_python_generated.models.community_invites_result.CommunityInvitesResult(
                                __typename = , 
                                message = '', 
                                reason = 'Unavailable', ), 
                            is_pinned = True, 
                            join_policy = 'Open', 
                            join_requests_result = twitter_openapi_python_generated.models.community_join_requests_result.CommunityJoinRequestsResult(
                                __typename = , ), 
                            member_count = 56, 
                            members_facepile_results = [
                                
                                ], 
                            moderator_count = 56, 
                            name = '', 
                            primary_community_topic = twitter_openapi_python_generated.models.primary_community_topic.PrimaryCommunityTopic(
                                topic_id = '4', 
                                topic_name = '', ), 
                            question = '', 
                            role = 'NonMember', 
                            rules = [
                                twitter_openapi_python_generated.models.community_rule.CommunityRule(
                                    description = '', 
                                    name = '', 
                                    rest_id = '4', )
                                ], 
                            search_tags = [
                                ''
                                ], 
                            show_only_users_to_display = [
                                ''
                                ], 
                            urls = twitter_openapi_python_generated.models.community_urls.CommunityUrls(
                                permalink = twitter_openapi_python_generated.models.community_urls_permalink.CommunityUrlsPermalink(
                                    url = '', ), ), 
                            viewer_relationship = { }, ), ), 
                    role = 'Member', 
                    user_results = , ),
                birdwatch_pivot = twitter_openapi_python_generated.models.birdwatch_pivot.BirdwatchPivot(
                    call_to_action = twitter_openapi_python_generated.models.birdwatch_pivot_call_to_action.BirdwatchPivotCallToAction(
                        destination_url = '', 
                        prompt = '', 
                        title = '', ), 
                    destination_url = '', 
                    footer = twitter_openapi_python_generated.models.birdwatch_pivot_footer.BirdwatchPivotFooter(
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
                        text = '', ), 
                    icon_type = 'BirdwatchV1Icon', 
                    note = twitter_openapi_python_generated.models.birdwatch_pivot_note.BirdwatchPivotNote(
                        rest_id = '4', ), 
                    shorttitle = '', 
                    subtitle = twitter_openapi_python_generated.models.birdwatch_pivot_subtitle.BirdwatchPivotSubtitle(
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
                        text = '', ), 
                    title = '', 
                    visual_style = 'Default', ),
                card = twitter_openapi_python_generated.models.tweet_card.TweetCard(
                    legacy = twitter_openapi_python_generated.models.tweet_card_legacy.TweetCardLegacy(
                        binding_values = [
                            twitter_openapi_python_generated.models.tweet_card_legacy_binding_value.TweetCardLegacyBindingValue(
                                key = '', 
                                value = twitter_openapi_python_generated.models.tweet_card_legacy_binding_value_data.TweetCardLegacyBindingValueData(
                                    boolean_value = True, 
                                    image_color_value = { }, 
                                    image_value = twitter_openapi_python_generated.models.tweet_card_legacy_binding_value_data_image.TweetCardLegacyBindingValueDataImage(
                                        alt = '', 
                                        height = 56, 
                                        url = '', 
                                        width = 56, ), 
                                    scribe_key = '', 
                                    string_value = '', 
                                    type = '', 
                                    user_value = twitter_openapi_python_generated.models.user_value.UserValue(
                                        id_str = '4', ), ), )
                            ], 
                        card_platform = twitter_openapi_python_generated.models.tweet_card_platform_data.TweetCardPlatformData(
                            platform = twitter_openapi_python_generated.models.tweet_card_platform.TweetCardPlatform(
                                audience = twitter_openapi_python_generated.models.tweet_card_platform_audience.TweetCardPlatformAudience(
                                    name = 'production', ), 
                                device = twitter_openapi_python_generated.models.tweet_card_platform_device.TweetCardPlatformDevice(
                                    name = '', 
                                    version = '4', ), ), ), 
                        name = '', 
                        url = '', 
                        user_refs_results = [
                            twitter_openapi_python_generated.models.user_results.UserResults(
                                result = null, )
                            ], ), 
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
                has_birdwatch_notes = True,
                is_translatable = True,
                legacy = twitter_openapi_python_generated.models.tweet_legacy.TweetLegacy(
                    bookmark_count = 56, 
                    bookmarked = True, 
                    conversation_control = { }, 
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
                                additional_media_info = { }, 
                                display_url = '', 
                                expanded_url = '', 
                                ext_alt_text = '', 
                                ext_media_availability = twitter_openapi_python_generated.models.ext_media_availability.ExtMediaAvailability(
                                    reason = '', 
                                    status = 'Available', ), 
                                features = twitter_openapi_python_generated.models.features.features(), 
                                id_str = '4', 
                                indices = [
                                    56
                                    ], 
                                media_key = '', 
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
                                sensitive_media_warning = twitter_openapi_python_generated.models.sensitive_media_warning.SensitiveMediaWarning(
                                    adult_content = True, 
                                    graphic_violence = True, 
                                    other = True, ), 
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
                                source_status_id_str = '4', 
                                source_user_id_str = '4', 
                                type = 'photo', 
                                url = '', 
                                video_info = { }, )
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
                                display_url = '', 
                                expanded_url = '', 
                                ext_alt_text = '', 
                                features = twitter_openapi_python_generated.models.features.features(), 
                                id_str = '4', 
                                indices = , 
                                media_stats = twitter_openapi_python_generated.models.media_stats.MediaStats(
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
                                source_status_id_str = '4', 
                                source_user_id_str = '4', 
                                type = 'photo', 
                                url = '', )
                            ], ), 
                    favorite_count = 56, 
                    favorited = True, 
                    full_text = '', 
                    id_str = '4', 
                    in_reply_to_screen_name = '', 
                    in_reply_to_status_id_str = '4', 
                    in_reply_to_user_id_str = '4', 
                    is_quote_status = True, 
                    lang = '', 
                    limited_actions = 'limited_replies', 
                    place = { }, 
                    possibly_sensitive = True, 
                    possibly_sensitive_editable = True, 
                    quote_count = 56, 
                    quoted_status_id_str = '4', 
                    quoted_status_permalink = twitter_openapi_python_generated.models.quoted_status_permalink.QuotedStatusPermalink(
                        display = '', 
                        expanded = '', 
                        url = '', ), 
                    reply_count = 56, 
                    retweet_count = 56, 
                    retweeted = True, 
                    retweeted_status_result = twitter_openapi_python_generated.models.item_result.ItemResult(
                        __typename = 'TimelineTweet', 
                        result = null, ), 
                    scopes = twitter_openapi_python_generated.models.tweet_legacy_scopes.TweetLegacyScopes(
                        followers = True, ), 
                    self_thread = twitter_openapi_python_generated.models.self_thread.SelfThread(
                        id_str = '4', ), 
                    user_id_str = '4', ),
                note_tweet = twitter_openapi_python_generated.models.note_tweet.NoteTweet(
                    is_expandable = True, 
                    note_tweet_results = twitter_openapi_python_generated.models.note_tweet_result.NoteTweetResult(
                        result = twitter_openapi_python_generated.models.note_tweet_result_data.NoteTweetResultData(
                            entity_set = twitter_openapi_python_generated.models.entities.Entities(
                                hashtags = [
                                    { }
                                    ], 
                                media = [
                                    twitter_openapi_python_generated.models.media.Media(
                                        additional_media_info = { }, 
                                        display_url = '', 
                                        expanded_url = '', 
                                        ext_alt_text = '', 
                                        ext_media_availability = twitter_openapi_python_generated.models.ext_media_availability.ExtMediaAvailability(
                                            reason = '', 
                                            status = 'Available', ), 
                                        features = twitter_openapi_python_generated.models.features.features(), 
                                        id_str = '4', 
                                        indices = [
                                            56
                                            ], 
                                        media_key = '', 
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
                                        sensitive_media_warning = twitter_openapi_python_generated.models.sensitive_media_warning.SensitiveMediaWarning(
                                            adult_content = True, 
                                            graphic_violence = True, 
                                            other = True, ), 
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
                                        source_status_id_str = '4', 
                                        source_user_id_str = '4', 
                                        type = 'photo', 
                                        url = '', 
                                        video_info = { }, )
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
                            id = 'zA9LCSLv1C1ylmgd0/Y2TA5TkIRHRRA401iz1CiIykN3HUO6XMsJPGh8AsaLONiNuo2ZPKNpkAmJHONf1Elbsh0SR//=', 
                            media = twitter_openapi_python_generated.models.note_tweet_result_media.NoteTweetResultMedia(
                                inline_media = [
                                    twitter_openapi_python_generated.models.note_tweet_result_media_inline_media.NoteTweetResultMediaInlineMedia(
                                        index = 56, 
                                        media_id = '4', )
                                    ], ), 
                            richtext = twitter_openapi_python_generated.models.note_tweet_result_rich_text.NoteTweetResultRichText(
                                richtext_tags = [
                                    twitter_openapi_python_generated.models.note_tweet_result_rich_text_tag.NoteTweetResultRichTextTag(
                                        from_index = 56, 
                                        richtext_types = [
                                            'Bold'
                                            ], 
                                        to_index = 56, )
                                    ], ), 
                            text = '', ), ), ),
                previous_counts = twitter_openapi_python_generated.models.tweet_previous_counts.TweetPreviousCounts(
                    bookmark_count = 56, 
                    favorite_count = 56, 
                    quote_count = 56, 
                    reply_count = 56, 
                    retweet_count = 56, ),
                quick_promote_eligibility = twitter_openapi_python_generated.models.quick_promote_eligibility.quick_promote_eligibility(),
                quoted_ref_result = twitter_openapi_python_generated.models.quoted_ref_result.QuotedRefResult(
                    result = null, ),
                quoted_status_result = twitter_openapi_python_generated.models.item_result.ItemResult(
                    __typename = 'TimelineTweet', 
                    result = null, ),
                rest_id = '4',
                source = '',
                super_follows_reply_user_result = twitter_openapi_python_generated.models.super_follows_reply_user_result.SuperFollowsReplyUserResult(
                    result = twitter_openapi_python_generated.models.super_follows_reply_user_result_data.SuperFollowsReplyUserResultData(
                        __typename = 'TimelineTweet', 
                        legacy = twitter_openapi_python_generated.models.super_follows_reply_user_result_legacy.SuperFollowsReplyUserResultLegacy(
                            screen_name = '', ), ), ),
                unified_card = twitter_openapi_python_generated.models.unified_card.UnifiedCard(
                    card_fetch_state = 'NoCard', ),
                unmention_data = { },
                views = twitter_openapi_python_generated.models.tweet_view.TweetView(
                    count = '4', 
                    state = 'Enabled', )
            )
        else:
            return Tweet(
                rest_id = '4',
        )
        """

    def testTweet(self):
        """Test Tweet"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
