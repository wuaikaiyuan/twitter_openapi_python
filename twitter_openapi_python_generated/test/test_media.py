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

from twitter_openapi_python_generated.models.media import Media

class TestMedia(unittest.TestCase):
    """Media unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def make_instance(self, include_optional) -> Media:
        """Test Media
            include_optional is a boolean, when False only required
            params are included, when True both required and
            optional params are included """
        # uncomment below to create an instance of `Media`
        """
        model = Media()
        if include_optional:
            return Media(
                additional_media_info = twitter_openapi_python_generated.models.additional_media_info.AdditionalMediaInfo(
                    call_to_actions = twitter_openapi_python_generated.models.additional_media_info_call_to_actions.AdditionalMediaInfoCallToActions(
                        visit_site = twitter_openapi_python_generated.models.additional_media_info_call_to_actions_url.AdditionalMediaInfoCallToActionsUrl(
                            url = '', ), 
                        watch_now = twitter_openapi_python_generated.models.additional_media_info_call_to_actions_url.AdditionalMediaInfoCallToActionsUrl(
                            url = '', ), ), 
                    description = '', 
                    embeddable = True, 
                    monetizable = True, 
                    source_user = twitter_openapi_python_generated.models.user_result_core.UserResultCore(
                        user_results = twitter_openapi_python_generated.models.user_results.UserResults(
                            result = null, ), ), 
                    title = '', ),
                allow_download_status = twitter_openapi_python_generated.models.allow_download_status.AllowDownloadStatus(
                    allow_download = True, ),
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
                media_results = twitter_openapi_python_generated.models.media_results.MediaResults(
                    result = twitter_openapi_python_generated.models.media_result.MediaResult(
                        media_key = '', ), ),
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
                        ], )
            )
        else:
            return Media(
                display_url = '',
                expanded_url = '',
                ext_media_availability = twitter_openapi_python_generated.models.ext_media_availability.ExtMediaAvailability(
                    reason = '', 
                    status = 'Available', ),
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
                url = '',
        )
        """

    def testMedia(self):
        """Test Media"""
        # inst_req_only = self.make_instance(include_optional=False)
        # inst_req_and_optional = self.make_instance(include_optional=True)

if __name__ == '__main__':
    unittest.main()
