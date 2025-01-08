import logging
import unittest
import os, sys

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
project_path = os.path.join(project_root, './twitter_openapi_python')
sys.path.insert(0, project_path)

import twitter_openapi_python as api
from test.api import get_guest_client



class TestGuestDefaultApi(unittest.TestCase):
    client: api.DefaultApiUtils

    def setUp(self):
        self.client = get_guest_client().get_default_api()

    def test_get_tweet_result_by_rest_id(self):
        result = self.client.get_tweet_result_by_rest_id(tweet_id="1349129669258448897")

        assert result.data is not None
        assert result.data.tweet.legacy is not None
        logging.info(result.data.tweet.legacy.full_text)


if __name__ == "__main__":
    unittest.main()
