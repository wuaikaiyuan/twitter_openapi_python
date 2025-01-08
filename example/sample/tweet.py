import datetime

import login as login
from twitter_openapi_python import TwitterOpenapiPython

cookies_dict = login.login().get_cookies().get_dict()
X = TwitterOpenapiPython().get_client_from_cookies(cookies=cookies_dict)

# time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
# X.get_post_api().post_create_tweet(tweet_text=f"code today!!{time}")

# tweet = X.get_default_api().get_tweet_result_by_rest_id(tweet_id='1451015154196353027')
# print(f'{tweet.data.tweet}')

tweets = X.get_tweet_api().get_user_tweets(user_id='173630669108149681')
for tweet in tweets:
    print(f'{tweet.data.tweet}')
    print('---------------------------------')


