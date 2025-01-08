# PostCreateTweetRequestVariables


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**attachment_url** | **str** |  | [optional] [default to 'https://x.com/elonmusk/status/1349129669258448897']
**conversation_control** | [**PostCreateTweetRequestVariablesConversationControl**](PostCreateTweetRequestVariablesConversationControl.md) |  | [optional] 
**dark_request** | **bool** |  | [default to False]
**disallowed_reply_options** | **object** |  | [optional] 
**media** | [**PostCreateTweetRequestVariablesMedia**](PostCreateTweetRequestVariablesMedia.md) |  | 
**reply** | [**PostCreateTweetRequestVariablesReply**](PostCreateTweetRequestVariablesReply.md) |  | [optional] 
**semantic_annotation_ids** | **List[object]** |  | 
**tweet_text** | **str** |  | [default to 'test']

## Example

```python
from twitter_openapi_python_generated.models.post_create_tweet_request_variables import PostCreateTweetRequestVariables

# TODO update the JSON string below
json = "{}"
# create an instance of PostCreateTweetRequestVariables from a JSON string
post_create_tweet_request_variables_instance = PostCreateTweetRequestVariables.from_json(json)
# print the JSON string representation of the object
print(PostCreateTweetRequestVariables.to_json())

# convert the object into a dict
post_create_tweet_request_variables_dict = post_create_tweet_request_variables_instance.to_dict()
# create an instance of PostCreateTweetRequestVariables from a dict
post_create_tweet_request_variables_from_dict = PostCreateTweetRequestVariables.from_dict(post_create_tweet_request_variables_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


