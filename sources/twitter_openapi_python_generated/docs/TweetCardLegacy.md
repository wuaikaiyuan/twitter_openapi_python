# TweetCardLegacy


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**binding_values** | [**List[TweetCardLegacyBindingValue]**](TweetCardLegacyBindingValue.md) |  | 
**card_platform** | [**TweetCardPlatformData**](TweetCardPlatformData.md) |  | [optional] 
**name** | **str** |  | 
**url** | **str** |  | 
**user_refs_results** | [**List[UserResults]**](UserResults.md) |  | [optional] 

## Example

```python
from twitter_openapi_python_generated.models.tweet_card_legacy import TweetCardLegacy

# TODO update the JSON string below
json = "{}"
# create an instance of TweetCardLegacy from a JSON string
tweet_card_legacy_instance = TweetCardLegacy.from_json(json)
# print the JSON string representation of the object
print(TweetCardLegacy.to_json())

# convert the object into a dict
tweet_card_legacy_dict = tweet_card_legacy_instance.to_dict()
# create an instance of TweetCardLegacy from a dict
tweet_card_legacy_from_dict = TweetCardLegacy.from_dict(tweet_card_legacy_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


