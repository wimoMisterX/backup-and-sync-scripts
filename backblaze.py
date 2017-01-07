import base64
import json
import urllib2

def get_api_authorization():
    id_and_key = '<>:<>'
    request = urllib2.Request(
        'https://api.backblazeb2.com/b2api/v1/b2_authorize_account',
        headers= {
            'Authorization': 'Basic ' + base64.b64encode(id_and_key)
        }
    )
    response = urllib2.urlopen(request)
    response_data = json.loads(response.read())
    response.close()

    return response_data['authorizationToken'], response_data['apiUrl'], response_data['accountId']

def list_buckets():
    account_authorization_token, api_url, account_id = get_api_authorization()
    request = urllib2.Request(
        '%s/b2api/v1/b2_list_buckets' % api_url,
        json.dumps({'accountId': account_id}),
        headers= {
            'Authorization': account_authorization_token
        }
    )
    response = urllib2.urlopen(request)
    response_data = json.loads(response.read())
    response.close()
    return response_data
