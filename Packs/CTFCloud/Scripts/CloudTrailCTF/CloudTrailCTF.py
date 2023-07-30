import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

def main():

    json_array = [
        {
          "type": "AssumedRole",
          "principalId": "AKIAZVSI4536365AD6WCJC:svc_dev",
          "arn": "arn:aws:sts::666688938958:assumed-role/sso_admin/svc_dev",
          "accessKeyId": "AKIAZVSI4536365AD6WCJC",
          "eventTime": "2023-06-07T12:43:34Z",
          "sourceIPAddress": "31.154.166.148",
          "requestID": "9fbee49c-64c7-464a-a1e2-b58d4f420fbf",
          "eventID": "9e98911e-6954-48a0-b851-9c029ab60573",
          "eventType": "AwsApiCall",
          "eventName":"ListTrails",
          "recipientAccountId": "666688938958",
          "requestParameters":""
        },
        {
          "type": "AssumedRole",
          "principalId": "AKIAZVSI4536365AD6WCJC:svc_dev",
          "arn": "arn:aws:sts::666688938958:assumed-role/sso_admin/svc_dev",
          "accessKeyId": "AKIAZVSI4536365AD6WCJC",
          "eventTime": "2023-06-07T12:45:34Z",
          "sourceIPAddress": "31.154.166.148",
          "requestID": "9fbee49c-64c7-464a-a1e2-b58d4f420fbf",
          "eventID": "9e98911e-6954-48a0-b851-9c029ab60573",
          "eventType": "AwsApiCall",
          "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-ebeaf9e2"}]}},
          "eventName":"StartInstances",
          "recipientAccountId": "666688938958"
        },
        {
          "type": "AssumedRole",
          "principalId": "AKIAZVSI4536365AD6WCJC:svc_dev",
          "arn": "arn:aws:sts::666688938958:assumed-role/sso_admin/svc_dev",
          "accessKeyId": "AKIAZVSI4536365AD6WCJC",
          "eventTime": "2023-06-07T12:52:34Z",
          "sourceIPAddress": "31.154.166.148",
          "requestID": "9fbee49c-64c7-464a-a1e2-b58d4f420fbf",
          "eventID": "9e98911e-6954-48a0-b851-9c029ab60573",
          "eventType": "AwsApiCall",
          "eventName": "CreateUser",
          "requestParameters": {"userName": "Bob"},
          "recipientAccountId": "666688938958"
        },
        {
          "type": "AssumedRole",
          "principalId": "AKIAZVSI4536365AD6WCJC:svc_dev",
          "arn": "arn:aws:sts::666688938958:assumed-role/sso_admin/svc_dev",
          "accessKeyId": "AKIAZVSI4536365AD6WCJC",
          "eventTime": "2023-06-07T12:53:34Z",
          "sourceIPAddress": "31.154.166.148",
          "requestID": "9fbee49c-64c7-464a-a1e2-b58d4f420fbf",
          "eventID": "9e98911e-6954-48a0-b851-9c029ab60573",
          "eventType": "AwsApiCall",
          "eventName":"AddUserToGroup",
          "requestParameters": {
                "userName": "Bob",
                "groupName": "admin"
            },
          "recipientAccountId": "666688938958"
        }
        ]
    markdown=json_to_markdown_table(json_array)
    return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}


def json_to_markdown_table(json_array):
    # Extracting the keys from the first JSON object to use as table headers
    headers = json_array[0].keys()

    # Creating the header row for the markdown table
    header_row = "| " + " | ".join(headers) + " |"
    separator_row = "| " + " | ".join(["---"] * len(headers)) + " |"

    # Creating the rows for the markdown table
    data_rows = []
    for item in json_array:
        values = [str(item.get(key, "")) for key in headers]
        data_row = "| " + " | ".join(values) + " |"
        data_rows.append(data_row)

    # Combining all the parts into the final markdown table
    markdown_table = "\n".join([header_row, separator_row] + data_rows)

    return markdown_table

if __name__ in ('__main__', '__builtin__', 'builtins'):
      try:
          return_results(main())
      except Exception as e:
          return_error(f'Got an error while parsing Splunk events: {e}', error=e)
