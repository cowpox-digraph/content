from CommonServerPython import string_to_table_header, tableToMarkdown


import json

from Packs.FeedGithub.Integrations.FeedGithub.FeedGitHub import get_yara_indicators, parse_and_map_yara_content, extract_text_indicators


URL = "https://openphish.com/feed.txt"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())

def util_load_txt(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def doibnttest_build_iterator(requests_mock):
    """

    Given:
        - Output of the feed API
    When:
        - When calling fetch_indicators or get_indicators
    Then:
        - Returns a list of the indicators parsed from the API's response

    """
    with open("test_data/FeedHelloWorld_mock.txt") as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_url = "https://url1.com"
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.build_iterator()
    url_indicators = {
        indicator["value"] for indicator in indicators if indicator["type"] == "URL"
    }
    assert expected_url in url_indicators


# def test_fetch_indicators(mocker):
#     """

#     Given:
#         - Output of the feed API as list
#     When:
#         - Fetching indicators from the API
#     Then:
#         - Create indicator objects list

#     """
#     client = Client(base_url=URL)
#     mocker.patch.object(
#         Client,
#         "build_iterator",
#         return_value=util_load_json("./test_data/build_iterator_results.json"),
#     )
#     results = fetch_indicators_command(client, params={"tlp_color": "RED"})
#     assert results == util_load_json("./test_data/get_indicators_command_results.json")


# def test_get_indicators_command(mocker):
#     """

#     Given:
#         - Output of the feed API as list
#     When:
#         - Getting a limited number of indicators from the API
#     Then:
#         - Return results as war-room entry

#     """
#     client = Client(base_url=URL)
#     indicators_list = util_load_json("./test_data/build_iterator_results.json")[:10]
#     mocker.patch.object(Client, "build_iterator", return_value=indicators_list)
#     results = get_indicators_command(
#         client, params={"tlp_color": "RED"}, args={"limit": "10"}
#     )
#     human_readable = tableToMarkdown(
#         "Indicators from HelloWorld Feed:",
#         indicators_list,
#         headers=["value", "type"],
#         headerTransform=string_to_table_header,
#         removeNull=True,
#     )
#     assert results.readable_output == human_readable
    
    
def test_extractindicators():
    text_content = {"test_file": util_load_txt("test_data/iocs.txt")}
    params = {}
    indicator_type = extract_text_indicators(text_content, params)
    
    

 
def test_get_yara_indicators():
    my_text_content = {"test_file": util_load_txt("test_data/tara_test.yar")}
    indicators = parse_and_map_yara_content(my_text_content)
