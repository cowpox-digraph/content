import importlib
import io

from CommonServerPython import *

OpenAIGPT = importlib.import_module("OpenAIGPT")


class OpenAiClient:
    def get_chat_completions(self):
        pass


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def util_load_text(path: str) -> str:
    with open(path) as f:
        return f.read()


def test_extract_assistant_message():
    """Tests extraction from a valid response with choices and message."""

    from OpenAIGPT import extract_assistant_message

    mock_response = util_load_json('test_data/mock_response.json')

    conversation = []
    extracted_message = extract_assistant_message(response=mock_response, conversation=conversation)

    assert extracted_message == "Hello! How can I assist you today?"
    assert conversation == [{'role': 'assistant', 'content': 'Hello! How can I assist you today?'}]


def test_get_email_parts(mocker):
    """ Tests email parsing and parts extraction. """

    from OpenAIGPT import get_email_parts

    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/attachment_malicious_url.eml',
                                                              'name': 'attachment_malicious_url.eml'})

    headers, text_body, html_body = get_email_parts(entry_id="0")

    assert headers == util_load_json('./test_data/expected_headers.json')
    assert text_body == 'Body of the text'
    assert html_body.replace('\r\n', '\n') == util_load_text('test_data/expected_html_body.txt')
