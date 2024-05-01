import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from TAXII2ApiModule import *
import plyara
import tldextract

CONTEXT_PREFIX = "GITHUB"
RAW_RESPONSE = ""


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this gitHub Feed implementation, no special attributes defined
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, owner: str, repo: str, headers: dict):
        base_url = urljoin(base_url, f"/repos/{owner}/{repo}")
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_repo_base_sha(self) -> str:
        """
        Retrieves the SHA of the base commit of the repository.

        This function fetches all commits of the repository and returns the SHA of the latest commit,
        which represents the base commit of the repository.

        Returns:
            str: The SHA of the base commit of the repository.
        """
        all_commits = []
        response = self._http_request("GET", full_url=f"{self._base_url}/commits", resp_type="response")
        demisto.debug(f"The base get_repo_base_sha() raw response: {response}")
        if "next" not in response.links:
            all_commits.extend(response.json())
        while "next" in response.links:
            data = response.json()
            all_commits.extend(data)
            response = self._http_request("GET", full_url=response.links["next"]["url"], resp_type="response")
        return all_commits[-1]["sha"]

    def get_files_between_commits(self, base: str, head: str) -> list:
        """
        Retrieves the list of files modified between two commits.

        Args:
            base (str): The SHA of the base commit.
            head (str): The SHA of the head commit.

        Returns:
            list: A list of files modified between the specified base and head commits.
        """
        try:
            response = self._http_request("GET", f"/compare/{base}...{head}")["files"]
        except Exception as e:
            demisto.error(f"in get_files_between_commits func  error message: {e}")
        demisto.debug(f"The response from 'get base...head' :{response}")
        return response


def filter_out_files_by_status(commits_files: list) -> list:
    """
    Parses files from a list of commit files based on their status.

    Args:
        commits_files (list): A list of dictionaries representing commit files.

    Returns:
        list: A list of URLs for files that are added or modified.
    """
    relevant_files: list[dict] = []
    for file in commits_files:
        if file.get("status") in ("added", "modified"):
            relevant_files.append(file.get("raw_url"))
    return relevant_files


def get_content_files_from_repo(client: Client, relevant_files: list[str], params:dict):
    """
    Retrieves content of relevant files based on specified extensions.

    Args:
        client (Client): An instance of the client used for HTTP requests.
        relevant_files (list): A list of URLs for relevant files.

    Returns:
        list: A list of file contents fetched via HTTP requests.
    """
    global RAW_RESPONSE
    extensions_to_fetch = argToList(params.get("extensions_to_fetch") or [])
    relevant_files = [file for file in relevant_files if any(file.endswith(ext) for ext in extensions_to_fetch)]
    raw_data_files = [{file: client._http_request("GET", full_url=file, resp_type="text")} for file in relevant_files]
    demisto.debug(f"list of all files raw_data :{raw_data_files}")
    RAW_RESPONSE = [file.values() for file in raw_data_files]
    return raw_data_files


def extract_branch_sha(client: Client, branch_name):
    branch_info = client._http_request("GET", f"/git/refs/heads/{branch_name}")
    return branch_info["object"]["sha"]


def get_commits_files(client: Client, params, last_commit_fetch) -> tuple[list, str]:
    """
    Retrieves relevant files modified between commits and the current repository head.

    Args:
        client (Client): An instance of the client used for interacting with the repository.
        last_commit_fetch (str): The SHA of the last fetched commit.

    Returns:
        tuple: A tuple containing a list of relevant file URLs and the SHA of the current repository head.
    """
    current_repo_head = params.get("branch_head",'')
    base_repo_sha = last_commit_fetch or client.get_repo_base_sha()
    try:
        all_commits_files = client.get_files_between_commits(base_repo_sha, current_repo_head)
        relevant_files = filter_out_files_by_status(all_commits_files)
        return relevant_files, current_repo_head

    except IndexError:
        return [], last_commit_fetch


def parse_and_map_yara_content(content_item: dict[str, str]) -> list:
    """
    Parses YARA rules from a given content item and maps their attributes.

    Args:
        content_item (str): A string containing one or more YARA rules.

    Returns:
        list: A list of dictionaries representing parsed and mapped YARA rules.
              Each dictionary contains attributes such as rule name, description, author, etc.
    """
    pattern = re.compile(r"rule\s+\w+\s*?\{(?:.*?)\}(?:$|\n)", re.DOTALL)
    text_content = list(content_item.values())[0]
    file_path = list(content_item.keys())[0]
    content_rules = pattern.findall(text_content)
    parsed_rules = []
    for rule in content_rules:
        parser = plyara.Plyara()
        try:
            parsed_rule = parser.parse_string(rule)[0]
            metadata = {key: value for d in parsed_rule["metadata"] for key, value in d.items()}
            value_ = parsed_rule["rule_name"]
            type_ = "YARA"
            mapper = {
                "value": value_,
                "description": metadata.get("description", ""),
                "author": metadata.get("author", ""),
                "rulereference": metadata.get("reference", ""),
                "sourcetimestamp": metadata.get("date", ""),
                "id": metadata.get("id", ""),
                "rulestrings": make_grid_layout(parsed_rule.get("strings", {})),
                "condition": " ".join(parsed_rule["condition_terms"]),
                "references": file_path,
                "raw rule": rule,
            }
            indicator_obj = {
                "value": value_,
                "type": type_,
                "service": "github",
                "fields": mapper,
                "score": Common.DBotScore.NONE,
                "rawJSON": {"value": value_, "type": type_},
            }
            parsed_rules.append(indicator_obj)
        except Exception as e:
            demisto.error(f"Rull: {rule} cannot be processed. Error Message: {e}")
            continue
    return parsed_rules


def make_grid_layout(list_dict):
    res = []
    for d in list_dict:
        grid_layout = {"name": d.get("name"), "value": d.get("value"), "type": d.get("type"), "modifiers": d.get("modifiers", "")}
        res.append(grid_layout)
    return res


def get_yara_indicators(content: list[dict]):
    """
    Retrieves YARA indicators from a list of content items.

    Args:
        content (list): A list of strings containing YARA rules.

    Returns:
        list: A list of dictionaries representing parsed and mapped YARA rules for each content item.
    """
    res = []
    for item in content:
        res += parse_and_map_yara_content(item)
    return res


def detect_domain_type(domain: str):
    """
    Detects the type of an indicator (e.g., Domain, DomainGlob) using tldextract library.

    Args:
        domain (str): The indicator value to be analyzed.

    Returns:
        Optional[FeedIndicatorType]: The type of the indicator, or None if detection fails.
    """
    try:
        no_cache_extract = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=None)

        if no_cache_extract(domain).suffix:
            if "*" in domain:
                return FeedIndicatorType.DomainGlob
            return FeedIndicatorType.Domain

    except Exception:
        demisto.debug("tldextract failed to detect indicator type. indicator value: {}".format(domain))
    return None


ipv4Regex = (
    r"(?P<ipv4>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[:]?(?P<port>\d+)?"
)
ipv4cidrRegex = r"([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))"
ipv6Regex = r"(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"  # noqa: E501
ipv6cidrRegex = r"s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))"  # noqa: E501

regex_indicators = [
    (ipv4cidrRegex, FeedIndicatorType.CIDR),
    (ipv6Regex, FeedIndicatorType.IPv6),
    (ipv6cidrRegex, FeedIndicatorType.IPv6CIDR),
    (emailRegex, FeedIndicatorType.Email),
    (re.compile(cveRegex, re.M), FeedIndicatorType.CVE),
    (md5Regex, FeedIndicatorType.File),
    (sha1Regex, FeedIndicatorType.File),
    (sha256Regex, FeedIndicatorType.File),
    (sha512Regex, FeedIndicatorType.File),
]

regex_with_groups = [
    (ipv4Regex, FeedIndicatorType.IP, "ipv4"),
    (urlRegex, FeedIndicatorType.URL, "url_with_path"),
    (domainRegex, detect_domain_type, "fqdn"),
]


def extract_text_indicators(content: dict[str, str], params):
    """
    Extracts indicators from text content using predefined regular expressions.

    Args:
        content (str): The text content to extract indicators from.

    Returns:
        list: A list of dictionaries representing extracted indicators.
              Each dictionary contains the indicator value and its type.
    """
    text_content = list(content.values())[0]
    file_path = list(content.keys())[0]
    text_content = text_content.replace("[.]", ".").replace("[@]", "@")  # Refang indicator prior to checking
    indicators = []
    for regex, type in regex_indicators:
        matches = re.finditer(regex, text_content)
        if matches:
            indicators += [{"value": match.group(0), "type": type} for match in matches]
    for regex, type, group_name in regex_with_groups:
        matches = re.finditer(regex, text_content)
        if matches:
            for match in matches:
                if regex in (ipv4Regex, urlRegex):
                    indicators.append({"value": match.group(group_name), "type": type})
                elif regex == domainRegex:
                    regex_type = type(match.group(group_name))
                    if regex_type:
                        indicators.append({"value": match.group(group_name), "type": regex_type})
    indicators_to_xsoar = arrange_iocs_indicator_to_xsoar(file_path, indicators, params)
    return indicators_to_xsoar


def arrange_iocs_indicator_to_xsoar(file_path: str, parsed_indicators: list, params:dict):
    res = []
    owner = params.get("owner",'')
    repo = params.get("repo",'')
    now = datetime.now().isoformat()
    for indicator in parsed_indicators:
        value_ = indicator.get("value")
        type_ = indicator.get("type")
        raw_data = {"value": value_, "type": type_}
        indicator_obj = {
            "value": value_,
            "type": type_,
            "service": "github",
            "fields": {"references": file_path, "tags": [owner, repo], "firstseenbysource": now},
            "rawJSON": raw_data,
        }
        res.append(indicator_obj)
    return res


def identify_json_structure(json_data: dict) -> Any:
    """
    Identifies the structure of JSON data based on its content.

    Args:
        json_data (dict): The JSON data to identify its structure.

    Returns:
        Union[str, Dict[str, Any], None]: The identified structure of the JSON data.
            Possible values are: "Bundle", "Envelope", or a dictionary with the key "objects".
            Returns None if the structure cannot be identified.
    """
    if isinstance(json_data, dict) and json_data.get("bundle"):
        return "Bundle"
    if isinstance(json_data, dict) and json_data.get("objects"):
        return "Envelope"
    if isinstance(json_data, list) and all([json_data[0].get("type"), json_data[0].get("id")]):
        return {"objects": json_data}
    return None


def filtering_stix_files(content_files: list) -> list:
    """
    Filters a list of content files to include only those in STIX format.

    Args:
        content_files (list): A list of JSON files or dictionaries representing STIX content.

    Returns:
        list: A list of STIX files or dictionaries found in the input list.
    """
    stix_files = []
    for file in content_files:
        file_type = identify_json_structure(file)
        if file_type in ("Envelope", "Bundle"):
            stix_files.append(file)
        if isinstance(file_type, dict):
            stix_files.append(file_type)
    return stix_files


def create_stix_generator(content_files):
    """
    Create a generator for iterating over STIX files.

    This function takes a list of JSON files, filters them to include only STIX files, and then
    creates a generator that yields each STIX file or object one at a time.

    Args:
        content_files (list): A list of JSON files.

    Returns:
        Generator: A generator that yields each STIX file from the filtered list one at a time.
    """
    return get_stix_files_generator(filtering_stix_files(content_files))


def get_stix_files_generator(json_files):
    yield from json_files


def test_module(client: Client) -> str:
    """Builds the iterator to check that the feed is accessible.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    client._http_request("GET", full_url=client._base_url)
    return "ok"


def fetch_indicators(
    client: Client,
    last_commit_fetch,
    params,
    tlp_color: Optional[str] = None,
    feed_tags: List = [],
    limit: int = -1,
) -> List[Dict]:
    """
    Fetches indicators from a GitHub repository using the provided client.

    Args:
        client (Client): The GitHub client used to fetch indicators.
        last_commit_fetch: The last commit fetched from the repository.
        tlp_color (Optional[str]): The Traffic Light Protocol (TLP) color to assign to the fetched indicators.
        feed_tags (List): Tags to associate with the fetched indicators.
        limit (int): The maximum number of indicators to fetch. Default is -1 (fetch all).

    Returns:
        List[Dict]: A list of dictionaries representing the fetched indicators.
    """
    demisto.debug(f"Before fetch command last commit sha run: {last_commit_fetch}")
    iterator, last_commit_info = get_indicators(client, params, last_commit_fetch)
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    for item in iterator:
        # value_ = item.get("value")
        # type_ = item.get("type")
        # raw_data = {
        #     "value": value_,
        #     "type": type_,
        # }

        # for key, value in item.items():
        #     raw_data.update({key: value})
        # indicator_obj = {
        #     "value": value_,
        #     "type": type_,
        #     "service": "github",
        #     "fields": {},
        #     "rawJSON": raw_data,
        # }

        if feed_tags:
            item["fields"]["tags"] = feed_tags

        if tlp_color:
            item["fields"]["trafficlightprotocol"] = tlp_color

        indicators.append(item)
    demisto.debug(f"After fetch command last run: {last_commit_info}")
    if last_commit_info:
        demisto.setLastRun({"last_commit": last_commit_info})

    return indicators


def get_indicators(client: Client, params, last_commit_fetch=None):
    indicators = []

    relevant_files, last_commit_info = get_commits_files(client, params, last_commit_fetch)
    feed_type = params.get("feedType",'')
    repo_files_content = get_content_files_from_repo(client, relevant_files, params)
    try:
        if feed_type == "YARA":
            indicators = get_yara_indicators(repo_files_content)
            demisto.debug(f"YARA indicators : {indicators}")

        elif feed_type == "STIX":
            stix_client = STIX2XSOARParser({})
            generator_stix_files = create_stix_generator(repo_files_content)
            indicators = stix_client.load_stix_objects_from_envelope(generator_stix_files)

        elif feed_type == "IOCs":
            for file in repo_files_content:
                indicators += extract_text_indicators(file, params)
            demisto.debug(f"IOCs` indicators : {indicators}")

    except Exception as err:
        demisto.debug(str(err))
        raise ValueError(f"Could not parse returned data as indicator. \n\nError massage: {err}")
    demisto.debug(f"fetching {len(indicators)} indicators")
    return indicators, last_commit_info


def get_indicators_command(client: Client, params:dict) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Outputs.
    """
    indicators = []
    try:
        indicators, _ = get_indicators(client, params)

        demisto.debug(f"indicators: {indicators}")
        return CommandResults(
            outputs_prefix=CONTEXT_PREFIX + ".Indicators",
            outputs_key_field="githubfeed",
            raw_response=RAW_RESPONSE,
            outputs=indicators,
        )

    except Exception as err:
        demisto.debug(str(err))
        raise ValueError(f"Could not parse returned data as indicator. \n\nError massage: {err}")


def fetch_indicators_command(client: Client, params: Dict[str, str]) -> List[Dict]:
    """Wrapper for fetching indicators from the feed to the Indicators tab.
    Args:
        client: Client object with request
        params: demisto.params()
    Returns:
        Indicators.
    """
    feed_tags = argToList(params.get("feedTags", ""))
    tlp_color = params.get("tlp_color")
    last_commit_fetch = demisto.getLastRun().get("last_commit")
    indicators = fetch_indicators(client, last_commit_fetch, params, tlp_color=tlp_color, feed_tags=feed_tags)
    return indicators


def main():
    params = demisto.params()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    base_url = str(params.get("url"))
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    owner = params.get("owner",'')
    repo = params.get("repo",'')
    api_token = (params.get("api_token") or {}).get("password", "")
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {api_token}"}

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            owner=owner,
            repo=repo,
            headers=headers,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "github-get-indicators":
            return_results(get_indicators_command(client, params))

        elif command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
