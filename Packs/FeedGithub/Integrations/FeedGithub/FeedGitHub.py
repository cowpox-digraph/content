import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from TAXII2ApiModule import *
import plyara

CONTEXT_PREFIX = "GITHUB"

FEED_TYPE = {
    "YARA": "yar",
    "STIX": "stix",
    "IOCs": "iocs",
}


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this gitHub Feed implementation, no special attributes defined
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, owner: str, repo: str, headers: dict):
        base_url = urljoin(base_url, f"/repos/{owner}/{repo}/commits")
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_list_commits(self, last_fetch, params=[]) -> list:
        """
        Retrieves a list of commits from the GitHub repository.

        This method sends an HTTP GET request to the GitHub API endpoint
        to retrieve a list of commits from the repository specified by the
        base URL.

        Returns:
            None: This method does not return any value directly. The retrieved
            commits can be accessed using the `_http_request` method or other
            appropriate mechanisms.

        Raises:
            Any exceptions raised by the `_http_request` method.
        """
        current_date = datetime.now().isoformat()
        if last_fetch:
            full_url = self._base_url + f"?since={last_fetch}&until={current_date}"
        else:
            full_url = self._base_url
        res = self._http_request("GET", full_url=full_url, params=params)
        last_run_commit_sha = demisto.getLastRun().get("sha")
        if res[-1].get("sha") == last_run_commit_sha:
            return res[:-1]
        return res

    def get_files_per_commit(self, list_commits) -> dict[str, list]:
        """
        Retrieves a dictionary containing files changed per commit.

        This method takes a list of commits and sends an HTTP GET request to
        the GitHub API for each commit to retrieve the list of files changed.
        It constructs a dictionary where each key is the commit SHA and the
        corresponding value is a list of files changed in that commit.

        Args:
            list_commits (List[Dict[str, any]]): A list of dictionaries representing commits.
                Each dictionary should contain information about a single commit.

        Returns:
            Dict[str, List[str]]: A dictionary where keys are commit SHA strings and values
                are lists of file paths changed in each commit.

        Raises:
            Any exceptions raised by the `_http_request` method.
        """
        return {commit["sha"]: self._http_request("GET", commit["sha"]).get("files", []) for commit in list_commits}


def parsing_files_by_status(commits_files: dict[str, list]) -> dict[str, list]:
    """
    Parsing files by their status.

    Args:
        commits_files (Dict[str, List[Dict[str, str]]]): A dictionary where keys are commit SHA strings and values
            are lists of files changed in each commit.

    Returns:
        Dict[str, List[Dict[str, str]]]: A dictionary where keys are commit SHA strings and values
            are lists of files that have A status 'added' or 'modified' in each commit.

    """
    relevant_files: dict[str, list[dict]] = {}
    for commit, files in commits_files.items():
        raw_files_list = []
        for file in files:
            if file.get("status") == "added" or file.get("status") == "modified":
                raw_files_list.append(file)
        relevant_files[commit] = raw_files_list
    return relevant_files


def get_files_names(commits_files: dict[str, list]) -> list:
    return [file.get("raw_url") for _, files in commits_files.items() for file in files]


def get_files_token(client: Client, relevant_files: list[str], format_files: str = None):  # type: ignore
    if format_files:
        relevant_files = [file for file in relevant_files if file.endswith(format_files)]
    return [client._http_request("GET", full_url=file, resp_type="text") for file in relevant_files]


def parse_and_map_yara_content(content_item: str) -> list:
    pattern = re.compile(r"rule\s+\w+\s*?\{(?:.*?\n)*?\}", re.DOTALL)
    content_rules = pattern.findall(content_item)
    parsed_rules = []
    for rule in content_rules:
        parser = plyara.Plyara()
        parsed_rule = parser.parse_string(rule)[0]
        metadata = {key: value for d in parsed_rule["metadata"] for key, value in d.items()}
        mapper = {
            "value": parsed_rule["rule_name"],
            "description": metadata.get("description", ""),
            "author": metadata.get("author", ""),
            "references": metadata.get("reference", ""),
            "sourcetimestamp": metadata.get("date", ""),
            "id": metadata.get("id", ""),
            "rule_strings": parsed_rule.get("strings", []),
            "condition": " ".join(parsed_rule["condition_terms"]),
            "raw rule": rule,
        }
        parsed_rules.append(mapper)
    return parsed_rules


def extract_last_commit_info(list_commits):
    last_date = list_commits[0].get("commit", "").get("author", "").get("date", "")
    last_commit_sha = list_commits[0].get("sha", "")
    return {"date": last_date, "sha": last_commit_sha}


def get_commits_files(client: Client, last_fetch) -> tuple[list, dict]:
    """
    Retrieve files from commits based on the last fetch timestamp.

    Args:
        client (Client): The client to interact with the source.
        last_fetch (str): The timestamp of the last fetch.

    Returns:
        tuple[list, dict]: A tuple containing a list of content files and a dictionary with information
                           about the last commit.

    Raises:
        IndexError: If an index error occurs during the extraction of last commit information.

    """
    list_commits = client.get_list_commits(last_fetch)
    try:
        last_commit_info = extract_last_commit_info(list_commits)
        all_commits_files = client.get_files_per_commit(list_commits)
        relevant_files = parsing_files_by_status(all_commits_files)
        feed_files_raw_url = get_files_names(relevant_files)
        return feed_files_raw_url, last_commit_info
    except IndexError:
        return [], last_fetch


def get_yara_indicator(content: list):
    parsed_rules = []
    for file in content:
        parsed_rules += parse_and_map_yara_content(file)
    return parsed_rules


def detect_domain_type(domain: str):
    try:
        import tldextract
    except Exception:
        raise Exception(
            "Missing tldextract module, In order to use the auto detect function please use a docker"
            " image with it installed such as: demisto/jmespath"
        )
    try:
        tldextract_version = tldextract.__version__
        if LooseVersion(tldextract_version) < "3.0.0":
            no_cache_extract = tldextract.TLDExtract(cache_file=False, suffix_list_urls=None)
        else:
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


def extract_text_indicators(content: str):
    content = content.replace("[.]", ".").replace("[@]", "@")  # Refang indicator prior to checking
    indicators = []
    for regex, type in regex_indicators:
        matches = re.finditer(regex, content)
        if matches:
            indicators += [{"value": match.group(0), "type": type} for match in matches]
    for regex, type, group_name in regex_with_groups:
        matches = re.finditer(regex, content)
        if matches:
            for match in matches:
                if regex in (ipv4Regex, urlRegex):
                    indicators.append({"value": match.group(group_name), "type": type})
                elif regex == domainRegex:
                    regex_type = type(match.group(group_name))
                    if regex_type:
                        indicators.append({"value": match.group(group_name), "type": regex_type})
    return indicators


def identify_json_structure(json_data: dict) -> Any:
    """
    Identify the structure of a JSON data.

    Args:
        json_data (dict): A dictionary representing the JSON data.

    Returns:
        Any: The identified structure of the JSON data. Possible values are:
             - "Bundle": If the JSON data is structured as a STIX Bundle.
             - "Envelope": If the JSON data is structured as a STIX Envelope.
             - dict: If the JSON data contains a list of STIX objects, returns a dictionary with the key "objects"
                     and the list of objects as its value.
             - None: If the structure cannot be identified.
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
    Filter a list of JSON files to include only STIX files.

    Args:
        content_files (list): A list of JSON files.

    Returns:
        list: A filtered list containing only STIX files or objects. If an object is identified as a STIX Envelope or Bundle,
              it is included as-is. If an object contains a list of STIX objects, it is included with the key "objects" in
              a dictionary.
    """
    stix_files = []
    for file in content_files:
        file_type = identify_json_structure(file)
        if file_type in ("Envelope", "Bundle"):
            stix_files.append(file)
        if isinstance(file_type, dict):
            stix_files.append(file_type)
    return stix_files


def create_generator(content_files):
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


def detect_type(relevant_files: list, client: Client) -> str:
    format_file = relevant_files[0].split(".")[-1]
    if format_file not in ("yar", "json"):
        return "iocs"
    if format_file == "json":
        raw_json = get_files_token(client, relevant_files[0])
        if not filtering_stix_files(raw_json):
            return "iocs"
        return "stix"
    return format_file


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
    client: Client, last_fetch, feed_type: str = "AUTO", tlp_color: Optional[str] = None, feed_tags: List = [], limit: int = -1
) -> List[Dict]:
    """
    Fetch indicators from the feed.

    Args:
        client (Client): The HTTP client instance.
        last_fetch (str): The timestamp indicating when the fetch was last executed.
        feed_type (str): The type of feed to fetch. Default is "AUTO".
        tlp_color (str): The Traffic Light Protocol (TLP) color to assign to the fetched indicators.
        feed_tags (List): List of tags to assign to the fetched indicators.
        limit (int): Limit the number of fetched indicators. Default is -1, indicating no limit.

    Returns:
        List[Dict]: A list of dictionaries representing the fetched indicators.
    """
    demisto.debug(f"Before fetch command last run: {last_fetch}")
    iterator, last_commit_info = get_indicators(client, feed_type, last_fetch)
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value_ = item.get("value")
        type_ = item.get("type")
        raw_data = {
            "value": value_,
            "type": type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        for key, value in item.items():
            raw_data.update({key: value})
        indicator_obj = {
            "value": value_,
            "type": type_,
            "service": "github",
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            "fields": {},
            "rawJSON": raw_data,
        }

        if feed_tags:
            indicator_obj["fields"]["tags"] = feed_tags

        if tlp_color:
            indicator_obj["fields"]["trafficlightprotocol"] = tlp_color

        indicators.append(indicator_obj)
    demisto.debug(f"After fetch command last run: {last_commit_info}")
    if last_commit_info:
        demisto.setLastRun(last_commit_info)

    return indicators


def get_indicators(client: Client, feed_type, last_fetch=None):
    indicators = []

    relevant_files, last_commit_info = get_commits_files(client, last_fetch)
    feed_type = detect_type(relevant_files, client) if feed_type == "AUTO" else FEED_TYPE.get(feed_type)
    format_file = feed_type if feed_type == "yar" else "json" if feed_type == "stix" else None
    files_tokens = get_files_token(client, relevant_files, format_file)  # type: ignore
    try:
        if feed_type == "yar":
            indicators = get_yara_indicator(files_tokens)
            demisto.debug(f"YARA indicators : {indicators}")

        elif feed_type == "stix":
            stix_client = STIX2XSOARParser({})
            files_tokens = eval((demisto.params()).get("data"))
            generator_stix_files = create_generator(files_tokens)
            indicators = stix_client.load_stix_objects_from_envelope(generator_stix_files)

        elif feed_type == "iocs":
            for file in files_tokens:
                indicators += extract_text_indicators(file)
            # indicators += extract_text_indicators(str((demisto.params()).get('data')))
            demisto.debug(f"IOCs` indicators : {indicators}")

    except Exception as err:
        demisto.debug(str(err))
        raise ValueError(f"Could not parse returned data as indicator. \n\nError massage: {err}")
    return indicators, last_commit_info


def get_indicators_command(client: Client, feed_type: str = "AUTO") -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    indicators = []
    try:
        indicators, _ = get_indicators(client=client, feed_type=feed_type)

        demisto.debug(f"indicators: {indicators}")
        return CommandResults(
            outputs_prefix=CONTEXT_PREFIX + ".Indicators",
            outputs_key_field="githubfeed",
            raw_response=indicators,
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
    feed_type = str(params.get("feedType"))
    last_run = demisto.getLastRun().get("date", None)
    indicators = fetch_indicators(client, last_run, feed_type=feed_type, tlp_color=tlp_color, feed_tags=feed_tags)
    return indicators


def main():
    """
    main function, parses params and runs command functions
    """
    params = demisto.params()

    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    base_url = str(params.get("url"))
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    owner = str(params.get("owner"))
    repo = str(params.get("repo"))
    api_token = str(params.get("api_token"))
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {api_token}"}
    feed_type = str(params.get("feedType"))

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
            return_results(get_indicators_command(client, feed_type))

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
