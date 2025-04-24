import os
import typing
import re
from json import loads
from subprocess import PIPE, Popen
from urllib.parse import urlparse

from stalker_job_sdk import (JobStatus, TextField, WebsiteFinding, build_url,
                             is_valid_ip, is_valid_port, log_error,
                             log_finding, log_info, log_status, log_warning,
                             to_boolean, TagFinding)


class WebsiteInfo:
    def __init__(self, ip, port, domain, path, ssl):
        self.domain: str = domain
        self.ip: str = ip
        self.port: int = port
        self.path: str = path
        self.ssl: bool = ssl

class WebsiteRequest:
    method: str
    endpoint: str
    tag: str
    attribute: str
    source: str

class WebsiteResponse:
    status_code: int
    headers: typing.Dict[str, str]
    technologies: 'list[str]'
    body: str

class TagAction:
    enabled: bool
    name: str

class ContentRegex:
    def __init__(
            self, finding_name: str,
            finding_display_name: str,
            finding_context: str,
            target: str,
            regex: list[str],
            tag_enabled: bool = False,
            tag_name: str = '',
            exclude_file_extensions: list[str] = [],
            exclude_content_types: list[str] = []
            ):
        self.finding_name: str = finding_name
        self.finding_display_name: str = finding_display_name
        self.finding_context: str = finding_context
        self.exclude_file_extensions: list[str] = exclude_file_extensions
        self.exclude_content_types: list[str] = exclude_content_types
        
        if target not in ["headers", "body", "all"]:
            self.target: str = 'all'
        else:
            self.target = target
        self.regex: list[str] = regex
        self.tag: TagAction = TagAction()
        self.tag.enabled = tag_enabled
        self.tag.name = tag_name
    
class WebsiteFile:
    timestamp: str
    request: WebsiteRequest
    response: WebsiteResponse
    error: str
    
    def __init__(self, data: dict):
        self.timestamp = data.get("timestamp")
        self.error = data.get("error")
        self.request = WebsiteRequest()
        req: dict = data.get("request")
        self.request.attribute = req.get("attribute")
        self.request.endpoint = req.get("endpoint")
        self.request.method = req.get("method")
        self.request.source = req.get("source")
        self.request.tag = req.get("tag")
        self.response = WebsiteResponse()
        if not self.error:
            res: dict = data.get("response")
            self.response.headers = res.get("headers")
            self.response.status_code = res.get("status_code")
            self.response.technologies = res.get("technologies")
            self.response.body = res.get("body")
        

def get_valid_args():
    """Gets the arguments from environment variables"""
    target_ip: str = os.environ.get("targetIp")
    port: int = int(os.environ.get("port"))
    domain: str = os.environ.get("domainName")
    path: str = os.environ.get("path")
    ssl: str = to_boolean(os.environ.get("ssl"))
    max_depth: int = int(os.environ.get("maxDepth"))
    crawl_duration_seconds: int = int(os.environ.get("crawlDurationSeconds"))
    concurrency : int = int(os.environ.get("fetcherConcurrency"))
    parallelism : int = int(os.environ.get("inputParallelism"))
    
    extra_katana_option: str = os.environ.get("extraOptions")

    if not is_valid_ip(target_ip):
        log_error(f"targetIp parameter is invalid: {target_ip}")
        log_status(JobStatus.FAILED)
        exit()

    if not is_valid_port(port):
        log_error(f"port parameter is invalid: {str(port)}")
        log_status(JobStatus.FAILED)
        exit()

    if max_depth <= 0:
        log_error(f"maxDepth parameter is invalid: {str(max_depth)}")
        log_status(JobStatus.FAILED)
        exit()

    if crawl_duration_seconds <= 0:
        log_error(f"crawlDurationSeconds parameter is invalid: {str(crawl_duration_seconds)}")
        log_status(JobStatus.FAILED)
        exit()

    if concurrency <= 0:
        log_error(f"fetcherConcurrency parameter is invalid: {str(concurrency)}")
        log_status(JobStatus.FAILED)
        exit()

    if parallelism <= 0:
        log_error(f"inputParallelism parameter is invalid: {str(parallelism)}")
        log_status(JobStatus.FAILED)
        exit()

    return target_ip, port, domain, path, ssl, max_depth, crawl_duration_seconds, concurrency, parallelism, extra_katana_option

extension_exclusions = ['css', 'png', 'jpg', 'jpeg', 'svg', 'ico']
content_types_exclusions = ['text/css']
global_content_types_exclusions = ['application/vnd', 'video/', 'image/', 'audio/']

default_regex: list[ContentRegex] = [
    ContentRegex("WebsiteLoginPortal", "Login Portal", "Possible login portal", "body", [
        r"<input[^>]*?name=[\"']?(user(?:name)?|login|pass(?:word|wd)?|pwd)[\"']?[^>]*?>",
        r"<button[^>]*?(?:type=[\"']?submit[\"']?[^>]*?)?>.{0,100}?(Log\s?in|Sign\s?In|Conne(?:ct|xion))",
        r"<form[^>]*?(?:action|id)=[\"']?(?:login|Conne(?:ct|xion)|auth)[\"']?[^>]*?>",
        r"<div class=\"auth-login-actions\"",
        r"log\s?in|pass(?:word|wd)|sign\s?in|mot(?:\sde\s|\-)passe|(?:se\s)connecter|connexion|username|(?:nom d')utilisateur|authenti(?:cation|fication)"
    ], True, "Login", extension_exclusions, content_types_exclusions),
    ContentRegex("AuthenticationHeader", "Authentication Header", "WWW-Authenticate header found", "headers", [
        r"WWW-Authenticate:\s*(Basic|Bearer|Digest|NTLM)?"
    ], True, "Login"),
]

def emit_file_finding(file: WebsiteFile, wi: WebsiteInfo):
    fields = []

    if file.response.status_code:
        fields.append(TextField("statusCode", "Status Code", file.response.status_code))

    if file.request.endpoint:
        endpoint = urlparse(file.request.endpoint).path
        fields.append(TextField("endpoint", "Endpoint", endpoint))

    if file.request.method:
        fields.append(TextField("method", "Method", file.request.method))
        
    if file.request.tag:
        fields.append(TextField("tag", "Tag", file.request.tag))

    if file.request.attribute:
        fields.append(TextField("attribute", "Attribute", file.request.attribute))
    
    if file.request.source:
        fields.append(TextField("source", "Source", file.request.source))

    log_finding(
        WebsiteFinding(
            "WebsitePathFinding", wi.ip, wi.port, wi.domain, wi.path, wi.ssl, f"Website path", fields
        )
    )

def emit_technology_findings(technologies: 'list[str]', wi: WebsiteInfo):
    for tech in technologies:
        log_finding(
            WebsiteFinding(
                "WebsiteTechnologyFinding", wi.ip, wi.port, wi.domain, wi.path, wi.ssl, f"Technology", [TextField("technology", "Technology", tech)]
            )
        )

def emit_out_of_scope_files(endpoints: 'list[str]', wi: WebsiteInfo):
    if len(endpoints) <= 0:
        return
    
    fields = [TextField("oos_endpoint_title", "Out of scope endpoints", None)]
    for endpoint in endpoints:
        fields.append(TextField("oos_endpoint", None, endpoint))

    log_finding(
        WebsiteFinding(
            "OutOfScopeEndpoints", wi.ip, wi.port, wi.domain, wi.path, wi.ssl, f"Website out of scope endpoints", fields
        )
    )

def apply_regex(content_regex: ContentRegex, text: str):
    matches: list[re.Match] = []
    for regex in content_regex.regex:
        matches.extend(re.finditer(regex, text, re.IGNORECASE | re.DOTALL))
    return matches

def emit_regex_findings(content_regex: ContentRegex, matches: list[re.Match], wi: WebsiteInfo, wr: WebsiteRequest):
    if len(matches) <= 0:
        return
    
    fields = [TextField("context", None, content_regex.finding_context)]
    for match in matches:
        extracted_fields = []
        fields.append(TextField("match", "Match", match[0]))
        fields.append(TextField("endpoint", "Endpoint", wr.endpoint))

        for group in match.groups():
            extracted_fields.append(TextField("group", None, group))

        if len(extracted_fields) > 0:
            fields.append(TextField("groups_title", "Extracted groups", None))
            fields.extend(extracted_fields)
    
    log_finding(
        WebsiteFinding(
            content_regex.finding_name, wi.ip, wi.port, wi.domain, wi.path, wi.ssl, content_regex.finding_display_name, fields
        )
    )

    if content_regex.tag.enabled:
        log_finding(
            TagFinding(
                content_regex.tag.name, ip=wi.ip, port=wi.port, domainName=wi.domain, path=wi.path, protocol='tcp'
            )
        )

def should_analyse(endpoint: str, content_type_header: str | None, extension_exclusions: list[str], content_type_exclusions: list[str]):
    if content_type_header is not None:
        all_ct_exclusions = global_content_types_exclusions + content_type_exclusions
        for exclusion in all_ct_exclusions:
            if content_type_header.startswith(exclusion):
                return False

    extension = os.path.splitext(urlparse(endpoint).path)[1]
    if extension in extension_exclusions:
        return False
    
    return True


def analyse_response(file: WebsiteFile, website_info: WebsiteInfo):
    for regex in default_regex:
        if not should_analyse(file.request.endpoint, file.response.headers.get("content-type"), regex.exclude_file_extensions, regex.exclude_content_types):
            continue
        if regex.target == "all" or regex.target == "headers":
            if file.response.headers:
                matches: list[re.Match] = []
                for headerName in file.response.headers.keys():
                    full_header = f"{headerName}: {file.response.headers.get(headerName)}"
                    matches.extend(apply_regex(regex, full_header))

                emit_regex_findings(regex, matches, website_info, file.request)

        if regex.target == "all" or regex.target == "body":
            if file.response.body:
                emit_regex_findings(regex, apply_regex(regex, file.response.body), website_info, file.request)

def main():
    target_ip, port, domain, path, ssl, max_depth, crawl_duration_seconds, concurrency, parallelism, extra_options = get_valid_args()
    url = build_url(target_ip, port, domain, path, ssl)
    website_info = WebsiteInfo(target_ip, port, domain, path, ssl)
    
    katana_str: str = f"katana -u {url} -d {max_depth} -ct {crawl_duration_seconds} -c {str(concurrency)} -p {str(parallelism)} {extra_options}"
    log_info(f'Start of crawling: {katana_str}')

    # katana -u https://example.com -d 3 -ct 3600 -c 10 -p 10 -jc -kf all -duc -j -or -silent -td -do
    technologies: 'set[str]' = set()
    external_files: 'set[str]' = set()
    with Popen(katana_str, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True) as katana_process:
        
        for line in katana_process.stdout:
            file = ''
            try:
                file: WebsiteFile = WebsiteFile(loads(line))
                if file:
                    if file.error:
                        if file.error == "out of scope":
                            external_files.add(file.request.endpoint)
                        continue

                    if file.response.technologies:
                        technologies.update(file.response.technologies)

                    if file.response.status_code == 404:
                        continue
                    
                    emit_file_finding(file, website_info)

                    if(file.response):
                        analyse_response(file, website_info)

            except Exception as err:
                log_warning(err)
                continue

        for line in katana_process.stderr:
            log_error(line)
            
    emit_technology_findings(technologies, website_info)
    emit_out_of_scope_files(external_files, website_info)


main()
log_status(JobStatus.SUCCESS)
