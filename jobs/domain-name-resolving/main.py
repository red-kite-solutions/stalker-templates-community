import os
import socket
import json

from stalker_job_sdk import DomainFinding, JobStatus, log_finding, log_status, log_error, log_warning


def main():
    hostnames = json.loads(os.environ.get("domainNames"))

    for hostname in hostnames:
        try:
            data = socket.gethostbyname_ex(hostname)
            ipx = data[2]

            for ip in ipx:
                log_finding(
                    DomainFinding(
                        "HostnameIpFinding", hostname, ip, "New ip", [], "HostnameIpFinding"
                    )
                )
        except:
            log_warning(f"Domain name {hostname} did not resolve.")

try:
    main()
    log_status(JobStatus.SUCCESS)
except Exception as err:
    log_error("An unexpected error occured")
    log_error(err)
    log_status(JobStatus.FAILED)
    exit()