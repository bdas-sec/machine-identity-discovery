"""pySigma processing pipelines for NHI rule field mapping."""

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation


def nhi_splunk_pipeline() -> ProcessingPipeline:
    """Field mapping pipeline for NHI rules targeting Splunk (CIM field names)."""
    return ProcessingPipeline(
        name="NHI Splunk Pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="nhi_file_access_splunk",
                transformation=FieldMappingTransformation({
                    "TargetFilename": "file_path",
                    "Contents": "_raw",
                }),
                rule_conditions=[LogsourceCondition(category="file_access")],
            ),
            ProcessingItem(
                identifier="nhi_network_connection_splunk",
                transformation=FieldMappingTransformation({
                    "dst_ip": "dest_ip",
                    "DestinationHostname": "dest_host",
                    "HttpRequestUri": "uri_path",
                }),
                rule_conditions=[LogsourceCondition(category="network_connection")],
            ),
            ProcessingItem(
                identifier="nhi_process_creation_splunk",
                transformation=FieldMappingTransformation({
                    "ParentImage": "parent_process",
                    "Image": "process",
                    "CommandLine": "process_command_line",
                }),
                rule_conditions=[LogsourceCondition(category="process_creation")],
            ),
            ProcessingItem(
                identifier="nhi_webserver_splunk",
                transformation=FieldMappingTransformation({
                    "cs-uri-query": "uri_query",
                }),
                rule_conditions=[LogsourceCondition(category="webserver")],
            ),
        ],
    )


def nhi_sentinel_pipeline() -> ProcessingPipeline:
    """Field mapping pipeline for NHI rules targeting Microsoft Sentinel (KQL)."""
    return ProcessingPipeline(
        name="NHI Sentinel Pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="nhi_file_access_sentinel",
                transformation=FieldMappingTransformation({
                    "TargetFilename": "TargetFilename",
                    "Contents": "FileContent",
                }),
                rule_conditions=[LogsourceCondition(category="file_access")],
            ),
            ProcessingItem(
                identifier="nhi_network_connection_sentinel",
                transformation=FieldMappingTransformation({
                    "dst_ip": "RemoteIP",
                    "DestinationHostname": "RemoteUrl",
                    "HttpRequestUri": "RequestUri",
                }),
                rule_conditions=[LogsourceCondition(category="network_connection")],
            ),
            ProcessingItem(
                identifier="nhi_process_creation_sentinel",
                transformation=FieldMappingTransformation({
                    "ParentImage": "InitiatingProcessFileName",
                    "Image": "FileName",
                    "CommandLine": "ProcessCommandLine",
                }),
                rule_conditions=[LogsourceCondition(category="process_creation")],
            ),
            ProcessingItem(
                identifier="nhi_webserver_sentinel",
                transformation=FieldMappingTransformation({
                    "cs-uri-query": "csUriQuery",
                }),
                rule_conditions=[LogsourceCondition(category="webserver")],
            ),
        ],
    )
