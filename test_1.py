from sigma.backends.sentinelone import SentinelOnePQBackend
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

list_of_rules = []

list_of_files = ['./test_rule.yml']#, './test_rule.yml']

rule = SigmaRule.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    DestinationHostname: foo bar
                    DestinationPort: 445
                    DestinationIp: 0.0.0.0
                    User: administrator
                    SourceIp: 1.1.1.1
                    SourcePort: 135
                    Protocol: udp
                    dst_ip: 2.2.2.2
                    src_ip: 3.3.3.3
                    dst_port: 80
                    src_port: 8080
                condition: sel
""")


backend = SentinelOnePQBackend()
print(backend.convert_rule(rule)[0])

translation_dict = {
    'process_creation':{                
        "ProcessId":"TgtProcPID",
        "Image":"TgtProcImagePath",
        "Description":"TgtProcDisplayName", #Not sure whether this should be Description or Product???
        "Product":"TgtProcDisplayName",
        "Company":"TgtProcPublisher",
        "CommandLine":"TgtProcCmdLine",
        "CurrentDirectory":"TgtProcImagePath",
        "User":"TgtProcUser",
        "TerminalSessionId":"TgtProcSessionId",
        "IntegrityLevel":"TgtProcIntegrityLevel",
        "md5":"TgtProcMd5",
        "sha1":"TgtProcSha1",
        "sha256":"TgtProcSha256",
        "ParentProcessId":"SrcProcPID",
        "ParentImage":"SrcProcImagePath",
        "ParentCommandLine":"SrcProcCmdLine",
    },
    'file':{
        "Image": "SrcProcImagePath",
        "CommandLine":"SrcProcCmdLine",
        "ParentImage":"SrcProcParentImagePath",
        "ParentCommandLine":"SrcProcParentCmdline",
        "TargetFilename":"TgtFilePath", 
        "SourceFilename":"TgtFileOldPath",
        "User":"SrcProcUser"
    },
    'image_load':{
        "ImageLoaded":"ModulePath",
        "Image": "SrcProcImagePath",
        "CommandLine":"SrcProcCmdLine",
        "ParentImage":"SrcProcParentImagePath",
        "ParentCommandLine":"SrcProcParentCmdline",
        "sha1":"ModuleSha1",
        "md5": "ModuleMd5"
    },
    'pipe_creation':{
        "PipeName":"NamedPipeName",
        "Image": "SrcProcImagePath",
        "CommandLine":"SrcProcCmdLine",
        "ParentImage":"SrcProcParentImagePath",
        "ParentCommandLine":"SrcProcParentCmdline",
    },
    'registry':{
        "Image": "SrcProcImagePath",
        "CommandLine":"SrcProcCmdLine",
        "ParentImage":"SrcProcParentImagePath",
        "ParentCommandLine":"SrcProcParentCmdline",
        "TargetObject": "RegistryKeyPath",
        "Details": "RegistryValue"
    },
    'dns':{
        "Image": "SrcProcImagePath",
        "CommandLine":"SrcProcCmdLine",
        "ParentImage":"SrcProcParentImagePath",
        "ParentCommandLine":"SrcProcParentCmdline",
        "query": "DnsRequest",
        "answer":"DnsResponse",
        "QueryName": "DnsRequest",
        "record_type":"DnsResponse"
    },
    'network':{
        "Image": "SrcProcImagePath",
        "CommandLine":"SrcProcCmdLine",
        "ParentImage":"SrcProcParentImagePath",
        "ParentCommandLine":"SrcProcParentCmdline",
        "DestinationHostname":["Url", "DnsRequest"],
        "DestinationPort":"DstPort",
        "DestinationIp":"DstIP",
        "User":"SrcProcUser",
        "SourceIp":"SrcIP",
        "SourcePort":"SrcPort",
        "Protocol":"NetProtocolName",
        "dst_ip":"DstIP",
        "src_ip":"SrcIP",
        "dst_port":"DstPort",
        "src_port":"SrcPort"
    }
}