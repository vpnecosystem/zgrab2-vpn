# zschema sub-schema for zgrab2's sstp module
# Registers zgrab2-sstp globally, and sstp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

# modules/tcp/scanner.go - Results
sstp_scan_response = SubRecord({
    "result": SubRecord({
        "status": String(),
        "content-length": String(),
        "host": String(),
        "content-type": String(),
        "server": String(),
        "misc": String(),
        "body": String()
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-sstp", sstp_scan_response)

zgrab2.register_scan_response_type("sstp", sstp_scan_response)