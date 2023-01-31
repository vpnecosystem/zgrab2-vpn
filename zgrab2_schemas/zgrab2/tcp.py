# zschema sub-schema for zgrab2's tcp module
# Registers zgrab2-tcp globally, and tcp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

# modules/tcp/scanner.go - Results
tcp_scan_response = SubRecord({
    "result": SubRecord({
        "response": String(),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-tcp", tcp_scan_response)

zgrab2.register_scan_response_type("tcp", tcp_scan_response)