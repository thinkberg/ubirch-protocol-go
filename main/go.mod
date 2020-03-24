module main

go 1.12

require (
	github.com/google/uuid v1.1.1
	github.com/paypal/go.crypto v0.1.0
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.0.2
)

replace github.com/ubirch/ubirch-protocol-go/ubirch/v2 => ../ubirch
