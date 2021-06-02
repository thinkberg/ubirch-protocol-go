module main

go 1.13

require (
	github.com/google/uuid v1.1.1
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.0.4
)

replace github.com/ubirch/ubirch-protocol-go/ubirch/v2 => ../ubirch
