module main

go 1.19

require (
	github.com/google/uuid v1.3.0
	github.com/ubirch/ubirch-protocol-go/ubirch/v2 v2.2.5
)

require (
	github.com/ubirch/go.crypto v0.1.2 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
)

replace github.com/ubirch/ubirch-protocol-go/ubirch/v2 => ../ubirch
