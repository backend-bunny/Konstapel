// An independent provider module: it builds against the published
// pkg/providerapi/v1 and pkg/providerkit packages only. The replace points
// at this repository so the example builds offline from a checkout; an
// external author drops it and requires a released Konstapel version.
module example.com/konstapel-reporting

go 1.27.3

require (
	github.com/backend-bunny/Konstapel v0.0.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
)

replace github.com/backend-bunny/Konstapel => ../../..
