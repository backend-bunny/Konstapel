// Command linked links the test-only reporting provider into a non-test
// binary, which must fail at startup (TestLinkingIntoABinaryPanics).
package main

import (
	"fmt"

	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

func main() { fmt.Println("started with", reporttest.Contract) }
