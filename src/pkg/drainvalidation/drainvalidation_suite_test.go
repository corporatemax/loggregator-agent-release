package drainvalidation_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDrainvalidation(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Drainvalidation Suite")
}
