package batching_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"code.cloudfoundry.org/go-loggregator/v10/rpc/loggregator_v2"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/plumbing/batching"
)

var _ = Describe("V2EnvelopeBatcher", func() {
	It("works", func() {
		writer := &spyV2EnvelopeWriter{}
		b := batching.NewV2EnvelopeBatcher(1, time.Minute, writer)

		b.Write(&loggregator_v2.Envelope{
			SourceId: "test-source-id",
		})

		Expect(writer.batch).To(HaveLen(1))
		Expect(writer.batch[0].GetSourceId()).To(Equal("test-source-id"))
	})
})

type spyV2EnvelopeWriter struct {
	batch  []*loggregator_v2.Envelope
	called int
}

func (w *spyV2EnvelopeWriter) Write(batch []*loggregator_v2.Envelope) {
	w.batch = batch
	w.called++
}
