package syslog_test

import (
	"code.cloudfoundry.org/loggregator-agent-release/src/internal/testhelper"
	"code.cloudfoundry.org/loggregator-agent-release/src/pkg/egress/syslog"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Loggregator Emitter", func() {
	Describe("EmitLog()", func() {
		It("emits a log message", func() {
			logClient := testhelper.NewSpyLogClient()
			emitter := syslog.NewAppLogEmitter(logClient, "0")

			emitter.EmitLog("app-id", "some-message")

			messages := logClient.Message()
			appIDs := logClient.AppID()
			sourceTypes := logClient.SourceType()
			Expect(messages).To(HaveLen(2))
			Expect(messages[0]).To(Equal("some-message"))
			Expect(messages[1]).To(Equal("some-message"))
			Expect(appIDs[0]).To(Equal("app-id"))
			Expect(appIDs[1]).To(Equal("app-id"))
			Expect(sourceTypes).To(HaveKey("LGR"))
			Expect(sourceTypes).To(HaveKey("SYS"))
		})

		It("does not emit a log message if the appID is empty", func() {
			logClient := testhelper.NewSpyLogClient()
			emitter := syslog.NewAppLogEmitter(logClient, "0")

			emitter.EmitLog("", "some-message")

			messages := logClient.Message()
			appIDs := logClient.AppID()
			sourceTypes := logClient.SourceType()
			Expect(messages).To(HaveLen(0))
			Expect(appIDs).To(HaveLen(0))
			Expect(sourceTypes).ToNot(HaveKey("LGR"))
			Expect(sourceTypes).ToNot(HaveKey("SYS"))
		})
	})
})