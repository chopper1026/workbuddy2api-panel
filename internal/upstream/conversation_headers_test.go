// conversation_headers_test.go 会话头三件套恒发单测（issue #188 渠道校验）。
//
// 上游国际版网关对 /v2/chat/completions 校验 X-Conversation-ID /
// X-Conversation-Request-ID / X-Conversation-Message-ID，缺任一即 400
// code=11128 "conversation id missing"。这组用例把「恒发 + 派生兜底 + 缓存键不动」
// 三条契约钉死。
package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/session"
)

// conversationTrio 抓取一次 ChatHeaders 出站的三件套取值。
func conversationTrio(t *testing.T, meta ChatMeta) (convID, convReqID, msgID string) {
	t.Helper()
	a := &auth.Auth{AccessToken: "at", UID: "u1"}
	req := httptest.NewRequest(http.MethodPost, "https://fake.example/v2/chat/completions", nil)
	(&Client{}).ChatHeaders(req, a, "", meta)
	return req.Header.Get("X-Conversation-ID"),
		req.Header.Get("X-Conversation-Request-ID"),
		req.Header.Get("X-Conversation-Message-ID")
}

// TestConversationHeaderTrioAlwaysSent 三形态（零值 meta / 仅 convReqID / 完整 meta）
// 下三件套必须全部非空——任一为空即触发上游 400 11128。
func TestConversationHeaderTrioAlwaysSent(t *testing.T) {
	cases := []struct {
		name string
		meta ChatMeta
	}{
		{"zero meta", ChatMeta{}},
		{"request id only", ChatMeta{ConversationRequestID: "0123456789abcdef0123456789abcdef"}},
		{"full meta", ChatMeta{
			ConversationID:        "conv-from-client",
			ConversationRequestID: "fedcba9876543210fedcba9876543210",
			TraceID:               "abcdefabcdefabcdefabcdefabcdefab",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			convID, convReqID, msgID := conversationTrio(t, c.meta)
			if convID == "" || convReqID == "" || msgID == "" {
				t.Fatalf("trio must all be non-empty: convID=%q convReqID=%q msgID=%q", convID, convReqID, msgID)
			}
		})
	}
}

// TestConversationIDFallbackIsDerivedNotRandom 缺失 conversationId 时的兜底必须是
// **稳定派生**（同 convReqID → 同 convID），不能是随机值：
//   - 随机值会让同一会话每轮落进不同"会话"，上游按会话聚合的台账碎片化；
//   - 该值同时是 prompt_cache_key 的会话段来源，随机化会让前缀缓存命中归零
//     （费用按 cache_key.go 实测上涨约 17×）。
func TestConversationIDFallbackIsDerivedNotRandom(t *testing.T) {
	const convReqID = "0123456789abcdef0123456789abcdef"
	meta := ChatMeta{ConversationRequestID: convReqID}
	first, _, _ := conversationTrio(t, meta)
	second, _, _ := conversationTrio(t, meta)
	if first != second {
		t.Errorf("fallback conversation id must be stable across calls: %q vs %q", first, second)
	}
	if want := session.RequestIDForKey(convReqID); first != want {
		t.Errorf("fallback conversation id = %q want derived %q", first, want)
	}
}

// TestConversationIDClientValueWins 客户端给了 conversationId 就透传原值，
// 兜底不得覆盖（透传优先，避免网关改写客户端语义）。
func TestConversationIDClientValueWins(t *testing.T) {
	convID, _, _ := conversationTrio(t, ChatMeta{
		ConversationID:        "conv-from-client",
		ConversationRequestID: "0123456789abcdef0123456789abcdef",
	})
	if convID != "conv-from-client" {
		t.Errorf("client conversation id must be passed through verbatim, got %q", convID)
	}
}

// TestConversationHeaderMessageIDForm X-Request-ID 与 X-Conversation-Message-ID 同值，
// 且为 32 位 hex（官方客户端形态；此前 desktop 路径发的是毫秒字符串）。
func TestConversationHeaderMessageIDForm(t *testing.T) {
	a := &auth.Auth{AccessToken: "at", UID: "u1"}
	req := httptest.NewRequest(http.MethodPost, "https://fake.example/v2/chat/completions", nil)
	(&Client{}).ChatHeaders(req, a, "", ChatMeta{ConversationRequestID: "0123456789abcdef0123456789abcdef"})
	msgID := req.Header.Get("X-Conversation-Message-ID")
	if got := req.Header.Get("X-Request-ID"); got != msgID {
		t.Errorf("X-Request-ID = %q want same as X-Conversation-Message-ID %q", got, msgID)
	}
	if len(msgID) != 32 || strings.Trim(msgID, "0123456789abcdef") != "" {
		t.Errorf("message id = %q want 32 hex chars", msgID)
	}
}

// TestConversationHeadersDoNotTouchPromptCacheKey 兜底不得改写
// prepareBody → InjectPromptCacheKey 的输入：空 conversationId 下 cache key 的会话段
// 由 uid 单独哈希（convHex = sha256(uid + "|" + "")[:16]）——与修复前逐字一致。
// 这条钉死「头注入处的局部兜底不可回写 meta/拐进 prepareBody」：一旦回写，
// 每轮 conversationID 都不同 → cache key 漂移 → 前缀缓存命中归零（费用 +17×）。
func TestConversationHeadersDoNotTouchPromptCacheKey(t *testing.T) {
	c := &Client{}
	body := []byte(`{"model":"glm-5.2","messages":[{"role":"user","content":"hi"}]}`)
	got := string(c.prepareBody(body, "cn", "u1", ""))

	sum := sha256.Sum256([]byte("u1|"))
	wantKey := "wb2a-u1-" + hex.EncodeToString(sum[:16])
	if !strings.Contains(got, `"prompt_cache_key":"`+wantKey+`"`) {
		t.Errorf("empty conversation id must keep the uid-only cache key %q (pre-fix behavior):\n%s", wantKey, got)
	}
}
