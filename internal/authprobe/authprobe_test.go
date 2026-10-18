package authprobe

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// deterministicBody 上游刷新端点确定性失效的实测原文（凭证被拒：refresh token
// 已被撤销，等不来恢复）。
const deterministicBody = `{"code":12153,"msg":"12153:refresh token failed:400 Bad Request: invalid_grant: Session doesn't have required client","requestId":"x"}`

// refreshServer 返回只服务刷新端点的上游服务（响应由 refresh 决定），
// 并统计刷新请求次数——探针的全部断言都建立在「打了几次刷新」上。
func refreshServer(t *testing.T, refresh http.HandlerFunc) (*upstream.Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v2/plugin/auth/token/refresh") {
			t.Errorf("探针打了非刷新端点: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		calls.Add(1)
		refresh(w, r)
	}))
	t.Cleanup(srv.Close)
	return &upstream.Client{HTTP: srv.Client(), ChatBaseCN: srv.URL, BillingBaseCN: srv.URL}, &calls
}

// probePool 取一个单账号池（cn realm：domain 非 workbuddy.ai 家族）。
func probePool(t *testing.T) (*pool.Pool, *auth.Auth) {
	t.Helper()
	p := pool.New("")
	p.SetRandomSource(func(n int64) int64 { return 0 })
	a := &auth.Auth{UID: "u1", AccessToken: "at", RefreshToken: "rt", ExpiresAt: 9999999999, Domain: "www.codebuddy.cn"}
	p.Add(a)
	return p, a
}

// waitUntil 轮询等待条件成立（异步探针用）。
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

// TestCooldownAndProbeInvalidGrantDisables 确定性失效（invalid_grant）：
// 同步部分让账号**立刻退出选号**（面板不再显示「可用」、不再被正常选号选中），
// 异步探针用刷新端点定性 → 禁用（终态，需人工重登）。
//
// 探针响应用闸门卡住：把「同步冷却」与「异步定性」两段分开断言，避免竞态
// （探针实测亚秒级完成，不卡闸门时异步结果会先于断言落地）。
func TestCooldownAndProbeInvalidGrantDisables(t *testing.T) {
	release := make(chan struct{})
	up, calls := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(deterministicBody))
	})
	p, _ := probePool(t)
	pr := New(p, up)

	pr.CooldownAndProbe("u1", "", 0)

	// 同步部分：冷却已生效，账号退出健康候选集（尚未判死——定性还没回来）。
	st, ok := p.Status("u1")
	if !ok {
		t.Fatal("no status")
	}
	if !st.Cooling || st.Until.IsZero() || !st.Until.After(time.Now()) {
		t.Fatalf("账号应立刻进入探针期短冷却（不再显示可用）: %+v", st)
	}
	if st.Disabled {
		t.Fatalf("定性未回前不应判死: %+v", st)
	}
	for _, uid := range p.AvailableUIDs() {
		if uid == "u1" {
			t.Fatal("探针期账号不应留在健康候选集里")
		}
	}

	// 异步部分：刷新端点报确定性失效 → 禁用。
	close(release)
	waitUntil(t, "确定性失效禁用", func() bool {
		st, _ := p.Status("u1")
		return st.Disabled
	})
	st, _ = p.Status("u1")
	if !strings.Contains(st.DisabledReason, "invalid_grant") {
		t.Errorf("disabled_reason=%q 应含 invalid_grant", st.DisabledReason)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("刷新探针调用次数=%d want 1", got)
	}
}

// TestProbeRefreshOKKeepsAccount 刷新成功 → 账号未死：只保留探针期短冷却
// （到期自动回池），不 Disable（P0-1 误杀防护：一次瞬时 401 不能杀号），
// 且探针拿到的新 token 已写回内存凭证。
func TestProbeRefreshOKKeepsAccount(t *testing.T) {
	up, calls := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600,"domain":"www.codebuddy.cn"}}`))
	})
	p, a := probePool(t)
	pr := New(p, up)

	pr.CooldownAndProbe("u1", "", 0)
	waitUntil(t, "探针完成（token 更新）", func() bool { return a.AccessTokenValue() == "new-at" })

	st, _ := p.Status("u1")
	if st.Disabled {
		t.Fatalf("刷新成功不应禁用账号: %+v", st)
	}
	if !st.Cooling {
		t.Fatalf("短冷却应仍在（到期自动回池）: %+v", st)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("刷新探针调用次数=%d want 1", got)
	}
}

// TestProbeNonDeterministicCountsToThreshold 12153 但无确定性文案（瞬时抖动形态）
// → 保留既有 3 连击容错：前 2 次只计次不禁用，第 3 次才禁用。
func TestProbeNonDeterministicCountsToThreshold(t *testing.T) {
	up, _ := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
	})
	p, _ := probePool(t)
	pr := New(p, up)

	for i := 1; i <= 2; i++ {
		pr.probe("u1") // 同步调用探针本体，断言不依赖调度时序
		if st, _ := p.Status("u1"); st.Disabled {
			t.Fatalf("第 %d 次非确定性 12153 不应禁用: %+v", i, st)
		}
	}
	pr.probe("u1")
	st, _ := p.Status("u1")
	if !st.Disabled {
		t.Fatalf("第 3 次连续 12153 应禁用: %+v", st)
	}
	if st.DisabledReason != "12153 session dead" {
		t.Errorf("disabled_reason=%q want 12153 session dead", st.DisabledReason)
	}
}

// TestProbeSingleFlight 单飞：同账号并发触发只打一次刷新探针
// （否则一个死号被并发请求同时命中会放大成 N 次上游调用）。
func TestProbeSingleFlight(t *testing.T) {
	release := make(chan struct{})
	up, calls := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-release // 卡住首个探针，制造并发窗口
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(deterministicBody))
	})
	p, _ := probePool(t)
	pr := New(p, up)

	pr.ProbeAsync("u1")
	pr.ProbeAsync("u1")
	pr.ProbeAsync("u1")
	waitUntil(t, "首个探针进入上游", func() bool { return calls.Load() == 1 })
	close(release)
	waitUntil(t, "探针完成", func() bool {
		st, _ := p.Status("u1")
		return st.Disabled
	})
	if got := calls.Load(); got != 1 {
		t.Errorf("单飞失败：刷新探针调用次数=%d want 1", got)
	}
}

// TestProbeRefreshOKClearsStrikes 探针刷新成功要清连续 12153 计数（与 keepalive
// 「刷新成功 → ClearSessionDead」同口径）：否则历史瞬时失败会垫进后续判死阈值，
// 让真死号少算几次、多活几轮。
func TestProbeRefreshOKClearsStrikes(t *testing.T) {
	// mode==0 → 12153（非确定性）；mode==1 → 刷新成功。
	var mode atomic.Int32
	up, _ := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() == 1 {
			_, _ = w.Write([]byte(`{"code":0,"data":{"accessToken":"new-at","expiresIn":3600}}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":12153,"msg":"Offline user session not found"}`))
	})
	p, _ := probePool(t)
	pr := New(p, up)

	pr.probe("u1") // 计次 1
	pr.probe("u1") // 计次 2
	if st, _ := p.Status("u1"); st.Disabled {
		t.Fatalf("2 次非确定性 12153 不应禁用: %+v", st)
	}
	mode.Store(1)
	pr.probe("u1") // 刷新成功 → 计数清零
	mode.Store(0)
	pr.probe("u1") // 清后第 1 次
	pr.probe("u1") // 清后第 2 次
	if st, _ := p.Status("u1"); st.Disabled {
		t.Fatalf("刷新成功清计数后连续 2 次 12153 不应禁用（历史计数未清零？）: %+v", st)
	}
	pr.probe("u1") // 清后第 3 次 → 禁用
	if st, _ := p.Status("u1"); !st.Disabled {
		t.Fatalf("清后第 3 次连续 12153 应禁用: %+v", st)
	}
}

// TestCooldownAndProbeSkipsDisabledAccount 已禁用账号零动作：禁用是终态
// （等人工重登），再冷却/探针只会把「禁用」这条信息搅浑，也白打一次上游。
func TestCooldownAndProbeSkipsDisabledAccount(t *testing.T) {
	up, calls := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("已禁用账号不应触发探针")
	})
	p, _ := probePool(t)
	p.Disable("u1", "manual disable (panel)")
	pr := New(p, up)

	pr.CooldownAndProbe("u1", "", 0)

	st, _ := p.Status("u1")
	if !st.Disabled || st.DisabledReason != "manual disable (panel)" {
		t.Fatalf("禁用终态不应被探针改写: %+v", st)
	}
	if st.Cooling {
		t.Errorf("已禁用账号不应再被冷却: %+v", st)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("刷新探针调用次数=%d want 0", got)
	}
}

// TestNilProberSafe 探针是可选依赖：nil 接收者/空依赖必须是 no-op（不 panic），
// 否则 handler 或 scheduler 的裸用/测试路径会被拖垮。
func TestNilProberSafe(t *testing.T) {
	var nilProber *Prober
	nilProber.CooldownAndProbe("u1", "", 0)
	nilProber.ProbeAsync("u1")

	if got := New(nil, nil); got != nil {
		t.Errorf("pool 为空时 New 应返回 nil, got %+v", got)
	}
	p, _ := probePool(t)
	noUpstream := New(p, nil) // 只冷却、不探针的降级形态
	noUpstream.CooldownAndProbe("u1", "", 0)
	if st, _ := p.Status("u1"); !st.Cooling {
		t.Errorf("upstream 缺失时仍应完成同步冷却: %+v", st)
	}
}
