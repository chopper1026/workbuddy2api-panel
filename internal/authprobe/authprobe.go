// Package authprobe 认证失效的定性探针。
//
// 上游把「凭证不再被接受」表达成多种形态，其中一类**无法当场定性**：HTTP 401 带
// 网关自己的 HTML 错误页（APISIX/openresty 的 "401 Authorization Required"），
// body 里没有业务 code/msg，看不出是「session 已死」还是「瞬时抖动」。这类形态此前
// 落 ErrClient 兜底 → 只换号不罚：账号既不冷却也不判死，以「可用」身份反复被选中
// 接流量，余额任务每 10 分钟打一次 401 也毫无痕迹（实测潜伏 8 小时，客户端连吃 503）。
//
// 本包把这类事实的处置收敛为一处：**先让账号退出选号**（状态立刻不再显示「可用」，
// 也不再接流量），再用刷新端点做一次探针定性——
//
//   - 12153 + invalid_grant（确定性失效，RFC 6749 refresh grant 拒绝码）→ 禁用，
//     等人工重登；
//   - 12153 无确定性文案（瞬时抖动形态）→ 记一次 12153 计次，达阈才禁用；
//   - 刷新成功 → 只保留探针期短冷却，到期自动回池（不误杀：P0-1 的 13 个
//     被一次 12153 杀掉的号复查全部刷新成功）；
//   - 探针本身失败/超时（网络抖动）→ 定性不了，保留短冷却，下次请求再判。
//
// 为什么不直接在判据层复用 ErrSessionDead：那是「确认死亡 → 禁用」的终态语义，
// 套在一次瞬时 401 上会误杀健康账号。探针是「多用一次刷新请求换不误杀」的取舍。
package authprobe

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/logfmt"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// DefaultCooldown 探针期短冷却：账号立刻退出选号，背景探针在窗口内定性。
// 取 60s 的理由：覆盖刷新探针的常规往返（实测亚秒级）与其 30s I/O 上限，
// 同时充当「同一账号同形态连环失败」的节流窗口（冷却中的号不再被选号命中，
// 只有全池兜底路径可能再进来，此时单飞语义保证不重复探针）。
const DefaultCooldown = 60 * time.Second

// CooldownReason 探针期冷却的持久化 reason（state.json + 面板展示）。
const CooldownReason = "upstream 401 (auth rejected, verifying)"

// DisableReason 确定性失效（invalid_grant）判死时的持久化 reason。
// 保留既有 "12153 session dead" 前缀：面板/日志/运维口径按此前缀识别本类终态。
const DisableReason = "12153 session dead (invalid_grant)"

// Prober 探针：持有池与上游客户端，按 uid 单飞。
//
// nil 安全：New 在 pool 为空时返回 nil，且各方法对 nil 接收者/缺失依赖是 no-op，
// 调用方无需到处 nil 判断（与 handler 的 wafIP 门控同一哲学：没配就没这一步）。
type Prober struct {
	pool *pool.Pool
	up   *upstream.Client
	// inflight 单飞表：同一账号同时只有一次探针在途。没有它时，一个死号被
	// 并发请求同时命中会打出 N 个刷新请求（全池兜底路径尤其容易这样）。
	inflight sync.Map // uid → struct{}
}

// New 构造探针；pool 为空（裸用/测试）返回 nil。
// up 为空时保留「只冷却、不探针」降级：状态可见性（退出选号）仍然成立，
// 只是没有背景定性这一步。
func New(p *pool.Pool, up *upstream.Client) *Prober {
	if p == nil {
		return nil
	}
	return &Prober{pool: p, up: up}
}

// CooldownAndProbe 认证被拒的统一处置入口（chat 路径与保号任务共用）：
// 同步冷却（账号立刻退出选号）+ 异步探针定性。d <= 0 时用 DefaultCooldown。
// 返回是否真的动作了（调用方据此决定要不要打「已退出选号」这类日志）。
//
// 已禁用（disabled）的账号零动作：禁用是终态（等人工重登），再冷却/探针没有意义，
// 只会把「禁用」这条信息搅浑。
func (p *Prober) CooldownAndProbe(uid, reason string, d time.Duration) bool {
	if p == nil || p.pool == nil || uid == "" {
		return false
	}
	if st, ok := p.pool.Status(uid); ok && st.Disabled {
		return false
	}
	if d <= 0 {
		d = DefaultCooldown
	}
	if reason == "" {
		reason = CooldownReason
	}
	p.pool.Cooldown(uid, pool.CoolSoft, d, reason)
	p.ProbeAsync(uid)
	return true
}

// ProbeAsync 启动一次异步探针（单飞）。已有一发在途时直接返回。
func (p *Prober) ProbeAsync(uid string) {
	if p == nil || p.pool == nil || p.up == nil || uid == "" {
		return
	}
	if _, loaded := p.inflight.LoadOrStore(uid, struct{}{}); loaded {
		return
	}
	go func() {
		defer p.inflight.Delete(uid)
		p.probe(uid)
	}()
}

// probe 探针本体：用刷新端点给账号定性并落处置。
func (p *Prober) probe(uid string) {
	acct := p.pool.AuthByUID(uid)
	if acct == nil {
		return // 探针期间账号已被移除
	}
	label := logfmt.Label(uid, acct.Nickname)
	if strings.TrimSpace(acct.RefreshTokenValue()) == "" {
		// 无 refreshToken 可探（凭证文件残缺）：定性不了，保留短冷却等人工处理。
		log.Printf("auth-probe %s: 无 refreshToken，无法定性（保留短冷却）", label)
		return
	}
	err := p.up.RefreshToken(acct)
	if err == nil {
		if serr := acct.SaveAtomic(); serr != nil {
			// 刷新成功但落盘失败：内存里是新 token，重启会回旧值——必须暴露。
			log.Printf("auth-probe %s: refresh ok but save failed: %v", label, serr)
		}
		// 刷新成功 = 账号没死的最强证据：清连续 12153 计数（与 keepalive「刷新成功 →
		// ClearSessionDead」同口径）。不清会把历史瞬时失败垫进后续判死阈值，让真死号
		// 少算几次、多活几轮。
		p.pool.ClearSessionDead(uid)
		// 账号未死：401 属瞬时抖动/网关侧拒绝。只保留探针期短冷却（到期自动回池），
		// 不 Disable、不计 12153——这正是「不误杀」的那条路径。
		log.Printf("auth-probe %s: refresh 成功 — 凭证有效（401 属瞬时），短冷却到期自动回池", label)
		return
	}
	var ue *upstream.Error
	switch {
	case errors.As(err, &ue) && ue.Kind == upstream.ErrSessionDead && upstream.IsDeterministicSessionDead(ue.Msg):
		// 确定性失效（invalid_grant）：refresh token 已被上游撤销，等不来恢复，
		// 立即判死（不占 3 次容错额度，见 deterministicSessionDeadMarkers 注释）。
		p.pool.Disable(uid, DisableReason)
		log.Printf("auth-probe %s: %v — 确定性失效，已禁用（需重新登录）", label, err)
	case errors.As(err, &ue) && ue.Kind == upstream.ErrSessionDead:
		// 12153 但无确定性文案：保留既有 3 连击容错（瞬时 12153 的真实形态）。
		if p.pool.NoteSessionDead(uid) {
			log.Printf("auth-probe %s: 连续 %d 次 12153 session dead — 禁用", label, pool.SessionDeadThreshold())
		} else {
			log.Printf("auth-probe %s: 12153（非确定性）— 计次，暂不禁用", label)
		}
	default:
		// 探针自身失败（网络抖动/上游 5xx 等）：定性不了，保留短冷却。
		log.Printf("auth-probe %s: 无法定性（%v）— 保留短冷却", label, err)
	}
}
