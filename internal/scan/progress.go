package scan

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// prog is the run's status line. Package-level because every stage reports into
// it and threading it through six call sites would buy nothing; it is assigned
// once in Run, before any goroutine starts, and every method is nil-safe so
// tests and dry runs need no wiring at all.
var prog *progress

// progress is a two-line self-rewriting block on stderr:
//
//	▎⠹ step 3/3 lockfiles   ████████░░░░░░░░░░░░░░ 4210/17520  12m04s
//	▎ └ matching distinct packages   ██████░░░░░░░░ 12000/48219  npm
//
// It earns its place: walking a decade of history, or waiting on osv-scanner
// loading a 220 MB database, is minutes of total silence. A hung run and a
// working one look identical without it, and the natural reaction to that is
// Ctrl-C on a scan that was about to finish.
//
// Two lines because the two questions are different. "Is it working" is answered
// by the pass in progress; "how much is left" only by the run as a whole. The
// pass bar cannot answer the second — it fills and restarts several times per
// wave, and its unit changes from files to packages between passes.
//
// It owns stderr. Log lines go through it (see Write) so the block is erased,
// the line scrolls past, and the block is redrawn underneath instead of being
// shredded by interleaved output.
type progress struct {
	mu      sync.Mutex
	out     *os.File
	on      bool
	started time.Time

	// The run as a whole: which of its fixed steps we are in, and how much of
	// its one real unit of work — a distinct lockfile version — is settled.
	stepNo, stepTotal int
	stepName          string
	goalDone          int
	goalTotal         int

	// The step in progress, whose unit changes: files, packages, repositories.
	phase  string
	detail string
	done   int
	total  int

	pal        palette
	tick       int
	drawnLines int
	stop       chan struct{}
	once       sync.Once
	wg         sync.WaitGroup
}

func newProgress(out *os.File, enabled bool) *progress {
	p := &progress{out: out, on: enabled, started: time.Now(), stop: make(chan struct{})}
	// Same rules as the report's colours: off when redirected, off under NO_COLOR.
	p.pal = newPalette(out)
	if !enabled {
		return p
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(120 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				p.mu.Lock()
				p.tick++
				p.draw()
				p.mu.Unlock()
			}
		}
	}()
	return p
}

// step names which of the run's fixed steps is running. The count is fixed
// because the steps are: take inventory, walk history, resolve the lockfile
// versions it found. Waves and their read/match passes are iterations inside the
// third one, not steps of their own — there is no honest way to know how many of
// those there will be before the history is walked.
func (p *progress) step(index, of int, name string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stepNo, p.stepTotal, p.stepName = index, of, name
	p.draw()
}

// goal sets the run's total work, once walking the history has established what
// it is. Until then the overall line shows the step only: a bar with a made-up
// denominator is worse than no bar.
func (p *progress) goal(total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.goalTotal, p.goalDone = total, 0
	p.draw()
}

// advance moves the overall bar: one lockfile version settled, whether by a
// cache hit, a scan, or being found unparseable. Distinct from inc, and the
// distinction matters — the stage counter measures files during one pass and
// packages during the next, so it cannot double as the run's own total.
func (p *progress) advance(n int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.goalDone += n
	p.draw()
}

// stage names the pass in progress. total 0 means "unknown length": the line
// then shows a counter rather than a bar that could never fill.
func (p *progress) stage(name string, total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase, p.total, p.done, p.detail = name, total, 0, ""
	p.draw()
}

func (p *progress) inc(n int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done += n
	p.draw()
}

func (p *progress) note(detail string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.detail = detail
	p.draw()
}

// Write lets slog share stderr with the bar without corrupting it.
func (p *progress) Write(b []byte) (int, error) {
	if p == nil {
		return os.Stderr.Write(b)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.erase()
	n, err := p.out.Write(b)
	p.draw()
	return n, err
}

func (p *progress) logWriter() io.Writer {
	if p == nil || !p.on {
		return os.Stderr
	}
	return p
}

// close stops the ticker and leaves the cursor on a clean line, so the report
// never lands on top of a half-drawn bar.
//
// Idempotent on purpose: it is called explicitly before printing the report
// AND deferred, so that an early return still restores the terminal.
func (p *progress) close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		if p.on {
			close(p.stop)
			p.wg.Wait()
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.erase()
	})
}

var spinner = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

// gutter marks both status lines as one block. Log lines have no gutter, so a
// warning scrolling past directly above the bars still reads as a separate
// thing rather than as part of them.
const gutter = "▎"

// draw and erase both assume the mutex is held.
func (p *progress) draw() {
	if !p.on {
		return
	}
	c := p.pal
	var lines []string
	if p.stepTotal > 0 {
		s := []span{
			{gutter, c.cyan},
			{string(spinner[p.tick%len(spinner)]) + " ", c.bold + c.cyan},
			{fmt.Sprintf("step %d/%d ", p.stepNo, p.stepTotal), c.bold},
			{fmt.Sprintf("%-11s", p.stepName), c.cyan},
		}
		if p.goalTotal > 0 {
			s = append(s, barSpans(p.goalDone, p.goalTotal, 22, c.grn, c)...)
			s = append(s, span{fmt.Sprintf(" %d/%d", p.goalDone, p.goalTotal), c.bold})
		}
		s = append(s, span{"  " + elapsed(time.Since(p.started)), c.dim})
		lines = append(lines, render(s, statusWidth))
	}
	if p.phase != "" {
		s := []span{
			{gutter, c.cyan},
			{" └ ", c.dim},
			{fmt.Sprintf("%-28s", p.phase), c.reset},
		}
		switch {
		case p.total > 0:
			s = append(s, barSpans(p.done, p.total, 14, c.cyan, c)...)
			s = append(s, span{fmt.Sprintf(" %d/%d", p.done, p.total), c.dim})
		case p.done > 0:
			s = append(s, span{fmt.Sprintf("%d", p.done), c.dim})
		}
		if p.detail != "" {
			s = append(s, span{"  " + p.detail, c.dim})
		}
		lines = append(lines, render(s, statusWidth))
	}
	if len(lines) == 0 {
		return
	}
	p.erase()
	fmt.Fprint(p.out, "\r")
	for i, l := range lines {
		if i > 0 {
			fmt.Fprint(p.out, "\n")
		}
		fmt.Fprint(p.out, "\033[K"+l)
	}
	p.drawnLines = len(lines)
}

// ponytail: fixed 78-column cap instead of querying the real terminal width. A
// wrapped line would survive \r\033[K only on its last row, and reading the
// width needs an ioctl or a golang.org/x/term dependency this binary does not
// otherwise have. Widen if 80-column terminals stop being the floor.
const statusWidth = 78

// span is one piece of a status line with its colour.
//
// Colour is kept beside the text rather than baked into it so the line can be
// clipped on VISIBLE width. An escape sequence is made of runes too: clipping a
// coloured string by rune count cuts the visible text short by however many
// bytes of colour it contains, and can sever a sequence halfway, leaving the
// terminal in a colour nothing ever tells it to leave.
type span struct{ text, color string }

// render concatenates spans, colouring each and stopping at width visible runes.
func render(spans []span, width int) string {
	var b strings.Builder
	left := width
	for _, s := range spans {
		if left <= 0 {
			break
		}
		t := s.text
		if r := []rune(t); len(r) > left {
			t = string(r[:max(0, left-1)]) + "…"
		}
		left -= len([]rune(t))
		b.WriteString(s.color)
		b.WriteString(t)
		if s.color != "" {
			b.WriteString("\033[0m")
		}
	}
	return b.String()
}

func barSpans(done, total, width int, fill string, c palette) []span {
	filled := 0
	if total > 0 {
		filled = min(width, done*width/total)
	}
	return []span{
		{strings.Repeat("█", filled), fill},
		{strings.Repeat("░", width-filled), c.dim},
	}
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// erase clears every line the last draw wrote, walking back up to the first —
// the cursor sits on the last one, and leaving stale rows behind is how a
// multi-line status line turns into scrollback confetti.
func (p *progress) erase() {
	for i := p.drawnLines; i > 0; i-- {
		fmt.Fprint(p.out, "\r\033[K")
		if i > 1 {
			fmt.Fprint(p.out, "\033[A")
		}
	}
	p.drawnLines = 0
}

func elapsed(d time.Duration) string {
	d = d.Truncate(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}
