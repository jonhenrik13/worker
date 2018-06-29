package backend

import (
	"context"
	"io"
	"time"

	"github.com/travis-ci/worker/config"
)

func init() {
	Register("kubernetes", "Kubernetes", map[string]string{
		"LOG_OUTPUT": "kubernetes log output to write",
		"RUN_SLEEP":  "kubernetes runtime sleep duration",
	}, newKubernetesProvider)
}

type kubernetesProvider struct {
	cfg *config.ProviderConfig
}

func newKubernetesProvider(cfg *config.ProviderConfig) (Provider, error) {
	return &kubernetesProvider{cfg: cfg}, nil
}

func (p *kubernetesProvider) Start(ctx context.Context, _ *StartAttributes) (Instance, error) {
	var (
		dur time.Duration
		err error
	)

	if p.cfg.IsSet("STARTUP_DURATION") {
		dur, err = time.ParseDuration(p.cfg.Get("STARTUP_DURATION"))
		if err != nil {
			return nil, err
		}
	}

	return &kubernetesProvider{p: p, startupDuration: dur}, nil
}

func (p *kubernetesProvider) Setup(ctx context.Context) error { return nil }

type kubernetesInstance struct {
	p *kubernetesProvider

	startupDuration time.Duration
}

func (i *kubernetesInstance) UploadScript(ctx context.Context, script []byte) error {
	return nil
}

func (i *kubernetesInstance) RunScript(ctx context.Context, writer io.Writer) (*RunResult, error) {
	if i.p.cfg.IsSet("RUN_SLEEP") {
		rs, err := time.ParseDuration(i.p.cfg.Get("RUN_SLEEP"))
		if err != nil {
			return &RunResult{Completed: false}, err
		}
		time.Sleep(rs)
	}

	_, err := writer.Write([]byte(i.p.cfg.Get("LOG_OUTPUT")))
	if err != nil {
		return &RunResult{Completed: false}, err
	}

	return &RunResult{Completed: true}, nil
}

func (i *kubernetesInstance) Stop(ctx context.Context) error {
	return nil
}

func (i *kubernetesInstance) ID() string {
	return "kubernetes"
}

func (i *kubernetesInstance) ImageName() string {
	return "kubernetes"
}

func (i *kubernetesInstance) StartupDuration() time.Duration {
	return i.startupDuration
}
