package backend

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	gocontext "context"

	"github.com/pkg/errors"
	"github.com/travis-ci/worker/config"
	"github.com/travis-ci/worker/context"
	"github.com/travis-ci/worker/ssh"
)

func init() {
	Register("kubernetes", "Kubernetes", map[string]string{
		"LOG_OUTPUT": "kubernetes log output to write",
		"RUN_SLEEP":  "kubernetes runtime sleep duration",
	}, newKubernetesProvider)
}

/******** POC SECTION ****/

type kubernetesContainerTmp struct {
	SSHPort  int    `json:"ssh_port"`
	Status   string `json:"status"`
	HostName string `json:"hostname"`
}

var (
	defaultKubernetesScriptLocation = "/home/jonhenrik/travis-in-kubernetes"
)

/****** POC SECTION *******/

type kubernetesProvider struct {
	cfg            *config.ProviderConfig
	sshDialer      ssh.Dialer
	sshDialTimeout time.Duration
	execCmd        []string
}

func newKubernetesProvider(cfg *config.ProviderConfig) (Provider, error) {

	sshDialer, err := ssh.NewDialerWithPassword("travis")

	if err != nil {
		return nil, errors.Wrap(err, "couldn't create SSH dialer")
	}

	sshDialTimeout := defaultDockerSSHDialTimeout
	if cfg.IsSet("SSH_DIAL_TIMEOUT") {
		sshDialTimeout, err = time.ParseDuration(cfg.Get("SSH_DIAL_TIMEOUT"))
		if err != nil {
			return nil, err
		}
	}

	execCmd := strings.Split(defaultExecCmd, " ")
	if cfg.IsSet("EXEC_CMD") {
		execCmd = strings.Split(cfg.Get("EXEC_CMD"), " ")
	}

	return &kubernetesProvider{
		cfg:            cfg,
		sshDialTimeout: sshDialTimeout,
		sshDialer:      sshDialer,
		execCmd:        execCmd,
	}, nil

}

func (p *kubernetesProvider) Start(ctx gocontext.Context, startAttributes *StartAttributes) (Instance, error) {
	var (
		dur time.Duration
		err error
	)

	logger := context.LoggerFromContext(ctx).WithField("self", "backend/kubernetes_provider")
	hostName := hostnameFromContext(ctx)
	out, err := exec.Command(fmt.Sprintf("%s/step_start.sh", defaultKubernetesScriptLocation), hostName).Output()

	if err != nil {
		logger.WithField("err", err).Error("couldn't run script ")
	}
	var container kubernetesContainerTmp

	err = json.Unmarshal(out, &container)
	if err != nil {
		logger.WithField("err", err).Error("unable to unmarshal output from script")
	}

	return &kubernetesInstance{
		provider:        p,
		startupDuration: dur,
		container:       &container,
	}, nil
}

func (p *kubernetesProvider) Setup(ctx gocontext.Context) error { return nil }

type kubernetesInstance struct {
	provider        *kubernetesProvider
	container       *kubernetesContainerTmp
	startupDuration time.Duration
}

func (i *kubernetesInstance) UploadScript(ctx gocontext.Context, script []byte) error {
	return i.uploadScriptSCP(ctx, script)
}

func (i *kubernetesInstance) uploadScriptSCP(ctx gocontext.Context, script []byte) error {
	conn, err := i.sshConnection(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	existed, err := conn.UploadFile("build.sh", script)
	if existed {
		return ErrStaleVM
	}
	if err != nil {
		return errors.Wrap(err, "couldn't upload build script")
	}

	return nil
}

func (i *kubernetesInstance) sshConnection(ctx gocontext.Context) (ssh.Connection, error) {
	time.Sleep(2 * time.Second)
	return i.provider.sshDialer.Dial(fmt.Sprintf("127.0.0.1:%d", i.container.SSHPort), "travis", i.provider.sshDialTimeout)
}

func (i *kubernetesInstance) RunScript(ctx gocontext.Context, output io.Writer) (*RunResult, error) {
	return i.runScriptSSH(ctx, output)
}

func (i *kubernetesInstance) runScriptSSH(ctx gocontext.Context, output io.Writer) (*RunResult, error) {
	conn, err := i.sshConnection(ctx)
	if err != nil {
		return &RunResult{Completed: false}, errors.Wrap(err, "couldn't connect to SSH server")
	}
	defer conn.Close()

	exitStatus, err := conn.RunCommand(strings.Join(i.provider.execCmd, " "), output)

	return &RunResult{Completed: err != nil, ExitCode: exitStatus}, errors.Wrap(err, "error running script")
}

func (i *kubernetesInstance) Stop(ctx gocontext.Context) error {
	logger := context.LoggerFromContext(ctx).WithField("self", "backend/kubernetes_provider")
	hostName := hostnameFromContext(ctx)
	_, err := exec.Command(fmt.Sprintf("%s/step_stop.sh", defaultKubernetesScriptLocation), hostName).Output()

	if err != nil {
		logger.WithField("err", err).Error("couldn't run script ")
	}
	return err
}

func (i *kubernetesInstance) ID() string {
	return i.container.HostName
}

func (i *kubernetesInstance) ImageName() string {
	return "kubernetes"
}

func (i *kubernetesInstance) StartupDuration() time.Duration {
	return i.startupDuration
}
