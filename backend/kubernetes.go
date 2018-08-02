package backend

import (
	"archive/tar"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	gocontext "context"

	"github.com/pkg/errors"
	"github.com/travis-ci/worker/config"
	"github.com/travis-ci/worker/context"
	"github.com/travis-ci/worker/image"
	"github.com/travis-ci/worker/ssh"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	/*
		appsv1 "k8s.io/api/apps/v1"
		apiv1 "k8s.io/api/core/v1"
		metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
		"k8s.io/client-go/kubernetes"
		"k8s.io/client-go/tools/clientcmd"
		"k8s.io/client-go/util/homedir"
		"k8s.io/client-go/util/retry"
	*/// Uncomment the following line to load the gcp plugin (only required to authenticate against GKE clusters).
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

func init() {
	Register("kubernetes", "Kubernetes", map[string]string{
		"REGISTRY_HOSTNAME": "Docker registry hostname",
		"REGISTRY_EMAIL":    "Email address for docker registry",
		"REGISTRY_LOGIN":    "Username for docker registry",
		"REGISTRY_PASSWORD": "Password for docker registry",
		"NAMESPACE":         "Kubernetes namespace to use for deploys",
		"KUBE_CONFIG":       "Path to kubeconfig file",
	}, newKubernetesProvider)
}

/******** POC SECTION ****/

type kubernetesContainerTmp struct {
	SSHPort  int    `json:"ssh_port"`
	Status   string `json:"status"`
	HostName string `json:"hostname"`
}

var (
	defaultKubernetesScriptLocation    = "/home/jonhenrik/travis-in-kubernetes"
	defaultKubeConfig                  = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	defaultDockerCfgSecretName         = "travis-docker-registry"
	defaultDockerRegistryHostName      = "index.docker.io"
	defaultKubernetesNamespace         = "default"
	defaultKubernetesImageSelectorType = "env"
)

/****** POC SECTION *******/

type kubernetesProvider struct {
	cfg                    *config.ProviderConfig
	clientSet              *kubernetes.Clientset
	restclientConfig       *rest.Config
	sshDialer              ssh.Dialer
	sshDialTimeout         time.Duration
	execCmd                []string
	dockerRegistryHost     string
	dockerRegistryUser     string
	dockerRegistryPassword string
	kubernetesNamespace    string
	imageSelector          image.Selector
}

func newKubernetesProvider(cfg *config.ProviderConfig) (Provider, error) {

	config, err := clientcmd.BuildConfigFromFlags("", defaultKubeConfig)
	if err != nil {
		return nil, err
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err

	}

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

	dockerRegistryHost := defaultDockerRegistryHostName
	if cfg.IsSet("REGISTRY_HOSTNAME") {
		dockerRegistryHost = cfg.Get("REGISTRY_HOSTNAME")
	}

	dockerRegistryUser := ""
	dockerRegistryPassword := ""
	if cfg.IsSet("REGISTRY_LOGIN") && cfg.IsSet("REGISTRY_PASSWORD") {
		if len(strings.TrimSpace(cfg.Get("REGISTRY_LOGIN"))) != 0 &&
			len(strings.TrimSpace(cfg.Get("REGISTRY_PASSWORD"))) != 0 {

			dockerRegistryUser = cfg.Get("REGISTRY_LOGIN")
			dockerRegistryPassword = cfg.Get("REGISTRY_PASSWORD")
		}
	}

	kubernetesNamespace := defaultKubernetesNamespace

	if cfg.IsSet("NAMESPACE") {
		kubernetesNamespace = cfg.Get("NAMESPACE")
	}

	imageSelectorType := defaultKubernetesImageSelectorType
	if cfg.IsSet("IMAGE_SELECTOR_TYPE") {
		imageSelectorType = cfg.Get("IMAGE_SELECTOR_TYPE")
	}

	if imageSelectorType != "env" && imageSelectorType != "api" {
		return nil, fmt.Errorf("invalid image selector type %q", imageSelectorType)
	}

	imageSelector, err := buildKubernetesImageSelector(imageSelectorType, cfg)
	if err != nil {
		return nil, err
	}

	return &kubernetesProvider{
		cfg:                    cfg,
		clientSet:              clientSet,
		restclientConfig:       config,
		sshDialTimeout:         sshDialTimeout,
		sshDialer:              sshDialer,
		execCmd:                execCmd,
		dockerRegistryHost:     dockerRegistryHost,
		dockerRegistryPassword: dockerRegistryPassword,
		dockerRegistryUser:     dockerRegistryUser,
		kubernetesNamespace:    kubernetesNamespace,
		imageSelector:          imageSelector,
	}, nil

}

func buildKubernetesImageSelector(selectorType string, cfg *config.ProviderConfig) (image.Selector, error) {
	switch selectorType {
	case "env":
		return image.NewEnvSelector(cfg)
	case "api":
		baseURL, err := url.Parse(cfg.Get("IMAGE_SELECTOR_URL"))
		if err != nil {
			return nil, err
		}
		return image.NewAPISelector(baseURL), nil
	default:
		return nil, fmt.Errorf("invalid image selector type %q", selectorType)
	}
}

func (p *kubernetesProvider) Start(ctx gocontext.Context, startAttributes *StartAttributes) (Instance, error) {
	var (
		dur time.Duration
		err error
	)

	logger := context.LoggerFromContext(ctx).WithField("self", "backend/kubernetes_provider")

	selectedImageID, err := p.imageSelector.Select(&image.Params{
		Language: startAttributes.Language,
		Infra:    "kubernetes",
	})

	if err != nil {
		logger.WithField("err", err).Error("couldn't select image")
		return nil, err
	}

	fmt.Printf("Image name is: %s\n", selectedImageID)

	hostName := hostnameFromContext(ctx)

	podSpec := &apiv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-kube-api", hostName),
		},
		Spec: apiv1.PodSpec{
			Containers: []apiv1.Container{
				{
					Name:  fmt.Sprintf("%s-kube-api", hostName),
					Image: selectedImageID,
					Ports: []apiv1.ContainerPort{
						{
							Name:          "ssh",
							Protocol:      apiv1.ProtocolTCP,
							ContainerPort: 22,
						},
					},
					Command: []string{"/sbin/init"},
				},
			},
		},
	}

	pod, err := p.clientSet.CoreV1().Pods(p.kubernetesNamespace).Create(podSpec)

	if err != nil {
		return nil, err
	}

	fmt.Printf("Created deployment %q.\n", pod.GetObjectMeta().GetName())

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
		pod:             pod,
		imageName:       selectedImageID,
		container:       &container,
	}, nil
}

func (i *kubernetesInstance) uploadScriptNative(ctx gocontext.Context, script []byte) error {

	reader, writer := io.Pipe()
	defer reader.Close()

	tw := tar.NewWriter(writer)

	go func() error {
		defer writer.Close()
		defer tw.Close()

		now := time.Now()

		err := tw.WriteHeader(&tar.Header{
			Name:       "/home/travis/build.sh",
			Mode:       0755,
			Size:       int64(len(script)),
			AccessTime: now,
			ModTime:    now,
			ChangeTime: now,
		})
		if err != nil {
			return err
		}

		_, err = tw.Write(script)
		return err
	}()

	//cmdArr := []string{"tar", "xf", "-"}
	/*
		destDir := path.Dir(dest.File)
		if len(destDir) > 0 {
			cmdArr = append(cmdArr, "-C", destDir)
		}
	*/
	//https://github.com/AOEpeople/kube-container-exec/blob/master/main.go

	restClient := i.provider.clientSet.CoreV1().RESTClient()
	commands := []string{"tar", "xf", "-"}

	req := restClient.Post().
		Namespace(i.provider.kubernetesNamespace).
		Resource("pods").
		Name(i.pod.Name).
		SubResource("exec").
		Param("container", i.pod.Name).
		Param("stdin", "true").
		Param("stdout", "true").
		Param("stderr", "true")

	for _, command := range commands {
		req.Param("command", command)
	}

	executor, err := remotecommand.NewSPDYExecutor(i.provider.restclientConfig, http.MethodPost, req.URL())
	if err != nil {
		return err
	}

	os.Stdout.Sync()
	os.Stderr.Sync()

	err = executor.Stream(remotecommand.StreamOptions{
		Stdin:             reader,
		Stdout:            os.Stdout,
		Stderr:            os.Stderr,
		Tty:               false,
		TerminalSizeQueue: nil,
	})

	return err
}

func (p *kubernetesProvider) Setup(ctx gocontext.Context) error {

	logger := context.LoggerFromContext(ctx).WithField("self", "backend/kubernetes_provider")
	if p.dockerRegistryUser != "" && p.dockerRegistryPassword != "" {
		secret, err := createDockerRegistrySecret(p.kubernetesNamespace, p.dockerRegistryHost, p.dockerRegistryUser, p.dockerRegistryPassword, "")

		if err != nil {
			logger.WithField("err", err).Error("Unable to manage auth for docker registry")
			return err
		}
		return p.upsertSecret(secret)
	}

	return nil
}

func (p *kubernetesProvider) upsertSecret(secret *apiv1.Secret) error {
	existingSecret, err := p.clientSet.Core().Secrets(p.kubernetesNamespace).Get(defaultDockerCfgSecretName, metav1.GetOptions{})

	if err != nil {
		_, err = p.clientSet.Core().Secrets(p.kubernetesNamespace).Create(secret)
		return err
	}

	if !reflect.DeepEqual(existingSecret.Data, secret.Data) {
		_, err = p.clientSet.Core().Secrets(p.kubernetesNamespace).Update(secret)
	} else {

	}

	return err
}

func createDockerRegistrySecret(namespace, hostname, username, password, email string) (*apiv1.Secret, error) {

	secret := newSecret(apiv1.SecretTypeDockercfg, namespace, defaultDockerCfgSecretName)

	dockerCfg := map[string]map[string]string{
		hostname: {
			"email":    email,
			"username": username,
			"password": password,
			"auth":     base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password))),
		},
	}

	dockerCfgContent, err := json.Marshal(dockerCfg)

	if err != nil {
		return nil, err
	}

	secret.Data = map[string][]byte{
		apiv1.DockerConfigKey: dockerCfgContent,
	}

	return secret, nil
}

func newSecret(secretType apiv1.SecretType, namespace, name string) *apiv1.Secret {
	return &apiv1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Type: secretType,
	}
}

type kubernetesInstance struct {
	provider        *kubernetesProvider
	pod             *apiv1.Pod
	imageName       string
	container       *kubernetesContainerTmp
	startupDuration time.Duration
}

func (i *kubernetesInstance) UploadScript(ctx gocontext.Context, script []byte) error {
	i.uploadScriptNative(ctx, script)
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

	deletePolicy := metav1.DeletePropagationForeground

	err = i.provider.clientSet.CoreV1().Pods(i.provider.kubernetesNamespace).Delete(i.pod.Name, &metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})

	return err
}

func (i *kubernetesInstance) ID() string {
	return i.container.HostName
}

func (i *kubernetesInstance) ImageName() string {
	return i.imageName
}

func (i *kubernetesInstance) StartupDuration() time.Duration {
	return i.startupDuration
}

/*
func getAvailablePort(
	for {
    conn, err := net.DialTimeout("tcp", net.JoinHostPort("", port), timeout)
    if conn != nil {
        conn.Close()
        break
    }
})
*/
