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
	"path/filepath"
	"reflect"
	"strings"
	"time"

	gocontext "context"

	"github.com/pkg/errors"
	"github.com/travis-ci/worker/config"
	"github.com/travis-ci/worker/context"
	"github.com/travis-ci/worker/image"
	"github.com/travis-ci/worker/metrics"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	scheme "k8s.io/client-go/kubernetes/scheme"
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

const imageSelectAPI = "api"
const imageSelectEnv = "env"

var (
	defaultKubeConfig                  = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	defaultDockerCfgSecretName         = "travis-docker-registry"
	defaultDockerRegistryHostName      = "index.docker.io"
	defaultKubernetesNamespace         = "default"
	defaultKubernetesImageSelectorType = imageSelectEnv
	defaultKubernetesPodTermGrace      = 1
	defaultKubernetesImage             = "travisci/ci-garnet:packer-1515445631-7dfb2e1"
)

func init() {
	Register("kubernetes", "Kubernetes", map[string]string{
		"REGISTRY_HOSTNAME":     "Docker registry hostname",
		"REGISTRY_EMAIL":        "Email address for docker registry",
		"REGISTRY_LOGIN":        "Username for docker registry",
		"REGISTRY_PASSWORD":     "Password for docker registry",
		"NAMESPACE":             "Kubernetes namespace to use for deploys",
		"KUBECONFIG_PATH":       "Path to kubeconfig file",
		"REQUESTS_CPU":          "How much CPU resources containers in the pod should request",
		"REQUESTS_MEM":          "How much memory containers in the pod should request",
		"LIMITS_CPU":            "How much CPU resources containers in the pod should be limited to",
		"LIMITS_MEM":            "How much memory containers in the pod should be limited to",
		"IMAGE_ALIASES":         "comma-delimited strings used as stable names for images, used only when image selector type is \"env\"",
		"IMAGE_DEFAULT":         "default image name to use when none found",
		"IMAGE_SELECTOR_TYPE":   fmt.Sprintf("image selector type (\"env\" or \"api\", default %q)", defaultKubernetesImageSelectorType),
		"IMAGE_SELECTOR_URL":    "URL for image selector API, used only when image selector is \"api\"",
		"IMAGE_[ALIAS_]{ALIAS}": "full name for a given alias given via IMAGE_ALIASES, where the alias form in the key is uppercased and normalized by replacing non-alphanumerics with _",
	}, newKubernetesProvider)
}

type kubernetesProvider struct {
	clientSet        *kubernetes.Clientset
	restclientConfig *rest.Config
	//	execCmd                []string
	dockerRegistryHost     string
	dockerRegistryUser     string
	dockerRegistryPassword string
	kubernetesNamespace    string
	limitsCPU              string
	limitsMem              string
	requestsCPU            string
	requestsMem            string
	defaultImage           string
	imageSelector          image.Selector
}

func newKubernetesProvider(cfg *config.ProviderConfig) (Provider, error) {

	kubeConfigPath := defaultKubeConfig
	if cfg.IsSet("KUBECONFIG_PATH") {
		kubeConfigPath = cfg.Get("KUBECONFIG_PATH")
	}

	if _, err := os.Stat(kubeConfigPath); err != nil {
		return nil, err
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, err
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	/*
		execCmd := strings.Split(defaultExecCmd, " ")
		if cfg.IsSet("EXEC_CMD") {
			execCmd = strings.Split(cfg.Get("EXEC_CMD"), " ")
		}
	*/

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

	if imageSelectorType != imageSelectEnv && imageSelectorType != imageSelectAPI {
		return nil, fmt.Errorf("invalid image selector type %q", imageSelectorType)
	}

	imageSelector, err := buildKubernetesImageSelector(imageSelectorType, cfg)
	if err != nil {
		return nil, err
	}

	limitsCPU := "0"
	if cfg.IsSet("LIMITS_CPU") {
		limitsCPU = cfg.Get("LIMITS_CPU")
	}

	limitsMem := "0"
	if cfg.IsSet("LIMITS_MEM") {
		limitsMem = cfg.Get("LIMITS_MEM")
	}

	requestsCPU := "0"
	if cfg.IsSet("REQUESTS_CPU") {
		requestsCPU = cfg.Get("REQUESTS_CPU")
	}

	requestsMem := "0"
	if cfg.IsSet("REQUESTS_MEM") {
		requestsMem = cfg.Get("REQUESTS_MEM")
	}

	defaultImage := defaultKubernetesImage
	if cfg.IsSet("IMAGE_DEFAULT") {
		defaultImage = cfg.Get("IMAGE_DEFAULT")
	}

	return &kubernetesProvider{
		clientSet:        clientSet,
		restclientConfig: config,
		//		execCmd:                execCmd,
		dockerRegistryHost:     dockerRegistryHost,
		dockerRegistryPassword: dockerRegistryPassword,
		dockerRegistryUser:     dockerRegistryUser,
		kubernetesNamespace:    kubernetesNamespace,
		imageSelector:          imageSelector,
		limitsMem:              limitsMem,
		limitsCPU:              limitsCPU,
		requestsMem:            requestsMem,
		requestsCPU:            requestsCPU,
		defaultImage:           defaultImage,
	}, nil
}

func buildKubernetesImageSelector(selectorType string, cfg *config.ProviderConfig) (image.Selector, error) {
	switch selectorType {
	case imageSelectEnv:
		return image.NewEnvSelector(cfg)
	case imageSelectAPI:
		baseURL, err := url.Parse(cfg.Get("IMAGE_SELECTOR_URL"))
		if err != nil {
			return nil, err
		}
		return image.NewAPISelector(baseURL), nil
	default:
		return nil, fmt.Errorf("invalid image selector type %q", selectorType)
	}
}

func (p *kubernetesProvider) StartWithProgress(ctx gocontext.Context, startAttributes *StartAttributes, progresser Progresser) (Instance, error) {
	return nil, nil
}

func (p *kubernetesProvider) SupportsProgress() bool {
	return false
}

func (i *kubernetesInstance) SupportsProgress() bool {
	return false
}

func (i *kubernetesInstance) Warmed() bool {
	return false
}

func (p *kubernetesProvider) Start(ctx gocontext.Context, startAttributes *StartAttributes) (Instance, error) {
	var (
		dur time.Duration
		err error
	)

	logger := context.LoggerFromContext(ctx).WithField("self", "backend/kubernetes_provider")

	selectedImageID, err := p.imageSelector.Select(ctx, &image.Params{
		Language: startAttributes.Language,
		Infra:    "kubernetes",
	})

	if err != nil {
		logger.WithField("err", err).Error("couldn't select image")
		return nil, err
	}

	if selectedImageID == "default" {
		selectedImageID = p.defaultImage
	}

	hostName := hostnameFromContext(ctx)

	// TODO: Need to remove existing pods with the same name and wait for termination

	podSpec := &apiv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s", hostName),
		},
		Spec: apiv1.PodSpec{
			Containers: []apiv1.Container{
				{
					Name:    fmt.Sprintf("%s", hostName),
					Image:   selectedImageID,
					Command: []string{"/sbin/init"},
					TTY:     true,
					Resources: apiv1.ResourceRequirements{
						Limits: apiv1.ResourceList{
							apiv1.ResourceCPU:    resource.MustParse(p.limitsCPU),
							apiv1.ResourceMemory: resource.MustParse(p.limitsMem),
						},
						Requests: apiv1.ResourceList{
							apiv1.ResourceCPU:    resource.MustParse(p.requestsCPU),
							apiv1.ResourceMemory: resource.MustParse(p.requestsMem),
						},
					},
				},
			},
		},
	}

	if p.dockerRegistryUser != "" && p.dockerRegistryPassword != "" {
		podSpec.Spec.ImagePullSecrets = []apiv1.LocalObjectReference{
			apiv1.LocalObjectReference{
				Name: defaultDockerCfgSecretName,
			},
		}
	}

	startBooting := time.Now()

	pod, err := p.clientSet.CoreV1().Pods(p.kubernetesNamespace).Create(podSpec)

	if err != nil {
		return nil, err
	}

	podReady := make(chan apiv1.PodStatus)
	errChan := make(chan error)

	go func(podName string) {
		for {
			runningPod, err := p.clientSet.CoreV1().Pods(p.kubernetesNamespace).Get(podName, metav1.GetOptions{})
			if err != nil {
				errChan <- err
				return
			}
			if runningPod.Status.Phase == "Running" {
				podReady <- runningPod.Status
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}(pod.Name)

	select {
	case <-podReady:
		metrics.TimeSince("worker.vm.provider.kubernetes.boot", startBooting)
		return &kubernetesInstance{
			provider:        p,
			startupDuration: dur,
			pod:             pod,
			imageName:       selectedImageID,
			startBooting:    startBooting,
			endBooting:      time.Now(),
		}, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		if ctx.Err() == gocontext.DeadlineExceeded {
			metrics.Mark("worker.vm.provider.kubernetes.boot.timeout")
		}
		return nil, ctx.Err()
	}
}

func (p *kubernetesProvider) Setup(ctx gocontext.Context) error {

	logger := context.LoggerFromContext(ctx).WithField("self", "backend/kubernetes_provider")
	if p.dockerRegistryUser != "" && p.dockerRegistryPassword != "" {
		secret, err := createDockerRegistrySecret(p.kubernetesNamespace, p.dockerRegistryHost, p.dockerRegistryUser, p.dockerRegistryPassword, p.dockerRegistryUser)

		if err != nil {
			logger.WithField("err", err).Error("Unable to manage auth for docker registry")
			return err
		}
		return p.upsertSecret(secret)
	}

	return nil
}

func (p *kubernetesProvider) upsertSecret(secret *apiv1.Secret) error {
	existingSecret, err := p.clientSet.CoreV1().Secrets(p.kubernetesNamespace).Get(defaultDockerCfgSecretName, metav1.GetOptions{})

	if err != nil {
		_, err = p.clientSet.CoreV1().Secrets(p.kubernetesNamespace).Create(secret)
		return err
	}

	if !reflect.DeepEqual(existingSecret.Data, secret.Data) {
		_, err = p.clientSet.CoreV1().Secrets(p.kubernetesNamespace).Update(secret)
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
	startupDuration time.Duration
	startBooting    time.Time
	endBooting      time.Time
}

func (i *kubernetesInstance) UploadScript(ctx gocontext.Context, script []byte) error {
	return i.uploadScriptNative(ctx, script)
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
	/*
		file, _ := os.Create("/tmp/build.sh")
		defer file.Close()
		_, _ = file.Write(script)
		file.Sync()
		file.Close()
	*/
	command := []string{"tar", "xf", "-"}
	return i.execute(command, reader, nil, nil)
}

func (i *kubernetesInstance) RunScript(ctx gocontext.Context, output io.Writer) (*RunResult, error) {
	return i.runScriptExec(ctx, output)
}

func (i *kubernetesInstance) runScriptExec(ctx gocontext.Context, output io.Writer) (*RunResult, error) {
	command := []string{"su", "-c", "/home/travis/build.sh", "-", "travis"}
	err := i.execute(command, nil, output, output)

	exitCode := int32(0)
	if err != nil {
		exitCode = int32(1)
	}

	return &RunResult{Completed: err != nil, ExitCode: exitCode}, errors.Wrap(err, "error running script")
}

func (i *kubernetesInstance) execute(command []string, stdin io.Reader, stdout, stderr io.Writer) error {

	restClient := i.provider.clientSet.CoreV1().RESTClient()

	req := restClient.Post().
		Namespace(i.provider.kubernetesNamespace).
		Resource("pods").
		Name(i.pod.Name).
		SubResource("exec")

	req.VersionedParams(&apiv1.PodExecOptions{
		Stdin:     stdin != nil,
		Container: i.pod.Name,
		Stdout:    stdout != nil,
		Stderr:    stderr != nil,
		Command:   command,
	}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(i.provider.restclientConfig, http.MethodPost, req.URL())
	if err != nil {
		return err
	}

	err = executor.Stream(remotecommand.StreamOptions{
		Stdin:             stdin,
		Stdout:            stdout,
		Stderr:            stderr,
		Tty:               false,
		TerminalSizeQueue: nil,
	})

	return err
}

func (i *kubernetesInstance) Stop(ctx gocontext.Context) error {
	logger := context.LoggerFromContext(ctx).WithField("self", "backend/kubernetes_provider")

	podTerminated := make(chan error)

	go func(podName string) {
		for {
			err := i.provider.deletePod(i.pod.Name)
			if err == nil {
				podTerminated <- err
				return
			}
			logger.WithField("err", err).Warn("Unable to communicate with the kubernetes api")
			time.Sleep(1000 * time.Millisecond)
		}
	}(i.pod.Name)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-podTerminated:
		return err

	}
}

func (i *kubernetesInstance) DownloadTrace(ctx gocontext.Context) ([]byte, error) {
	return nil, nil
}

func (p *kubernetesProvider) deletePod(hostname string) error {
	deletePolicy := metav1.DeletePropagationForeground
	gracePeriod := int64(defaultKubernetesPodTermGrace)

	err := p.clientSet.CoreV1().Pods(p.kubernetesNamespace).Delete(hostname, &metav1.DeleteOptions{
		PropagationPolicy:  &deletePolicy,
		GracePeriodSeconds: &gracePeriod,
	})
	return err
}

func (i *kubernetesInstance) ID() string {
	return i.pod.Name
}

func (i *kubernetesInstance) ImageName() string {
	return i.imageName
}

func (i *kubernetesInstance) StartupDuration() time.Duration {
	return i.endBooting.Sub(i.startBooting)
}
