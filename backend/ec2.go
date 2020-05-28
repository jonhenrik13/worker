package backend

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	gocontext "context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/travis-ci/worker/config"
	"github.com/travis-ci/worker/context"
	"github.com/travis-ci/worker/image"
	"github.com/travis-ci/worker/ssh"
)

var (
	defaultEC2SSHDialTimeout    = 5 * time.Second
	defaultEC2ImageSelectorType = "env"
	defaultEC2SSHUserName       = "travis"
	defaultEC2ExecCmd           = "bash ~/build.sh"
	defaultEC2SubnetID          = ""
	defaultEC2InstanceType      = "t2.micro"
	defaultEC2Image             = "ami-02790d1ebf3b5181d"
	defaultEC2SecurityGroupIDs  = "default"
	defaultEC2EBSOptimized      = false
	defaultEC2DiskSize          = int64(8)
	defaultEC2UploadRetries     = uint64(120)
	defaultEC2UploadRetrySleep  = 1 * time.Second
	defaultEC2Region            = "eu-west-1"
	defaultEC2PreProvisionPool  = int64(0)
)

var (
	ec2StartupScript = template.Must(template.New("ec2-startup").Parse(`#!/usr/bin/env bash

cat > ~travis/.ssh/authorized_keys <<EOF
{{ .SSHPubKey }}
EOF
chown -R travis:travis ~travis/.ssh/

{{ .UserData }}
`))
)

type ec2StartupScriptData struct {
	SSHPubKey string
	UserData  string
}

func init() {
	Register("ec2", "EC2", map[string]string{
		"IMAGE_MAP":                "Map of which image to use for which language",
		"AWS_ACCESS_KEY_ID":        "AWS Access Key ID",
		"AWS_SECRET_ACCESS_KEY":    "AWS Secret Access Key",
		"REGION":                   "Which region to run workers in",  // Should be autodetected when running on EC2 instances?
		"INSTANCE_TYPE":            "Instance type to use for builds", // t2 and t3 are burstable
		"SUBNET_ID":                "Subnet ID to launch instances into",
		"EBS_OPTIMIZED":            "Whether or not to use EBS-optimized instances (Default: false)",
		"USER_DATA":                "User data, needs to be URL safe base64 encoded format (RFC 4648)",
		"CPU_CREDIT_SPECIFICATION": "standard|unlimited (for faster boots)",
		"TAGS":                     "Tags, how to deal with key value?",
		"DISK_SIZE":                fmt.Sprintf("Disk size in GB (default %d)", defaultEC2DiskSize),
		"SSH_DIAL_TIMEOUT":         fmt.Sprintf("connection timeout for ssh connections (default %v)", defaultEC2SSHDialTimeout),
		"UPLOAD_RETRIES":           fmt.Sprintf("number of times to attempt to upload script before erroring (default %d)", defaultEC2UploadRetries),
		"UPLOAD_RETRY_SLEEP":       fmt.Sprintf("sleep interval between script upload attempts (default %v)", defaultEC2UploadRetrySleep),
		"SECURITY_GROUPS":          "Security groups to assign",
		"PUBLIC_IP":                "boot job instances with a public ip, disable this for NAT (default true)",
		"PUBLIC_IP_CONNECT":        "connect to the public ip of the instance instead of the internal, only takes effect if PUBLIC_IP is true (default true)",
		"KEY_NAME":                 "Key name to use for the admin user, this is in case you need login access to instances. The travis user has a auto generated key.",
		"IMAGE_ALIASES":            "comma-delimited strings used as stable names for images, used only when image selector type is \"env\"",
		"IMAGE_DEFAULT":            "default image name to use when none found",
		"IMAGE_SELECTOR_TYPE":      fmt.Sprintf("image selector type (\"env\" or \"api\", default %q)", defaultEC2ImageSelectorType),
		"IMAGE_SELECTOR_URL":       "URL for image selector API, used only when image selector is \"api\"",
		"IMAGE_[ALIAS_]{ALIAS}":    "full name for a given alias given via IMAGE_ALIASES, where the alias form in the key is uppercased and normalized by replacing non-alphanumerics with _",
		"CUSTOM_TAGS":              "Custom tags to set for the EC2 instance. Comma separated list with format key1=value1,key2=value2.....keyN=valueN",
		"PREPROVISION_POOL":        "Number of instances pre-provision as hibernated instances",
		"KMSKEY_ID":                "KMS key id used for encryption of EBS volumes, which is required for hibernation",
	}, newEC2Provider)
}

type ec2Provider struct {
	cfg                *config.ProviderConfig
	execCmd            []string
	imageSelector      image.Selector
	awsSession         *session.Session
	instanceType       string
	defaultImage       string
	securityGroups     []string
	ebsOptimized       bool
	diskSize           int64
	uploadRetries      uint64
	uploadRetrySleep   time.Duration
	sshDialTimeout     time.Duration
	publicIP           bool
	publicIPConnect    bool
	subnetID           string
	keyName            string
	userData           string
	customTags         map[string]string
	preProvisionPool   int64
	kmsKeyID           string
	preProvisionKeyMap map[string]*ec2.CreateKeyPairOutput
}

func newEC2Provider(cfg *config.ProviderConfig) (Provider, error) {

	sshDialTimeout := defaultEC2SSHDialTimeout
	if cfg.IsSet("SSH_DIAL_TIMEOUT") {
		sd, err := time.ParseDuration(cfg.Get("SSH_DIAL_TIMEOUT"))
		if err != nil {
			return nil, err
		}
		sshDialTimeout = sd
	}
	customTags := make(map[string]string, 0)
	if cfg.IsSet("CUSTOM_TAGS") {
		items := strings.Split(cfg.Get("CUSTOM_TAGS"), ",")
		for _, tag := range items {
			item := strings.Split(tag, "=")
			customTags[item[0]] = item[1]
		}
	}

	execCmd := strings.Split(defaultEC2ExecCmd, " ")
	if cfg.IsSet("EXEC_CMD") {
		execCmd = strings.Split(cfg.Get("EXEC_CMD"), " ")
	}

	imageSelectorType := defaultEC2ImageSelectorType
	if cfg.IsSet("IMAGE_SELECTOR_TYPE") {
		imageSelectorType = cfg.Get("IMAGE_SELECTOR_TYPE")
	}

	if imageSelectorType != "env" && imageSelectorType != "api" {
		return nil, fmt.Errorf("invalid image selector type %q", imageSelectorType)
	}

	imageSelector, err := buildEC2ImageSelector(imageSelectorType, cfg)
	if err != nil {
		return nil, err
	}

	awsRegion := defaultEC2Region
	if cfg.IsSet("REGION") {
		awsRegion = cfg.Get("REGION")
	}

	awsConfig := &aws.Config{
		Region:     aws.String(awsRegion),
		MaxRetries: aws.Int(8),
	}

	if cfg.IsSet("AWS_ACCESS_KEY_ID") && cfg.IsSet("AWS_SECRET_ACCESS_KEY") {
		staticCreds := credentials.NewStaticCredentials(
			cfg.Get("AWS_ACCESS_KEY_ID"),
			cfg.Get("AWS_SECRET_ACCESS_KEY"),
			"",
		)
		if _, err = staticCreds.Get(); err != credentials.ErrStaticCredentialsEmpty {
			awsConfig.WithCredentials(staticCreds)
		}

		if err != nil {
			return nil, err
		}
	}

	opts := session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *awsConfig,
	}

	awsSession, err := session.NewSessionWithOptions(opts)

	if err != nil {
		return nil, err
	}

	instanceType := defaultEC2InstanceType

	if cfg.IsSet("INSTANCE_TYPE") {
		instanceType = cfg.Get("INSTANCE_TYPE")
	}

	subnetID := ""
	if cfg.IsSet("SUBNET_ID") {
		subnetID = cfg.Get("SUBNET_ID")
	}

	defaultImage := ""
	if cfg.IsSet("IMAGE_DEFAULT") {
		defaultImage = cfg.Get("IMAGE_DEFAULT")
	}

	userData := ""
	if cfg.IsSet("USER_DATA") {
		var userDataBytes []byte
		userDataBytes, err = base64.RawURLEncoding.DecodeString(cfg.Get("USER_DATA"))
		if err != nil {
			return nil, err
		}
		userData = string(userDataBytes)
	}

	securityGroups := strings.Split(defaultEC2SecurityGroupIDs, ",")
	if cfg.IsSet("SECURITY_GROUP_IDS") {
		securityGroups = strings.Split(cfg.Get("SECURITY_GROUP_IDS"), ",")
	}

	ebsOptimized := defaultEC2EBSOptimized
	if cfg.IsSet("EBS_OPTIMIZED") {
		ebsOptimized = asBool(cfg.Get("EBS_OPTIMIZED"))
	}

	diskSize := defaultEC2DiskSize
	if cfg.IsSet("DISK_SIZE") {
		diskSize, err = strconv.ParseInt(cfg.Get("DISK_SIZE"), 10, 64)
		if err != nil {
			return nil, err
		}
	}

	uploadRetries := defaultEC2UploadRetries
	if cfg.IsSet("UPLOAD_RETRIES") {
		ur, err := strconv.ParseUint(cfg.Get("UPLOAD_RETRIES"), 10, 64)
		if err != nil {
			return nil, err
		}
		uploadRetries = ur
	}

	uploadRetrySleep := defaultEC2UploadRetrySleep
	if cfg.IsSet("UPLOAD_RETRY_SLEEP") {
		si, err := time.ParseDuration(cfg.Get("UPLOAD_RETRY_SLEEP"))
		if err != nil {
			return nil, err
		}
		uploadRetrySleep = si
	}

	publicIP := true
	if cfg.IsSet("PUBLIC_IP") {
		publicIP = asBool(cfg.Get("PUBLIC_IP"))
	}

	publicIPConnect := true
	if cfg.IsSet("PUBLIC_IP_CONNECT") {
		publicIPConnect = asBool(cfg.Get("PUBLIC_IP_CONNECT"))
	}

	keyName := ""
	if cfg.IsSet("KEY_NAME") {
		keyName = cfg.Get("KEY_NAME")
	}

	preProvisionPool := defaultEC2PreProvisionPool
	if cfg.IsSet("PREPROVISION_POOL") {
		pp, err := strconv.ParseInt(cfg.Get("PREPROVISION_POOL"), 10, 64)
		if err != nil {
			return nil, err
		}
		preProvisionPool = pp
	}

	kmsKeyID := ""

	if cfg.IsSet("KMSKEY_ID") {
		kmsKeyID = cfg.Get("KMSKEY_ID")
	}

	return &ec2Provider{
		cfg:              cfg,
		sshDialTimeout:   sshDialTimeout,
		execCmd:          execCmd,
		imageSelector:    imageSelector,
		awsSession:       awsSession,
		instanceType:     instanceType,
		defaultImage:     defaultImage,
		securityGroups:   securityGroups,
		ebsOptimized:     ebsOptimized,
		diskSize:         diskSize,
		uploadRetries:    uploadRetries,
		uploadRetrySleep: uploadRetrySleep,
		publicIP:         publicIP,
		publicIPConnect:  publicIPConnect,
		subnetID:         subnetID,
		userData:         userData,
		keyName:          keyName,
		customTags:       customTags,
		preProvisionPool: preProvisionPool,
		kmsKeyID:         kmsKeyID,
	}, nil
}

func buildEC2ImageSelector(selectorType string, cfg *config.ProviderConfig) (image.Selector, error) {
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

func (p *ec2Provider) StartWithProgress(ctx gocontext.Context, startAttributes *StartAttributes, progresser Progresser) (Instance, error) {
	return nil, nil
}

func (p *ec2Provider) SupportsProgress() bool {
	return false
}

func (p *ec2Provider) Start(ctx gocontext.Context, startAttributes *StartAttributes) (Instance, error) {
	startBooting := time.Now()

	instance, sshDialer, tmpKeyName, err := p.startInstance(ctx, startAttributes)

	if instance != nil {
		return &ec2Instance{
			provider:     p,
			sshDialer:    sshDialer,
			endBooting:   time.Now(),
			startBooting: startBooting,
			instance:     instance,
			tmpKeyName:   aws.String(tmpKeyName),
		}, nil
	}
	_ = p.deleteKeyPair(tmpKeyName)
	return nil, err
}

func (p *ec2Provider) getLaunchConfig(ctx gocontext.Context, startAttributes *StartAttributes) (*ec2.RunInstancesInput, *ec2.CreateKeyPairOutput, error) {
	logger := context.LoggerFromContext(ctx).WithField("self", "backend/ec2_provider")
	hostName := hostnameFromContext(ctx)

	// Create EC2 service client
	svc := ec2.New(p.awsSession)

	keyPairInput := &ec2.CreateKeyPairInput{
		KeyName: aws.String(fmt.Sprintf("%s-%d", hostName, time.Now().Unix())),
	}

	keyResp, err := svc.CreateKeyPair(keyPairInput)

	if err != nil {
		logger.WithField("err", err).Errorf("Unable to generate keypair %s", *keyPairInput.KeyName)
		return nil, nil, err
	}

	block, _ := pem.Decode([]byte(*keyResp.KeyMaterial))

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		logger.WithField("err", err).Error("Unable to parse private key")
		return nil, nil, err
	}

	publicKey, err := ssh.FormatPublicKey(key.Public())

	if err != nil {
		logger.WithField("err", err).Error(fmt.Sprintf("Unable to format public key for private key %s", *keyResp.KeyName))
		return nil, nil, err
	}

	userDataBuffer := bytes.Buffer{}
	err = ec2StartupScript.Execute(&userDataBuffer, ec2StartupScriptData{
		SSHPubKey: string(publicKey),
		UserData:  p.userData,
	})

	if err != nil {
		return nil, nil, err
	}

	userDataEncoded := base64.StdEncoding.EncodeToString(userDataBuffer.Bytes())

	imageID, err := p.imageSelector.Select(ctx, &image.Params{
		Language: startAttributes.Language,
		Infra:    "ec2",
	})

	if err != nil {
		return nil, nil, err
	}

	if imageID == "default" {
		imageID = p.defaultImage
	}

	securityGroups := []*string{}
	for _, securityGroup := range p.securityGroups {
		securityGroups = append(securityGroups, &securityGroup)
	}

	blockDevice := &ec2.EbsBlockDevice{
		VolumeSize:          aws.Int64(p.diskSize),
		DeleteOnTermination: aws.Bool(true),
	}

	hibernationOptions := &ec2.HibernationOptionsRequest{
		Configured: aws.Bool(false),
	}

	if p.kmsKeyID != "" {
		blockDevice.KmsKeyId = aws.String(p.kmsKeyID)
		blockDevice.Encrypted = aws.Bool(true)
		hibernationOptions.Configured = aws.Bool(true)
	}

	blockDeviceMappings := []*ec2.BlockDeviceMapping{
		&ec2.BlockDeviceMapping{
			DeviceName: aws.String("/dev/sda1"),
			Ebs:        blockDevice,
		},
	}

	keyName := keyResp.KeyName
	if p.keyName != "" {
		keyName = aws.String(p.keyName)
	}

	runOpts := &ec2.RunInstancesInput{
		ImageId:             aws.String(imageID),
		InstanceType:        aws.String(p.instanceType),
		MaxCount:            aws.Int64(1),
		MinCount:            aws.Int64(1),
		KeyName:             keyName,
		EbsOptimized:        aws.Bool(p.ebsOptimized),
		UserData:            aws.String(userDataEncoded),
		BlockDeviceMappings: blockDeviceMappings,
		HibernationOptions:  hibernationOptions,
	}

	regex := regexp.MustCompile("^(t2|t3).*")

	if regex.MatchString(p.instanceType) {
		runOpts.CreditSpecification = &ec2.CreditSpecificationRequest{
			CpuCredits: aws.String("unlimited"), // TODO:
		}
	}

	if p.subnetID != "" && p.publicIP {
		runOpts.NetworkInterfaces = []*ec2.InstanceNetworkInterfaceSpecification{
			{
				DeviceIndex:              aws.Int64(0),
				AssociatePublicIpAddress: &p.publicIP,
				SubnetId:                 aws.String(p.subnetID),
				Groups:                   securityGroups,
				DeleteOnTermination:      aws.Bool(true),
			},
		}
	} else {
		runOpts.SubnetId = aws.String(p.subnetID)
		runOpts.SecurityGroupIds = securityGroups
	}

	return runOpts, keyResp, nil
}

func (p *ec2Provider) getJobTags(ctx gocontext.Context, startAttributes *StartAttributes) []*ec2.Tag {

	hostName := hostnameFromContext(ctx)
	tags := []*ec2.Tag{
		&ec2.Tag{
			Key:   aws.String("travis.hibernation-state"),
			Value: aws.String("unavailable"),
		},
		&ec2.Tag{
			Key:   aws.String("Name"),
			Value: aws.String(hostName),
		},
		&ec2.Tag{
			Key:   aws.String("travis.dist"),
			Value: aws.String(startAttributes.Dist),
		},
	}

	for key, value := range p.customTags {
		tags = append(tags, &ec2.Tag{
			Key:   aws.String(key),
			Value: aws.String(value),
		})
	}

	r, ok := context.RepositoryFromContext(ctx)
	if ok {
		tags = append(tags, &ec2.Tag{
			Key:   aws.String("travis.repo"),
			Value: aws.String(r),
		})

		repo := strings.Split(r, "/")
		tags = append(tags,
			&ec2.Tag{
				Key:   aws.String("travis.github_repo"),
				Value: aws.String(repo[1]),
			},
			&ec2.Tag{
				Key:   aws.String("travis.github_org"),
				Value: aws.String(repo[0]),
			})
	}

	jid, ok := context.JobIDFromContext(ctx)
	if ok {
		tags = append(tags, &ec2.Tag{
			Key:   aws.String("travis.job_id"),
			Value: aws.String(strconv.FormatUint(jid, 10)),
		})
	}

	return tags
}

func (p *ec2Provider) startInstance(ctx gocontext.Context, startAttributes *StartAttributes) (*ec2.Instance, *ssh.AuthDialer, string, error) {
	tags := p.getJobTags(ctx, startAttributes)

	if len(p.preProvisionKeyMap) == 0 {
		runOpts, keyResp, err := p.getLaunchConfig(ctx, startAttributes)

		if err != nil {
			_ = p.deleteKeyPair(*keyResp.KeyName)
			return nil, nil, "", err
		}

		sshDialer, err := ssh.NewDialerWithKeyWithoutPassPhrase([]byte(*keyResp.KeyMaterial))

		if err != nil {
			return nil, nil, "", err
		}

		runOpts.TagSpecifications = []*ec2.TagSpecification{
			&ec2.TagSpecification{
				ResourceType: aws.String("instance"),
				Tags:         tags,
			},
		}
		instance, err := p.startInstanceCold(ctx, runOpts)
		return instance, sshDialer, *keyResp.KeyName, err
	}
	// Get the first key
	var instanceId string
	var keyResp *ec2.CreateKeyPairOutput
	for instanceId, keyResp = range p.preProvisionKeyMap {
		delete(p.preProvisionKeyMap, instanceId)
		break
	}

	sshDialer, err := ssh.NewDialerWithKeyWithoutPassPhrase([]byte(*keyResp.KeyMaterial))
	if err != nil {
		return nil, nil, "", err
	}
	instance, err := p.startInstanceWarm(ctx, instanceId, tags)

	return instance, sshDialer, *keyResp.KeyName, err

}

func (p *ec2Provider) startInstanceHibernate(ctx gocontext.Context, language string) error {

	startAttributes := &StartAttributes{
		Language: language,
	}

	runOpts, keyResp, err := p.getLaunchConfig(ctx, startAttributes)

	if err != nil {
		panic(err)
	}

	tags := []*ec2.Tag{
		&ec2.Tag{
			Key:   aws.String("Name"),
			Value: aws.String(fmt.Sprintf("travis-builder-%s", language)),
		},
		&ec2.Tag{
			Key:   aws.String("travis.hibernation-state"),
			Value: aws.String("provisioning"),
		},
	}

	runOpts.TagSpecifications = []*ec2.TagSpecification{
		&ec2.TagSpecification{
			ResourceType: aws.String("instance"),
			Tags:         tags,
		},
	}

	instance, err := p.startInstanceCold(ctx, runOpts)

	if err != nil {
		p.deleteKeyPair(*keyResp.KeyName)
		panic(err)
	}

	svc := ec2.New(p.awsSession)

	// This can be one api call
	hibernateInput := &ec2.StopInstancesInput{
		InstanceIds: []*string{
			instance.InstanceId,
		},
		Hibernate: aws.Bool(true),
	}

	errCount := 0
	for errCount < 500 {
		hibernateOutput, err := svc.StopInstances(hibernateInput)
		if err == nil {
			fmt.Printf("%+v\n", hibernateOutput)
			break
		}
		errCount++
		if errCount >= 500 {
			return errors.New("Exceeded hibernation limit")
		}
		time.Sleep(500 * time.Millisecond)
	}

	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			instance.InstanceId,
		},
	}
	errCount = 0
	for errCount < 1000 {
		instances, _ := svc.DescribeInstances(describeInstancesInput)

		if instances != nil && instances.Reservations != nil {
			if instances.Reservations[0].Instances != nil {
				instance := instances.Reservations[0].Instances[0]
				if *instance.State.Name == ec2.InstanceStateNameStopped {
					break
				}
			}
		}
		errCount++
	}

	tagInput := &ec2.CreateTagsInput{
		Resources: []*string{
			instance.InstanceId,
		},
		Tags: []*ec2.Tag{
			&ec2.Tag{
				Key:   aws.String("travis.hibernation-state"),
				Value: aws.String("ready"),
			},
		},
	}

	_, err = svc.CreateTags(tagInput)

	p.preProvisionKeyMap[*instance.InstanceId] = keyResp
	fmt.Printf("errCount: %d\n", errCount)
	fmt.Printf("%+v\n", instance)
	fmt.Printf("%+v\n", p.preProvisionKeyMap)
	return nil
}

func (p *ec2Provider) startInstanceWarm(ctx gocontext.Context, instanceId string, tags []*ec2.Tag) (*ec2.Instance, error) {

	svc := ec2.New(p.awsSession)

	tagInput := &ec2.CreateTagsInput{
		Resources: []*string{
			aws.String(instanceId),
		},
		Tags: tags,
	}

	_, err := svc.CreateTags(tagInput)

	startInput := &ec2.StartInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
		},
	}
	_, err = svc.StartInstances(startInput)
	if err != nil {
		return nil, err
	}
	logger := context.LoggerFromContext(ctx).WithField("self", "backend/ec2_provider")
	logger.Info(fmt.Sprintf("Started warm instance %s", instanceId))
	//fmt.Printf("#### HIBERNATED INSTANCE\n")
	//fmt.Printf("%+v\n", output)
	return p.waitForUp(ctx, instanceId)
}

func (p *ec2Provider) waitForUp(ctx gocontext.Context, instanceId string) (*ec2.Instance, error) {

	svc := ec2.New(p.awsSession)

	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
		},
	}

	instanceChan := make(chan *ec2.Instance)

	var lastErr error
	go func() {
		for {
			var errCount uint64
			var instances *ec2.DescribeInstancesOutput

			instances, lastErr = svc.DescribeInstances(describeInstancesInput)
			if instances != nil && instances.Reservations != nil {
				if instances.Reservations[0].Instances != nil {
					instance := instances.Reservations[0].Instances[0]
					address := ""
					if p.publicIPConnect {
						if instance.PublicIpAddress != nil {
							address = *instance.PublicIpAddress
						}
					} else {
						if instance.PrivateIpAddress != nil {
							address = *instance.PrivateIpAddress
						}
					}
					if address != "" {
						_, lastErr = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", address, 22), 1*time.Second)
						if lastErr == nil {
							instanceChan <- instance
							return
						}
					}
				}
			}
			errCount++
			if errCount > p.uploadRetries {
				instanceChan <- nil
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	select {
	case instance := <-instanceChan:
		if instance != nil {
			return instance, nil
		}
		return nil, lastErr
	case <-ctx.Done():
		context.LoggerFromContext(ctx).WithFields(logrus.Fields{
			"err":  lastErr,
			"self": "backend/ec2_instance",
		}).Info("Stopping probing for up instance")
		return nil, ctx.Err()
	}
}

func (p *ec2Provider) startInstanceCold(ctx gocontext.Context, runOpts *ec2.RunInstancesInput) (*ec2.Instance, error) {
	svc := ec2.New(p.awsSession)

	reservation, err := svc.RunInstances(runOpts)

	if err != nil {
		return nil, err
	}

	logger := context.LoggerFromContext(ctx).WithField("self", "backend/ec2_provider")
	logger.Info(fmt.Sprintf("Started cold instance %s", *reservation.Instances[0].InstanceId))

	if err != nil {
		return nil, err
	}
	return p.waitForUp(ctx, *reservation.Instances[0].InstanceId)
}

func (p *ec2Provider) Setup(ctx gocontext.Context) error {
	p.preProvisionKeyMap = make(map[string]*ec2.CreateKeyPairOutput, 0)

	if p.preProvisionPool > 0 {
		//p.startInstanceHibernate(ctx, "default")
		svc := ec2.New(p.awsSession)
		describeInput := &ec2.DescribeInstancesInput{
			Filters: []*ec2.Filter{
				{
					Name:   aws.String("tag:travis.hibernation-state"),
					Values: []*string{aws.String("provisioning"), aws.String("ready")},
				},
				{
					Name: aws.String("instance-state-name"),
					Values: []*string{
						aws.String("pending"),
						aws.String("running"),
						aws.String("shutting-down"),
						aws.String("stopping"),
						aws.String("stopped"),
					},
				},
			},
		}
		go func() {
			for {
				instances, err := svc.DescribeInstances(describeInput)

				noInstances := 0

				if err != nil {
					continue
				}
				for _, res := range instances.Reservations {
					noInstances = noInstances + len(res.Instances)
				}
				if int64(noInstances) < p.preProvisionPool {
					go p.startInstanceHibernate(ctx, "default")
				}

				fmt.Printf("## Number of provisioned instances: %d(ready: %d)\n", noInstances, len(p.preProvisionKeyMap))
				//fmt.Printf("## ERR: %+v\n## INSTANCES%+v\n", err, instances)
				time.Sleep(5000 * time.Millisecond)
			}
		}()
	}

	return nil
}

type ec2Instance struct {
	provider     *ec2Provider
	startBooting time.Time
	endBooting   time.Time
	sshDialer    ssh.Dialer
	instance     *ec2.Instance
	tmpKeyName   *string
}

func (i *ec2Instance) UploadScript(ctx gocontext.Context, script []byte) error {
	defer context.TimeSince(ctx, "boot_poll_ssh", time.Now())
	uploadedChan := make(chan error)
	var lastErr error

	logger := context.LoggerFromContext(ctx).WithField("self", "backend/ec2_instance")

	// Wait for ssh to becom available
	go func() {
		var errCount uint64
		for {
			if ctx.Err() != nil {
				return
			}

			err := i.uploadScriptAttempt(ctx, script)
			if err != nil {
				logger.WithError(err).Debug("upload script attempt errored")
			} else {
				uploadedChan <- nil
				return
			}

			lastErr = err

			errCount++
			if errCount > i.provider.uploadRetries {
				uploadedChan <- err
				return
			}
			time.Sleep(i.provider.uploadRetrySleep)
		}
	}()

	select {
	case err := <-uploadedChan:
		return err
	case <-ctx.Done():
		context.LoggerFromContext(ctx).WithFields(logrus.Fields{
			"err":  lastErr,
			"self": "backend/ec2_instance",
		}).Info("stopping upload retries, error from last attempt")
		return ctx.Err()
	}

	//return i.uploadScriptAttempt(ctx, script)
}

func (i *ec2Instance) waitForSSH(port, timeout int) error {

	host := *i.instance.PrivateIpAddress
	if i.provider.publicIPConnect {
		host = *i.instance.PublicIpAddress
	}

	iter := 0
	for {
		_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 1*time.Second)
		if err == nil {
			break
		}
		iter = iter + 1
		if iter > timeout {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

func (i *ec2Instance) uploadScriptAttempt(ctx gocontext.Context, script []byte) error {
	return i.uploadScriptSCP(ctx, script)
}

func (i *ec2Instance) uploadScriptSCP(ctx gocontext.Context, script []byte) error {
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

func (i *ec2Instance) sshConnection(ctx gocontext.Context) (ssh.Connection, error) {
	ip := *i.instance.PrivateIpAddress
	if i.provider.publicIPConnect {
		ip = *i.instance.PublicIpAddress
	}
	return i.sshDialer.Dial(fmt.Sprintf("%s:22", ip), defaultEC2SSHUserName, i.provider.sshDialTimeout)
}

func (i *ec2Instance) RunScript(ctx gocontext.Context, output io.Writer) (*RunResult, error) {
	return i.runScriptSSH(ctx, output)
}

func (i *ec2Instance) runScriptSSH(ctx gocontext.Context, output io.Writer) (*RunResult, error) {
	conn, err := i.sshConnection(ctx)
	if err != nil {
		return &RunResult{Completed: false}, errors.Wrap(err, "couldn't connect to SSH server")
	}
	defer conn.Close()

	exitStatus, err := conn.RunCommand(strings.Join(i.provider.execCmd, " "), output)

	return &RunResult{Completed: err != nil, ExitCode: exitStatus}, errors.Wrap(err, "error running script")
}

func (p *ec2Provider) deleteKeyPair(keyName string) error {
	svc := ec2.New(p.awsSession)
	deleteKeyPairInput := &ec2.DeleteKeyPairInput{
		KeyName: aws.String(keyName),
	}

	_, err := svc.DeleteKeyPair(deleteKeyPairInput)

	if err != nil {
		return err
	}
	return nil
}

func (i *ec2Instance) Stop(ctx gocontext.Context) error {
	logger := context.LoggerFromContext(ctx).WithField("self", "backend/ec2_provider")

	svc := ec2.New(i.provider.awsSession)

	instanceTerminationInput := &ec2.TerminateInstancesInput{
		InstanceIds: []*string{
			i.instance.InstanceId,
		},
	}

	_, err := svc.TerminateInstances(instanceTerminationInput)

	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Terminated instance %s with hostname %s", *i.instance.InstanceId, *i.instance.PrivateDnsName))

	err = i.provider.deleteKeyPair(*i.tmpKeyName)

	if err != nil {
		return err
	}

	logger.Info(fmt.Sprintf("Deleted keypair %s", *i.tmpKeyName))

	return nil
}

func (i *ec2Instance) DownloadTrace(gocontext.Context) ([]byte, error) {
	return nil, nil
}

func (i *ec2Instance) SupportsProgress() bool {
	return false
}

func (i *ec2Instance) Warmed() bool {
	return false
}

func (i *ec2Instance) ID() string {
	if i.provider.publicIP {
		return *i.instance.PublicDnsName
	}
	return *i.instance.PrivateDnsName
}

func (i *ec2Instance) ImageName() string {
	return "ec2"
}

func (i *ec2Instance) StartupDuration() time.Duration {
	return i.endBooting.Sub(i.startBooting)
}
