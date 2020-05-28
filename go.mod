module github.com/travis-ci/worker

go 1.13

require (
	cloud.google.com/go v0.34.0
	contrib.go.opencensus.io/exporter/stackdriver v0.6.1-0.20180928162215-857ff689ec3b
	github.com/Azure/go-ntlmssp v0.0.0-20180810175552-4a21cbd618b4
	github.com/BurntSushi/toml v0.3.1
	github.com/ChrisTrenkamp/goxpath v0.0.0-20170922090931-c385f95c6022
	github.com/Jeffail/tunny v0.0.0-20180304204616-59cfa8fcb19f
	github.com/Microsoft/go-winio v0.4.11
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/Shopify/sarama v1.19.1-0.20181003071306-f21e149e5948
	github.com/aws/aws-sdk-go v1.31.5
	github.com/beorn7/perks v0.0.0-20180321164747-3a771d992973
	github.com/bitly/go-simplejson v0.5.1-0.20171023175154-0c965951289c
	github.com/bradfitz/gomemcache v0.0.0-20190329173943-551aad21a668
	github.com/cenk/backoff v2.1.0+incompatible
	github.com/certifi/gocertifi v0.0.0-20180905225744-ee1a9a0726d2
	github.com/client9/misspell v0.3.4 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v17.12.0-ce-rc1.0.20181012164311-10ebe6381e1f+incompatible
	github.com/docker/go-connections v0.4.1-0.20180821093606-97c2040d34df
	github.com/docker/go-units v0.3.3
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c
	github.com/dustin/go-humanize v1.0.0
	github.com/dylanmei/iso8601 v0.1.0
	github.com/eapache/go-resiliency v1.1.0
	github.com/eapache/go-xerial-snappy v0.0.0-20180814174437-776d5712da21
	github.com/eapache/queue v1.1.1-0.20180227141424-093482f3f8ce
	github.com/evanphx/json-patch v4.2.0+incompatible
	github.com/garyburd/redigo v1.6.1-Deprecated-please-use-github-dot-com-gomodule-redigo
	github.com/getsentry/raven-go v0.0.0-20180903072508-084a9de9eb03
	github.com/go-ini/ini v1.56.0 // indirect
	github.com/go-logr/logr v0.1.0
	github.com/gogo/protobuf v1.2.2-0.20190415061611-67e450fba694
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/lint v0.0.0-20180702182130-06c8688daad7 // indirect
	github.com/golang/mock v1.1.2-0.20180820161358-600781dde9cc
	github.com/golang/protobuf v1.2.1-0.20181005181728-ddf22928ea3c
	github.com/golang/snappy v0.0.1
	github.com/gomodule/redigo v2.0.1-0.20190322064113-39e2c31b7ca3+incompatible
	github.com/google/btree v1.0.1-0.20190326150332-20236160a414
	github.com/google/go-cmp v0.2.1-0.20180911194814-875f8df8b796
	github.com/google/gofuzz v1.0.0
	github.com/google/uuid v1.1.0
	github.com/googleapis/gax-go v2.0.1-0.20180702194919-1ef592c90f47+incompatible
	github.com/googleapis/gnostic v0.2.3-0.20190313182044-909070f02b66
	github.com/gorilla/context v1.1.2-0.20181012153548-51ce91d2eadd
	github.com/gorilla/mux v1.6.3-0.20181012153151-deb579d6e030
	github.com/gorilla/websocket v1.4.1-0.20190306004257-0ec3d1bd7fe5
	github.com/gregjones/httpcache v0.0.0-20190212212710-3befbb6ad0cc
	github.com/hashicorp/go-cleanhttp v0.5.0
	github.com/hpcloud/tail v1.0.1-0.20180514194441-a1dbeea552b7
	github.com/imdario/mergo v0.3.8-0.20190415133143-5ef87b449ca7
	github.com/jessevdk/go-flags v1.4.1-0.20181221193153-c0795c8afcf4
	github.com/json-iterator/go v1.1.6
	github.com/jtacoma/uritemplates v1.0.0
	github.com/kr/fs v0.1.0
	github.com/masterzen/azure-sdk-for-go v3.2.0-beta.0.20161014135628-ee4f0065d00c+incompatible
	github.com/masterzen/simplexml v0.0.0-20160608183007-4572e39b1ab9
	github.com/masterzen/winrm v0.0.0-20180702085143-58761a495ca4
	github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/mihasya/go-metrics-librato v0.0.0-20171227215858-c2a1624c7a80
	github.com/mitchellh/mapstructure v1.1.2
	github.com/mitchellh/multistep v0.0.0-20170316185339-391576a156a5
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 v1.0.1
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.1-0.20190417161816-abeb93df1e82
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/openzipkin/zipkin-go v0.1.2
	github.com/packer-community/winrmcp v0.0.0-20180921211025-c76d91c1e7db
	github.com/pborman/uuid v1.2.0
	github.com/petar/GoLLRB v0.0.0-20130427215148-53be0d36a84c
	github.com/peterbourgon/diskv v2.0.2-0.20180312054125-0646ccaebea1+incompatible
	github.com/pierrec/lz4 v1.0.2-0.20181005164709-635575b42742
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.2.2-0.20180809112205-057bc52a47ec
	github.com/pkg/sftp v1.8.3
	github.com/prometheus/client_golang v0.9.0-pre1.0.20181010161331-7866eead363e
	github.com/prometheus/client_model v0.0.0-20180712105110-5c3871d89910
	github.com/prometheus/common v0.0.0-20180801064454-c7de2306084e
	github.com/prometheus/procfs v0.0.0-20181005140218-185b4288413d
	github.com/rackspace/gophercloud v1.0.1-0.20161013232434-e00690e87603
	github.com/rcrowley/go-metrics v0.0.0-20180503174638-e2704e165165
	github.com/sirupsen/logrus v1.1.2-0.20181010200618-458213699411
	github.com/spf13/pflag v1.0.4-0.20181223182923-24fa6976df40
	github.com/stathat/go v1.0.0
	github.com/streadway/amqp v0.0.0-20180806233856-70e15c650864
	github.com/stretchr/testify v1.5.1
	github.com/syndtr/goleveldb v1.0.1-0.20190318030020-c3a204f8e965
	go.opencensus.io v0.17.1-0.20181009160601-ae36bd8445ff
	go4.org v0.0.0-20180809161055-417644f6feb5
	golang.org/x/build v0.0.0-20181012000102-a5d307330404
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2
	golang.org/x/lint v0.0.0-20180702182130-06c8688daad7 // indirect
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.org/x/oauth2 v0.0.0-20190402181905-9f3314589c9a
	golang.org/x/sync v0.0.0-20181221193216-37e7f081c4d4
	golang.org/x/sys v0.0.0-20190312061237-fead79001313
	golang.org/x/text v0.3.1-0.20181227161524-e6919f6577db
	golang.org/x/time v0.0.0-20180412165947-fbb02b2291d2
	google.golang.org/api v0.0.0-20181012000736-72df7e5ac770
	google.golang.org/appengine v1.5.0
	google.golang.org/genproto v0.0.0-20181004005441-af9cb2a35e7f
	google.golang.org/grpc v1.14.0
	gopkg.in/airbrake/gobrake.v2 v2.0.9
	gopkg.in/gemnasium/logrus-airbrake-hook.v2 v2.1.2
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/urfave/cli.v1 v1.20.0
	gopkg.in/yaml.v2 v2.2.2
	honnef.co/go/tools v0.0.0-20180728063816-88497007e858 // indirect
	k8s.io/api v0.0.0-20190424052529-7fd04442e4f5
	k8s.io/apimachinery v0.0.0-20190424052434-11f1676e3da4
	k8s.io/client-go v0.0.0-20190424052710-157c3d454138
	k8s.io/klog v0.3.0
	k8s.io/kube-openapi v0.0.0-20190418160015-6b3d3b2d5666
	k8s.io/utils v0.0.0-20190308190857-21c4ce38f2a7
	sigs.k8s.io/yaml v1.1.1-0.20190204175104-199c9c29c4e4
)
