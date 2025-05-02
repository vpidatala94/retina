package retina

import (
	"time"

	"github.com/microsoft/retina/test/e2e/common"
	"github.com/microsoft/retina/test/e2e/framework/azure"
	"github.com/microsoft/retina/test/e2e/framework/generic"
	"github.com/microsoft/retina/test/e2e/framework/kubernetes"
	"github.com/microsoft/retina/test/e2e/framework/types"
	"github.com/microsoft/retina/test/e2e/hubble"
	"github.com/microsoft/retina/test/e2e/scenarios/dns"
	"github.com/microsoft/retina/test/e2e/scenarios/drop"
	"github.com/microsoft/retina/test/e2e/scenarios/latency"
	tcp "github.com/microsoft/retina/test/e2e/scenarios/tcp"
	"github.com/microsoft/retina/test/e2e/scenarios/windows"
)

func CreateTestInfra(subID, rg, clusterName, location, kubeConfigFilePath string, createInfra bool) *types.Job {
	job := types.NewJob("Create e2e test infrastructure")
	if createInfra {
		job.AddStep(&azure.CreateResourceGroup{
			SubscriptionID:    subID,
			ResourceGroupName: rg,
			Location:          location,
		}, nil)

		job.AddStep(&azure.CreateVNet{
			VnetName:         "testvnet",
			VnetAddressSpace: "10.0.0.0/9",
		}, nil)

		job.AddStep(&azure.CreateSubnet{
			SubnetName:         "testsubnet",
			SubnetAddressSpace: "10.0.0.0/12",
		}, nil)

		job.AddStep(&azure.CreateNPMCluster{
			ClusterName:  clusterName,
			PodCidr:      "10.128.0.0/9",
			DNSServiceIP: "192.168.0.10",
			ServiceCidr:  "192.168.0.0/28",
		}, nil)

		job.AddStep(&azure.GetAKSKubeConfig{
			KubeConfigFilePath: kubeConfigFilePath,
		}, nil)
	} else {
		job.AddStep(&azure.GetAKSKubeConfig{
			KubeConfigFilePath: kubeConfigFilePath,
			ClusterName:        "runner-e2e-netobs-1746176142",
			SubscriptionID:     subID,
			ResourceGroupName:  "runner-e2e-netobs-1746176142",
			Location:           location,
		}, nil)
	}
	return job
}

func DeleteTestInfra(subID, rg, location string, deleteInfra bool) *types.Job {
	job := types.NewJob("Delete e2e test infrastructure")

	if deleteInfra {
		job.AddStep(&azure.DeleteResourceGroup{
			SubscriptionID:    subID,
			ResourceGroupName: rg,
			Location:          location,
		}, nil)
	}
	if deleteInfra {
		job.AddStep(&azure.DeleteResourceGroup{
			SubscriptionID:    subID,
			ResourceGroupName: rg,
			Location:          location,
		}, nil)
	}

	return job
}

func InstallRetina(kubeConfigFilePath, chartPath string, enableHeartBeat bool) *types.Job {
	job := types.NewJob("Install and test Retina with basic metrics")

	job.AddStep(&kubernetes.InstallHelmChart{
		Namespace:          common.KubeSystemNamespace,
		ReleaseName:        "retina",
		KubeConfigFilePath: kubeConfigFilePath,
		ChartPath:          chartPath,
		TagEnv:             generic.DefaultTagEnv,
		EnableHeartbeat:    enableHeartBeat,
	}, nil)

	return job
}

func InstallAndTestRetinaBasicMetrics(kubeConfigFilePath, chartPath string, testPodNamespace string) *types.Job {
	job := types.NewJob("Install and test Retina with basic metrics")

	job.AddStep(&kubernetes.InstallHelmChart{
		Namespace:          common.KubeSystemNamespace,
		ReleaseName:        "retina",
		KubeConfigFilePath: kubeConfigFilePath,
		ChartPath:          chartPath,
		TagEnv:             generic.DefaultTagEnv,
	}, nil)

	dnsScenarios := []struct {
		name string
		req  *dns.RequestValidationParams
		resp *dns.ResponseValidationParams
	}{
		{
			name: "Validate basic DNS request and response metrics for a valid domain",
			req: &dns.RequestValidationParams{
				NumResponse: "0",
				Query:       "kubernetes.default.svc.cluster.local.",
				QueryType:   "A",
				Command:     "nslookup kubernetes.default",
				ExpectError: false,
			},
			resp: &dns.ResponseValidationParams{
				NumResponse: "1",
				Query:       "kubernetes.default.svc.cluster.local.",
				QueryType:   "A",
				ReturnCode:  "No Error",
				Response:    "10.0.0.1",
			},
		},
		{
			name: "Validate basic DNS request and response metrics for a non-existent domain",
			req: &dns.RequestValidationParams{
				NumResponse: "0",
				Query:       "some.non.existent.domain.",
				QueryType:   "A",
				Command:     "nslookup some.non.existent.domain",
				ExpectError: true,
			},
			resp: &dns.ResponseValidationParams{
				NumResponse: "0",
				Query:       "some.non.existent.domain.",
				QueryType:   "A",
				Response:    dns.EmptyResponse, // hacky way to bypass the framework for now
				ReturnCode:  "Non-Existent Domain",
			},
		},
	}

	for _, arch := range common.Architectures {
		job.AddScenario(drop.ValidateDropMetric(testPodNamespace, arch))
		job.AddScenario(tcp.ValidateTCPMetrics(testPodNamespace, arch))

		for _, scenario := range dnsScenarios {
			name := scenario.name + " - Arch: " + arch
			job.AddScenario(dns.ValidateBasicDNSMetrics(name, scenario.req, scenario.resp, testPodNamespace, arch))
		}
	}

	/*
		job.AddStep(&kubernetes.EnsureStableComponent{
			PodNamespace:           common.KubeSystemNamespace,
			LabelSelector:          "k8s-app=retina",
			IgnoreContainerRestart: false,
		}, nil)
	*/
	return job
}

func UpgradeAndTestRetinaAdvancedMetrics(kubeConfigFilePath, chartPath, valuesFilePath string, testPodNamespace string) *types.Job {
	job := types.NewJob("Upgrade and test Retina with advanced metrics")

	// enable advanced metrics
	job.AddStep(&kubernetes.UpgradeRetinaHelmChart{
		Namespace:          common.KubeSystemNamespace,
		ReleaseName:        "retina",
		KubeConfigFilePath: kubeConfigFilePath,
		ChartPath:          chartPath,
		TagEnv:             generic.DefaultTagEnv,
		ValuesFile:         valuesFilePath,
	}, nil)

	dnsScenarios := []struct {
		name string
		req  *dns.RequestValidationParams
		resp *dns.ResponseValidationParams
	}{
		{
			name: "Validate advanced DNS request and response metrics for a valid domain",
			req: &dns.RequestValidationParams{
				NumResponse: "0",
				Query:       "kubernetes.default.svc.cluster.local.",
				QueryType:   "A",
				Command:     "nslookup kubernetes.default",
				ExpectError: false,
			},
			resp: &dns.ResponseValidationParams{
				NumResponse: "1",
				Query:       "kubernetes.default.svc.cluster.local.",
				QueryType:   "A",
				ReturnCode:  "NOERROR",
				Response:    "10.0.0.1",
			},
		},
		{
			name: "Validate advanced DNS request and response metrics for a non-existent domain",
			req: &dns.RequestValidationParams{
				NumResponse: "0",
				Query:       "some.non.existent.domain.",
				QueryType:   "A",
				Command:     "nslookup some.non.existent.domain.",
				ExpectError: true,
			},
			resp: &dns.ResponseValidationParams{
				NumResponse: "0",
				Query:       "some.non.existent.domain.",
				QueryType:   "A",
				Response:    dns.EmptyResponse, // hacky way to bypass the framework for now
				ReturnCode:  "NXDOMAIN",
			},
		},
		{
			name: "Validate advanced DNS request and response metrics for a non-existent domain",
			req: &dns.RequestValidationParams{
				NumResponse: "0",
				Query:       "some.non.existent.domain.",
				QueryType:   "A",
				Command:     "nslookup some.non.existent.domain.",
				ExpectError: true,
			},
			resp: &dns.ResponseValidationParams{
				NumResponse: "0",
				Query:       "some.non.existent.domain.",
				QueryType:   "A",
				Response:    dns.EmptyResponse, // hacky way to bypass the framework for now
				ReturnCode:  "NXDOMAIN",
			},
		},
	}

	for _, arch := range common.Architectures {
		for _, scenario := range dnsScenarios {
			name := scenario.name + " - Arch: " + arch
			job.AddScenario(dns.ValidateAdvancedDNSMetrics(name, scenario.req, scenario.resp, kubeConfigFilePath, testPodNamespace, arch))
		}

		job.AddScenario(windows.ValidateWindowsBasicMetric())
	}

	job.AddScenario(latency.ValidateLatencyMetric(testPodNamespace))

	/*
		job.AddStep(&kubernetes.EnsureStableComponent{
			PodNamespace:           common.KubeSystemNamespace,
			LabelSelector:          "k8s-app=retina",
			IgnoreContainerRestart: false,
		}, nil)
	*/
	return job
}

func ValidateHubble(kubeConfigFilePath, chartPath string, testPodNamespace string) *types.Job {
	job := types.NewJob("Validate Hubble")

	job.AddStep(&kubernetes.ValidateHubbleStep{
		Namespace:          common.KubeSystemNamespace,
		ReleaseName:        "retina",
		KubeConfigFilePath: kubeConfigFilePath,
		ChartPath:          chartPath,
		TagEnv:             generic.DefaultTagEnv,
	}, nil)

	job.AddScenario(hubble.ValidateHubbleRelayService())

	job.AddScenario(hubble.ValidateHubbleUIService(kubeConfigFilePath))

	job.AddStep(&kubernetes.EnsureStableComponent{
		PodNamespace:           common.KubeSystemNamespace,
		LabelSelector:          "k8s-app=retina",
		IgnoreContainerRestart: false,
	}, nil)

	return job
}

func LoadGenericFlags() *types.Job {
	job := types.NewJob("Loading Generic Flags to env")

	job.AddStep(&generic.LoadFlags{
		TagEnv:            generic.DefaultTagEnv,
		ImageNamespaceEnv: generic.DefaultImageNamespace,
		ImageRegistryEnv:  generic.DefaultImageRegistry,
	}, nil)

	return job
}

func InstallEbpfXdp(kubeConfigFilePath string) *types.Job {
	job := types.NewJob("Install ebpf and xdp")
	job.AddStep(&kubernetes.CreateNamespace{
		KubeConfigFilePath: kubeConfigFilePath,
		Namespace:          "install-ebpf-xdp"}, nil)
	job.AddStep(&kubernetes.ApplyYamlConfig{
		YamlFilePath: "yaml/windows/install-ebpf-xdp.yaml",
	}, nil)
	job.AddStep(&generic.Sleep{
		Duration: 10 * time.Minute,
	}, nil)
	return job
}

func LoadAndPinWinBPF(kubeConfigFilePath string) *types.Job {
	job := types.NewJob("Load and pin WinBPF")
	job.AddStep(&kubernetes.LoadAndPinWinBPF{
		KubeConfigFilePath:                 kubeConfigFilePath,
		LoadAndPinWinBPFDeamonSetNamespace: "install-ebpf-xdp",
		LoadAndPinWinBPFDeamonSetName:      "install-ebpf-xdp",
	}, nil)
	job.AddStep(&generic.Sleep{
		Duration: 1 * time.Minute,
	}, nil)
	return job
}

func CreateWindowsPod(kubeConfigFilePath string) *types.Job {
	job := types.NewJob("Create NON-HPC Windows Pod")
	job.AddStep(&kubernetes.ApplyYamlConfig{
		KubeConfigFilePath: kubeConfigFilePath,
		YamlFilePath:       "yaml/windows/non-hpc-pod.yaml",
	}, nil)
	job.AddStep(&generic.Sleep{
		Duration: 2 * time.Minute,
	}, nil)
	return job
}

func InstallAndTestRetinaWinBPFMetrics(kubeConfigFilePath string, chartPath string) *types.Job {
	job := types.NewJob("Install Retina with WinBPF metrics")

	/*
		job.AddStep(&kubernetes.InstallHelmChart{
			KubeConfigFilePath: kubeConfigFilePath,
			Namespace:          common.KubeSystemNamespace,
			ReleaseName:        "retina",
			ChartPath:          chartPath,
			TagEnv:             generic.DefaultTagEnv,
			EnableWinBpfPlugin: true,
		}, nil)

		job.AddStep(&generic.Sleep{
			Duration: 5 * time.Minute,
		}, nil)
	*/
	job.AddScenario(windows.ValidateWinBpfMetricScenario())
	return job
}
