package windows

import (
	"github.com/microsoft/retina/test/e2e/common"
	"github.com/microsoft/retina/test/e2e/framework/types"
)

func ValidateCiliumMetricScenario() *types.Scenario {
	name := "Validate Windows Cilium Basic Metrics"
	steps := []*types.StepWrapper{
		{
			Step: &ValidateCiliumMetric{
				KubeConfigFilePath:        "./test.pem",
				RetinaDaemonSetNamespace:  common.KubeSystemNamespace,
				RetinaDaemonSetName:       "retina-agent-win",
				EbpfXdpDeamonSetNamespace: "install-ebpf-xdp",
				EbpfXdpDeamonSetName:      "install-ebpf-xdp",
			},
		},
	}
	return types.NewScenario(name, steps...)
}
