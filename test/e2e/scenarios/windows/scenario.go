package windows

import (
	"github.com/microsoft/retina/test/e2e/common"
	"github.com/microsoft/retina/test/e2e/framework/types"
)

func ValidateWindowsBasicMetric() *types.Scenario {
	name := "Windows Metrics"
	steps := []*types.StepWrapper{
		{
			Step: &ValidateHNSMetric{
				KubeConfigFilePath:       "./test.pem",
				RetinaDaemonSetNamespace: common.KubeSystemNamespace,
				RetinaDaemonSetName:      "retina-agent-win",
			},
		},
	}
	return types.NewScenario(name, steps...)
}

func ValidateCiliumBasicMetric() *types.Scenario {
	name := "Cilium Windows Metrics"
	steps := []*types.StepWrapper{
		{
			Step: &ValidateCiliumMetric{
				KubeConfigFilePath:       "./test.pem",
				RetinaDaemonSetNamespace: common.KubeSystemNamespace,
				RetinaDaemonSetName:      "retina-agent-win",
			},
		},
	}
	return types.NewScenario(name, steps...)
}
