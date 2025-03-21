//go:build e2e

package retina

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/microsoft/retina/test/e2e/common"
	"github.com/microsoft/retina/test/e2e/framework/helpers"
	"github.com/microsoft/retina/test/e2e/framework/types"
	"github.com/microsoft/retina/test/e2e/infra"
	jobs "github.com/microsoft/retina/test/e2e/jobs"
	"github.com/stretchr/testify/require"
)

// TestE2ERetina tests all e2e scenarios for retina
func TestE2ERetina(t *testing.T) {
	ctx, cancel := helpers.Context(t)
	defer cancel()

	cwd, err := os.Getwd()
	require.NoError(t, err)

	// Get to root of the repo by going up two directories
	rootDir := filepath.Dir(filepath.Dir(cwd))

	hubblechartPath := filepath.Join(rootDir, "deploy", "hubble", "manifests", "controller", "helm", "retina")

	err = jobs.LoadGenericFlags().Run()
	require.NoError(t, err, "failed to load generic flags")

<<<<<<< HEAD
	// Install Ebpf and XDP
	installEbpfAndXDP := types.NewRunner(t, jobs.InstallEbpfXdp(kubeConfigFilePath))
	installEbpfAndXDP.Run(ctx)

	t.Cleanup(func() {
		if *common.DeleteInfra {
			_ = jobs.DeleteTestInfra(subID, rg, clusterName, location).Run()
		}
	})
=======
	if *common.KubeConfig == "" {
		*common.KubeConfig = infra.CreateAzureTempK8sInfra(ctx, t, rootDir)
	}
>>>>>>> af4b65b592eebd995d53c7d263a1af14636590ce

	time.Sleep(10 * time.Minute)

	// Install Ebpf and XDP
	installEventWriter := types.NewRunner(t, jobs.InstallEventWriter(kubeConfigFilePath))
	installEventWriter.Run(ctx)

	time.Sleep(10 * time.Minute)

	// Install and test Retina basic metrics
	basicMetricsE2E := types.NewRunner(t,
		jobs.InstallAndTestRetinaBasicMetrics(
			common.KubeConfigFilePath(rootDir),
			common.RetinaChartPath(rootDir),
			common.TestPodNamespace),
	)
	basicMetricsE2E.Run(ctx)

<<<<<<< HEAD
	time.Sleep(10 * time.Minute)
	//Upgrade and test Retina with advanced metrics
	advanceMetricsE2E := types.NewRunner(t, jobs.UpgradeAndTestRetinaAdvancedMetrics(kubeConfigFilePath, chartPath, profilePath, common.TestPodNamespace))
=======
	// Upgrade and test Retina with advanced metrics
	advanceMetricsE2E := types.NewRunner(t,
		jobs.UpgradeAndTestRetinaAdvancedMetrics(
			common.KubeConfigFilePath(rootDir),
			common.RetinaChartPath(rootDir),
			common.RetinaAdvancedProfilePath(rootDir),
			common.TestPodNamespace),
	)
>>>>>>> af4b65b592eebd995d53c7d263a1af14636590ce
	advanceMetricsE2E.Run(ctx)

	// Install and test Hubble basic metrics
	validatehubble := types.NewRunner(t,
		jobs.ValidateHubble(
			common.KubeConfigFilePath(rootDir),
			hubblechartPath,
			common.TestPodNamespace),
	)
	validatehubble.Run(ctx)

	// Install and test Cilium Windows basics and advanced metrics
	time.Sleep(10 * time.Minute)
}
