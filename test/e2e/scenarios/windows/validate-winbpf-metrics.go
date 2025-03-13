package windows

import (
	"context"
	"fmt"
	"strings"
	"time"

	k8s "github.com/microsoft/retina/test/e2e/framework/kubernetes"
	prom "github.com/microsoft/retina/test/e2e/framework/prometheus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type ValidateWinBpfMetric struct {
	KubeConfigFilePath        string
	EbpfXdpDeamonSetNamespace string
	EbpfXdpDeamonSetName      string
	RetinaDaemonSetNamespace  string
	RetinaDaemonSetName       string
}

type CommandResult struct {
	Output string
}

func (v *ValidateWinBpfMetric) ExecCommandInWinPod(cmd string, DeamonSetName string, DaemonSetNamespace string, LabelSelector string) (error, string) {
	config, err := clientcmd.BuildConfigFromFlags("", v.KubeConfigFilePath)
	if err != nil {
		return fmt.Errorf("error building kubeconfig: %w", err), ""
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %w", err), ""
	}

	pods, err := clientset.CoreV1().Pods(DaemonSetNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: LabelSelector,
	})
	if err != nil {
		panic(err.Error())
	}

	var windowsPod *v1.Pod
	for pod := range pods.Items {
		if pods.Items[pod].Spec.NodeSelector["kubernetes.io/os"] == "windows" {
			windowsPod = &pods.Items[pod]
		}
	}

	if windowsPod == nil {
		return fmt.Errorf("no Windows Pod found in DaemonSet %s and label %s", DeamonSetName, LabelSelector), ""
	}

	result := &CommandResult{}
	err = defaultRetrier.Do(context.TODO(), func() error {
		outputBytes, err := k8s.ExecPod(context.TODO(), clientset, config, windowsPod.Namespace, windowsPod.Name, cmd)
		if err != nil {
			fmt.Errorf("error executing command in windows pod: %w", err)
			return fmt.Errorf("error executing command in windows pod: %w", err)
		}

		result.Output = string(outputBytes)
		return nil
	})
	if err != nil {
		return err, ""
	}

	return nil, result.Output
}

func (v *ValidateWinBpfMetric) GetPromMetrics(ebpfLabelSelector string) (string, error) {
	var promOutput string = ""
	numAttempts := 10
	for promOutput == "" && numAttempts > 0 {
		err, newPromOutput := v.ExecCommandInWinPod("C:\\event-writer-helper.bat GetRetinaPromMetrics", v.EbpfXdpDeamonSetName, v.EbpfXdpDeamonSetNamespace, ebpfLabelSelector)
		if err != nil {
			fmt.Println(err.Error())
			return "", err
		}
		promOutput = newPromOutput

		if promOutput != "" {
			break
		}
		numAttempts--
		time.Sleep(5 * time.Second)
	}

	return promOutput, nil
}

func (v *ValidateWinBpfMetric) Run() error {
	ebpfLabelSelector := fmt.Sprintf("name=%s", v.EbpfXdpDeamonSetName)
	promOutput, err := v.GetPromMetrics(ebpfLabelSelector)
	if err != nil {
		return fmt.Errorf("failed to get prometheus metrics")
	}

	fwd_labels := map[string]string{
		"direction": "ingress",
	}
	drp_labels := map[string]string{
		"direction": "ingress",
		"reason":    "130, 0",
	}

	var preTestFwdBytes float64 = 0
	var preTestDrpBytes float64 = 0
	var preTestFwdCount float64 = 0
	var preTestDrpCount float64 = 0
	if promOutput == "" {
		fmt.Println("PreTest - no prometheus metrics found")
	} else {
		preTestFwdBytes, _ = prom.GetMetricGuageValueFromBuffer([]byte(promOutput), "networkobservability_forward_bytes", fwd_labels)
		fmt.Printf("Metric value %f, labels: %v\n", preTestFwdBytes, fwd_labels)

		preTestFwdCount, _ = prom.GetMetricGuageValueFromBuffer([]byte(promOutput), "networkobservability_forward_count", fwd_labels)
		fmt.Printf("Metric value %f, labels: %v\n", preTestFwdBytes, fwd_labels)

		preTestDrpBytes, _ = prom.GetMetricGuageValueFromBuffer([]byte(promOutput), "networkobservability_drop_bytes", drp_labels)
		fmt.Printf("Metric value %f, labels: %v\n", preTestDrpBytes, drp_labels)

		preTestDrpCount, _ = prom.GetMetricGuageValueFromBuffer([]byte(promOutput), "networkobservability_drop_count", drp_labels)
		fmt.Printf("Metric value %f, labels: %v\n", preTestDrpBytes, drp_labels)
	}

	//TRACE
	fmt.Printf("Produce Trace Events\n")
	//Example.com - 23.192.228.84
	err, _ = v.ExecCommandInWinPod("C:\\event-writer-helper.bat Start-EventWriter -event 4 -srcIP 23.192.228.84",
		v.EbpfXdpDeamonSetName,
		v.EbpfXdpDeamonSetNamespace,
		ebpfLabelSelector)
	if err != nil {
		return err
	}

	time.Sleep(5 * time.Second)
	err, output := v.ExecCommandInWinPod("C:\\event-writer-helper.bat DumpEventWriter",
		v.EbpfXdpDeamonSetName,
		v.EbpfXdpDeamonSetNamespace,
		ebpfLabelSelector)
	if err != nil {
		return err
	}
	fmt.Println(output)
	if strings.Contains(output, "failed") || strings.Contains(output, "error") {
		return fmt.Errorf("failed to start event writer")
	}

	numcurls := 10
	for numcurls > 0 {
		err, _ = v.ExecCommandInWinPod("C:\\event-writer-helper.bat Curl 23.192.228.84",
			v.EbpfXdpDeamonSetName,
			v.EbpfXdpDeamonSetNamespace,
			ebpfLabelSelector)
		if err != nil {
			return err
		}
		numcurls--
	}

	//DROP
	time.Sleep(60 * time.Second)
	fmt.Printf("Produce Drop Events\n")
	err, _ = v.ExecCommandInWinPod("C:\\event-writer-helper.bat Start-EventWriter -event 1 -srcIP 23.192.228.84",
		v.EbpfXdpDeamonSetName,
		v.EbpfXdpDeamonSetNamespace,
		ebpfLabelSelector)
	if err != nil {
		return err
	}

	time.Sleep(5 * time.Second)
	err, output = v.ExecCommandInWinPod("C:\\event-writer-helper.bat DumpEventWriter",
		v.EbpfXdpDeamonSetName,
		v.EbpfXdpDeamonSetNamespace,
		ebpfLabelSelector)
	if err != nil {
		return err
	}
	fmt.Println(output)
	if strings.Contains(output, "failed") || strings.Contains(output, "error") {
		return fmt.Errorf("failed to start event writer")
	}

	numcurls = 10
	for numcurls > 0 {
		err, _ = v.ExecCommandInWinPod("C:\\event-writer-helper.bat Curl 23.192.228.84",
			v.EbpfXdpDeamonSetName,
			v.EbpfXdpDeamonSetNamespace,
			ebpfLabelSelector)
		if err != nil {
			return err
		}
		numcurls--
	}

	err, output = v.ExecCommandInWinPod("C:\\event-writer-helper.bat DumpCurl", v.EbpfXdpDeamonSetName, v.EbpfXdpDeamonSetNamespace, ebpfLabelSelector)
	if err != nil {
		return err
	}
	if strings.Contains(output, "failed") {
		return fmt.Errorf("failed to curl to example.com")
	}

	fmt.Println("Waiting for basic metrics to be updated as part of next polling cycle")
	time.Sleep(60 * time.Second)
	promOutput, err = v.GetPromMetrics(ebpfLabelSelector)
	if err != nil {
		return fmt.Errorf("failed to get prometheus metrics")
	}
	if promOutput == "" {
		return fmt.Errorf("post test - failed to get prometheus metrics")
	}
	postTestFwdCount, _ := prom.GetMetricGuageValueFromBuffer([]byte(promOutput), "networkobservability_forward_count", fwd_labels)
	fmt.Printf("Metric value %f, labels: %v\n", preTestFwdBytes, fwd_labels)

	postTestFwdBytes, err := prom.GetMetricGuageValueFromBuffer([]byte(promOutput), "networkobservability_forward_bytes", fwd_labels)
	if err != nil {
		return fmt.Errorf("failed to get metric: %w", err)
	}
	fmt.Printf("Metric value %f, labels: %v\n", postTestFwdBytes, fwd_labels)

	postTestDrpBytes, err := prom.GetMetricGuageValueFromBuffer([]byte(promOutput), "networkobservability_drop_bytes", drp_labels)
	if err != nil {
		return fmt.Errorf("failed to get metric: %w", err)
	}
	fmt.Printf("Metric value %f, labels: %v\n", postTestDrpBytes, drp_labels)

	postTestDrpCount, _ := prom.GetMetricGuageValueFromBuffer([]byte(promOutput), "networkobservability_drop_count", drp_labels)
	fmt.Printf("Metric value %f, labels: %v\n", preTestDrpBytes, drp_labels)

	if postTestFwdBytes < preTestFwdBytes {
		return fmt.Errorf("fwd Bytes not incremented")
	}

	if postTestDrpBytes < preTestDrpBytes {
		return fmt.Errorf("drp Bytes not incremented")
	}

	if postTestFwdCount < preTestFwdCount {
		return fmt.Errorf("fwd count not incremented")
	}
	if postTestDrpCount < preTestDrpCount {
		return fmt.Errorf("drp count not incremnted")
	}

	// Advanced Metrics
	adv_fwd_count_labels := map[string]string{
		"direction":     "egress",
		"ip":            "23.192.228.84",
		"namespace":     "",
		"podname":       "",
		"workload_kind": "unknown",
		"workload_name": "unknown",
	}
	err = prom.CheckMetricFromBuffer([]byte(promOutput), "networkobservability_adv_forward_count", adv_fwd_count_labels)
	if err != nil {
		return fmt.Errorf("failed to find networkobservability_adv_forward_count")
	}

	tcpFlags := []string{"ACK", "FIN", "PSH"}
	for _, flag := range tcpFlags {
		tcpFlagLabels := map[string]string{
			"flag":          flag,
			"ip":            "23.192.228.84",
			"namespace":     "",
			"podname":       "",
			"workload_kind": "unknown",
			"workload_name": "unknown",
		}

		err = prom.CheckMetricFromBuffer([]byte(promOutput), "networkobservability_adv_tcpflags_count", tcpFlagLabels)
		if err != nil {
			return fmt.Errorf("failed to find networkobservability_adv_tcpflags_count for flag %s: %w", flag, err)
		}
		fmt.Printf("Found TCP flag metric for %s\n", flag)
	}

	adv_drop_byte_labels := map[string]string{
		"direction":     "egress",
		"ip":            "23.192.228.84",
		"namespace":     "",
		"podname":       "",
		"reason":        "Drop_NotAccepted",
		"workload_kind": "unknown",
		"workload_name": "unknown",
	}
	err = prom.CheckMetricFromBuffer([]byte(promOutput), "networkobservability_adv_drop_bytes", adv_drop_byte_labels)
	if err != nil {
		return fmt.Errorf("failed to find networkobservability_adv_drop_bytes")
	}

	adv_drop_count_labels := map[string]string{
		"direction":     "egress",
		"ip":            "23.192.228.84",
		"namespace":     "",
		"podname":       "",
		"reason":        "Drop_NotAccepted",
		"workload_kind": "unknown",
		"workload_name": "unknown",
	}
	err = prom.CheckMetricFromBuffer([]byte(promOutput), "networkobservability_adv_drop_count", adv_drop_count_labels)
	if err != nil {
		return fmt.Errorf("failed to find networkobservability_adv_drop_count")
	}

	return nil
}

func (v *ValidateWinBpfMetric) Prevalidate() error {
	return nil
}

func (v *ValidateWinBpfMetric) Stop() error {
	return nil
}
