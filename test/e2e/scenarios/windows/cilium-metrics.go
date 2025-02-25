package windows

import (
	"context"
	"fmt"
	"time"

	"github.com/microsoft/retina/test/e2e/common"
	k8s "github.com/microsoft/retina/test/e2e/framework/kubernetes"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type ValidateCiliumMetric struct {
	KubeConfigFilePath        string
	EbpfXdpDeamonSetNamespace string
	EbpfXdpDeamonSetName      string
	RetinaDaemonSetNamespace  string
	RetinaDaemonSetName       string
}

func (v *ValidateCiliumMetric) Run() error {
	config, err := clientcmd.BuildConfigFromFlags("", v.KubeConfigFilePath)
	if err != nil {
		return fmt.Errorf("error building kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %w", err)
	}

	// Install Event-Writer
	ebpfXDPLabelSelector := fmt.Sprintf("name=%s", v.EbpfXdpDeamonSetName)
	pods, err := clientset.CoreV1().Pods(v.EbpfXdpDeamonSetNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ebpfXDPLabelSelector,
	})
	if err != nil {
		panic(err.Error())
	}

	var windowsEbpfXdpPod *v1.Pod
	for pod := range pods.Items {
		if pods.Items[pod].Spec.NodeSelector["kubernetes.io/os"] == "windows" {
			windowsEbpfXdpPod = &pods.Items[pod]
		}
	}
	if windowsEbpfXdpPod == nil {
		return ErrorNoWindowsPod
	}

	bpfeventwriterurl := "https://github.com/vpidatala94/retina/raw/user/vpidatala/POC/8/test/plugin/eventwriter/x64/Release/bpf_event_writer.sys"
	eventwriterexeurl := "https://github.com/vpidatala94/retina/raw/user/vpidatala/POC/8/test/plugin/eventwriter/x64/Release/event_writer.exe"
	// Hardcoding IP addr for aka.ms - 23.213.38.151 - 399845015
	aksmsIpaddr := 399845015
	cmd := fmt.Sprintf(`try {
		$response = Invoke-WebRequest -Uri "%s" -OutFile "C:\bpf_event_writer.sys" -ErrorAction Stop;
		if ($response.StatusCode -ne 200) {
			throw;
		}
		$response = Invoke-WebRequest -Uri "%s" -OutFile "C:\event_writer.exe" -ErrorAction Stop;
		if ($response.StatusCode -ne 200) {
			throw;
		}
		& C:\event_writer.exe -event 4 -srcIP %s;
		Write-Output 0;
	} catch {
		Write-Output 1;
	}`, bpfeventwriterurl, eventwriterexeurl, aksmsIpaddr)

	err = defaultRetrier.Do(context.TODO(), func() error {
		outputBytes, err := k8s.ExecPod(context.TODO(), clientset, config, windowsEbpfXdpPod.Namespace, windowsEbpfXdpPod.Name, cmd)
		if err != nil {
			return fmt.Errorf("error executing command in windows retina pod: %w", err)
		}
		output := string(outputBytes)
		if output != "0" {
			return fmt.Errorf("failed to install event-writer: %w", err)
		}
		return nil
	})
	if err != nil {
		panic(err.Error())
	}

	time.Sleep(10 * time.Minute)

	pods, err = clientset.CoreV1().Pods(v.RetinaDaemonSetNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: "k8s-app=retina",
	})
	if err != nil {
		panic(err.Error())
	}

	var windowsRetinaPod *v1.Pod
	for pod := range pods.Items {
		if pods.Items[pod].Spec.NodeSelector["kubernetes.io/os"] == "windows" {
			windowsRetinaPod = &pods.Items[pod]
		}
	}
	if windowsRetinaPod == nil {
		return ErrorNoWindowsPod
	}

	// wrap this in a retrier because windows is slow
	var output []byte
	err = defaultRetrier.Do(context.TODO(), func() error {
		output, err = k8s.ExecPod(context.TODO(), clientset, config, windowsRetinaPod.Namespace, windowsRetinaPod.Name, fmt.Sprintf("curl -s http://localhost:%d/metrics", common.RetinaPort))
		if err != nil {
			return fmt.Errorf("error executing command in windows retina pod: %w", err)
		}
		if len(output) == 0 {
			return ErrNoMetricFound
		}

		fmt.Println(output)
		return nil
	})
	return nil
}

func (v *ValidateCiliumMetric) Prevalidate() error {
	return nil
}

func (v *ValidateCiliumMetric) Stop() error {
	return nil
}
