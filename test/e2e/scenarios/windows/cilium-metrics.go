package windows

import (
	"context"
	"fmt"
	"time"

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

func (v *ValidateCiliumMetric) ExecCommandInEbpfXdpHpcPod(cmd string) error {
	config, err := clientcmd.BuildConfigFromFlags("", v.KubeConfigFilePath)
	if err != nil {
		return fmt.Errorf("error building kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %w", err)
	}

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

	err = defaultRetrier.Do(context.TODO(), func() error {
		outputBytes, err := k8s.ExecPod(context.TODO(), clientset, config, windowsEbpfXdpPod.Namespace, windowsEbpfXdpPod.Name, cmd)
		if err != nil {
			return fmt.Errorf("error executing command in windows retina pod: %w", err)
		}
		output := string(outputBytes)
		fmt.Println(output)
		return nil
	})
	if err != nil {
		panic(err.Error())
	}

	return nil
}

func (v *ValidateCiliumMetric) InstallEventWriter() error {
	// Install Event-Writer
	bpfeventwriterurl := "https://github.com/vpidatala94/retina/blob/user/vpidatala/POC/8/test/e2e/tools/eventwriter/x64/Release/bpf_event_writer.sys"
	cmd := fmt.Sprintf(`
		Invoke-WebRequest -Uri "%s" -OutFile "C:\bpf_event_writer.sys" -ErrorAction Stop`, bpfeventwriterurl)
	v.ExecCommandInEbpfXdpHpcPod(cmd)

	eventwriterexeurl := "https://github.com/vpidatala94/retina/blob/user/vpidatala/POC/8/test/e2e/tools/eventwriter/x64/Release/event_writer.exe"
	cmd = fmt.Sprintf(`Invoke-WebRequest -Uri "%s" -OutFile "C:\event_writer.exe" -ErrorAction Stop`, eventwriterexeurl)
	v.ExecCommandInEbpfXdpHpcPod(cmd)
	return nil
}

func (v *ValidateCiliumMetric) Run() error {
	v.InstallEventWriter()
	time.Sleep(10 * time.Minute)
	// Hardcoding IP addr for aka.ms - 23.213.38.151 - 399845015
	//aksmsIpaddr := 399845015
	// Enable
	cmd := "cd C:\\ && .\\event_writer.exe -event 4 -bpf_sys_path C:\\bpf_event_writer.sys"
	v.ExecCommandInEbpfXdpHpcPod(cmd)
	return nil
}

func (v *ValidateCiliumMetric) Prevalidate() error {
	return nil
}

func (v *ValidateCiliumMetric) Stop() error {
	return nil
}
