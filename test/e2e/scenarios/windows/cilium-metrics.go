package windows

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type ValidateCiliumMetric struct {
	KubeConfigFilePath       string
	RetinaDaemonSetNamespace string
	RetinaDaemonSetName      string
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

	pods, err := clientset.CoreV1().Pods(v.RetinaDaemonSetNamespace).List(context.TODO(), metav1.ListOptions{
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
	/*
		labels := map[string]string{
			"direction": "win_packets_sent_count",
		}

		log.Printf("checking for metric %s with labels %+v\n", hnsMetricName, labels)

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

			if err != nil {
				return fmt.Errorf("failed to get metrics from windows retina pod: %w", err)
			}

			err = prom.CheckMetricFromBuffer(output, hnsMetricName, labels)
			if err != nil {
				return fmt.Errorf("failed to verify prometheus metrics: %w", err)
			}

			return nil
		})

		log.Printf("found metric matching %+v: with labels %+v\n", hnsMetricName, labels)
	*/
	return nil
}

func (v *ValidateCiliumMetric) Prevalidate() error {
	return nil
}

func (v *ValidateCiliumMetric) Stop() error {
	return nil
}
