package kubernetes

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	applyTimeout = 10 * time.Minute
)

type ApplyYamlConfig struct {
	KubeConfigFilePath string
	YamlFilePath       string
}

func (a *ApplyYamlConfig) Run() error {
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()

	config, err := clientcmd.BuildConfigFromFlags("", a.KubeConfigFilePath)
	if err != nil {
		return fmt.Errorf("error building kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("error creating dynamic client: %w", err)
	}

	yamlFile, err := ioutil.ReadFile(a.YamlFilePath)
	if err != nil {
		return fmt.Errorf("error reading YAML file: %w", err)
	}

	decoder := yaml.NewYAMLOrJSONDecoder(yamlFile, 100)
	var rawObj unstructured.Unstructured
	if err := decoder.Decode(&rawObj); err != nil {
		return fmt.Errorf("error decoding YAML file: %w", err)
	}

	gvk := rawObj.GroupVersionKind()
	mapping, err := clientset.RESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return fmt.Errorf("error getting REST mapping: %w", err)
	}

	resourceInterface := dynamicClient.Resource(mapping.Resource).Namespace(rawObj.GetNamespace())
	_, err = resourceInterface.Create(ctx, &rawObj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error applying YAML file: %w", err)
	}

	log.Printf("applied YAML file: %s\n", a.YamlFilePath)

	return nil
}

func (a *ApplyYamlConfig) Prevalidate() error {
	_, err := os.Stat(a.YamlFilePath)
	if os.IsNotExist(err) {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory %s: %w", cwd, err)
		}
		log.Printf("the current working directory %s", cwd)
		return fmt.Errorf("YAML file not found at %s: working directory: %s: %w", a.YamlFilePath, cwd, err)
	}
	log.Printf("found YAML file at %s", a.YamlFilePath)

	return nil
}

func (a *ApplyYamlConfig) Stop() error {
	return nil
}
