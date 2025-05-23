package main

import (
	"context"
	"flag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	backupSizeBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "volsync_sync_total_bytes",
			Help: "Size of the latest backup in bytes",
		},
		[]string{"namespace", "sourcepvc", "persistentvolume", "storageclass"},
	)

	// Regex to parse the backup size from logs in the CR status
	// Matches patterns like "504.129 MiB" or "1.5 GiB"
	sizeRegex = regexp.MustCompile(`processed \d+ files, ([\d.]+) ((?:[KMGT]i)?B)`)
)

func convertToBytes(size float64, unit string) float64 {
	multipliers := map[string]float64{
		"B":   1,
		"KiB": 1024,
		"MiB": 1024 * 1024,
		"GiB": 1024 * 1024 * 1024,
		"TiB": 1024 * 1024 * 1024 * 1024,
	}

	if multiplier, ok := multipliers[unit]; ok {
		return size * multiplier
	}
	return 0
}

func watchReplicationSources(clientset *kubernetes.Clientset, client dynamic.Interface) {
	replicationSource := schema.GroupVersionResource{
		Group:    "volsync.backube",
		Version:  "v1alpha1",
		Resource: "replicationsources",
	}

	for {
		list, err := client.Resource(replicationSource).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Printf("Error listing ReplicationSources: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		log.Printf("Found %d ReplicationSources, updating metrics now", len(list.Items))

		sourcesProcessed := 0
		for _, item := range list.Items {
			namespace := item.GetNamespace()
			name := item.GetName()

			logs, found, err := unstructured.NestedString(item.Object, "status", "latestMoverStatus", "logs")
			if !found || err != nil {
				continue
			}

			sourcePVC, found, err := unstructured.NestedString(item.Object, "spec", "sourcePVC")
			if !found || err != nil {
				continue
			}
			pvc, err := clientset.CoreV1().PersistentVolumeClaims(namespace).
				Get(context.Background(), sourcePVC, metav1.GetOptions{})
			if err != nil {
				log.Printf("Couldn't query source PVC %s for ReplicationSource %s/%s: %v", sourcePVC, namespace, name, err)
				continue
			}

			matches := sizeRegex.FindStringSubmatch(logs)
			if len(matches) == 3 {
				size, err := strconv.ParseFloat(matches[1], 64)
				if err != nil {
					continue
				}

				sizeInBytes := convertToBytes(size, matches[2])
				backupSizeBytes.WithLabelValues(
					namespace, sourcePVC, pvc.Spec.VolumeName, *pvc.Spec.StorageClassName,
				).Set(sizeInBytes)
				sourcesProcessed++
			} else {
				log.Printf("Couldn't parse backup size for ReplicationSource %s/%s from logs", namespace, name)
			}
		}

		log.Printf("Processed %d ReplicationSources successfully, sleeping until next time...", sourcesProcessed)
		time.Sleep(1 * time.Minute)
	}
}

func main() {
	kubeconfig := flag.String("kubeconfig", "", "path to kubeconfig (optional)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	prometheus.MustRegister(backupSizeBytes)

	var config *rest.Config
	var err error
	if *kubeconfig == "" {
		config, err = rest.InClusterConfig()
	} else {
		var configBytes []byte
		configBytes, err = os.ReadFile(*kubeconfig)
		if err != nil {
			log.Fatal(err)
		}
		config, err = clientcmd.RESTConfigFromKubeConfig(configBytes)
	}
	if err != nil {
		log.Fatal(err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	go watchReplicationSources(clientset, dynamicClient)

	log.Println("Starting metrics server at :8080/metrics")
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(":8080", nil))
}
