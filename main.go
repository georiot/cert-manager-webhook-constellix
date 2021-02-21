package main

import (
	"encoding/json"
	"fmt"
	"github.com/Constellix/constellix-go-client/client"
	"github.com/Constellix/constellix-go-client/models"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var groupName = os.Getenv("GROUP_NAME")

func main() {
	if groupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our Constellix DNS provider with the webhook serving
	// library, making it available as an API under the provided groupName.
	cmd.RunWebhookServer(groupName,
		&constellixDNSProviderSolver{},
	)
}

// constellixDNSProviderSolver implements the logic needed to 'present' an ACME
// challenge TXT record. To do so, it implements the
// `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver` interface.
type constellixDNSProviderSolver struct {
	k8sClient        *kubernetes.Clientset
	constellixClient *client.Client
}

// constellixDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
type constellixDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	APIKeySecretRef    cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
	APISecretSecretRef cmmeta.SecretKeySelector `json:"apiSecretSecretRef"`
	ZoneId             int                      `json:"zoneId"`
	Insecure           bool                     `json:"insecure"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
func (c *constellixDNSProviderSolver) Name() string {
	return "constellix"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *constellixDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	_, domain, err := c.parseChallenge(ch)
	if err != nil {
		return err
	}

	if c.constellixClient == nil {
		if err := c.setConstellixClient(ch, cfg); err != nil {
			return err
		}
	}

	// Create a TXT Record for domain.zone with answer set to DNS challenge key
	// Short TTL is fine, as we delete the record after the challenge is solved.
	TxtAttr := models.TxtAttributes{}
	TxtAttr.Name = domain
	TxtAttr.TTL = 60

	mapListRR := make([]interface{}, 0, 1)

	tpMap := make(map[string]interface{})
	tpMap["value"] = fmt.Sprintf("%v", ch.Key)
	tpMap["disableFlag"] = fmt.Sprintf("%v", "false")

	mapListRR = append(mapListRR, tpMap)
	TxtAttr.RoundRobin = mapListRR

	id := strconv.Itoa(cfg.ZoneId)

	_, err = c.constellixClient.Save(TxtAttr, "v1/domains/"+id+"/records/txt")
	if err != nil {
		return err
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *constellixDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	_, domain, err := c.parseChallenge(ch)
	if err != nil {
		return err
	}

	if c.constellixClient == nil {
		if err := c.setConstellixClient(ch, cfg); err != nil {
			return err
		}
	}

	id := strconv.Itoa(cfg.ZoneId)

	response, err := c.constellixClient.GetbyId("v1/domains/" + id + "/records/txt/search?exact=" + domain)
	if err != nil {
		return err
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	bodyString := string(bodyBytes)
	var data map[string]interface{}
	_ = json.Unmarshal([]byte(bodyString), &data)

	// Delete the TXT Record we created in Present
	if err = c.constellixClient.DeletebyId("v1/domains/" + id + "/records/txt/" + data["id"].(string)); err != nil {
		return err
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *constellixDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.k8sClient = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (constellixDNSProviderConfig, error) {
	cfg := constellixDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *constellixDNSProviderSolver) setConstellixClient(ch *v1alpha1.ChallengeRequest, cfg constellixDNSProviderConfig) error {
	apiKeyRef := cfg.APIKeySecretRef
	if apiKeyRef.Name == "" {
		return fmt.Errorf(
			"secret for NS1 apiKey not found in '%s'",
			ch.ResourceNamespace,
		)
	}
	if apiKeyRef.Key == "" {
		return fmt.Errorf(
			"no 'key' set in secret '%s/%s'",
			ch.ResourceNamespace,
			apiKeyRef.Name,
		)
	}

	secret, err := c.k8sClient.CoreV1().Secrets(ch.ResourceNamespace).Get(
		apiKeyRef.Name, metav1.GetOptions{},
	)
	if err != nil {
		return err
	}
	apiKeyBytes, ok := secret.Data[apiKeyRef.Key]
	if !ok {
		return fmt.Errorf(
			"no key '%s' in secret '%s/%s'",
			apiKeyRef.Key,
			ch.ResourceNamespace,
			apiKeyRef.Name,
		)
	}
	apiKey := string(apiKeyBytes)

	secretKeyRef := cfg.APISecretSecretRef
	if secretKeyRef.Name == "" {
		return fmt.Errorf(
			"secret for Constellix secretKey not found in '%s'",
			ch.ResourceNamespace,
		)
	}
	if secretKeyRef.Key == "" {
		return fmt.Errorf(
			"no 'key' set in secret '%s/%s'",
			ch.ResourceNamespace,
			secretKeyRef.Name,
		)
	}

	secret, err = c.k8sClient.CoreV1().Secrets(ch.ResourceNamespace).Get(
		secretKeyRef.Name, metav1.GetOptions{},
	)
	if err != nil {
		return err
	}
	secretKeyBytes, ok := secret.Data[secretKeyRef.Key]
	if !ok {
		return fmt.Errorf(
			"no key '%s' in secret '%s/%s'",
			secretKeyRef.Key,
			ch.ResourceNamespace,
			secretKeyRef.Name,
		)
	}
	secretKey := string(secretKeyBytes)

	c.constellixClient = client.GetClient(apiKey, secretKey, client.Insecure(cfg.Insecure))

	return nil
}

// Get the zone and domain we are setting from the challenge request
func (c *constellixDNSProviderSolver) parseChallenge(ch *v1alpha1.ChallengeRequest) (
	zone string, domain string, err error,
) {

	if zone, err = util.FindZoneByFqdn(
		ch.ResolvedFQDN, util.RecursiveNameservers,
	); err != nil {
		return "", "", err
	}
	zone = util.UnFqdn(zone)

	if idx := strings.Index(ch.ResolvedFQDN, "."+ch.ResolvedZone); idx != -1 {
		domain = ch.ResolvedFQDN[:idx]
	} else {
		domain = util.UnFqdn(ch.ResolvedFQDN)
	}

	return zone, domain, nil
}
