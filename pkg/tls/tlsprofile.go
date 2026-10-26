package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	crcommon "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	libapiserver "github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	libevents "github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetTLSProfileValues fetches the cluster API Server TLS profile via
// library-go's ObserveTLSSecurityProfile and returns TLS_MIN_VERSION, TLS_CIPHER_SUITES,
// TLS_CURVE_PREFERENCES, observedConfig for future comparisons and avoid unnecessary updates.
// Returns empty strings on error so callers fall back to kube-rbac-proxy defaults.
//
// Curve preferences are only produced when tlsGroupsEnabled is true (the TLSGroupPreferences
// feature gate is enabled); otherwise an empty string is returned so callers leave curves
// unrestricted. library-go's ObserveTLSSecurityProfile does not emit Groups, so they are read
// from the profile spec directly and converted to numeric curve IDs; unrecognized groups are
// warned-and-skipped rather than failing.
func GetTLSProfileValues(ctx context.Context, c client.Client, tlsGroupsEnabled bool, previousObservedConfig map[string]interface{}) (minVersion, cipherSuites, curvePreferences string, observedConfig map[string]interface{}, err error) {
	listers := &apiServerListers{&clientAPIServerLister{client: c, ctx: ctx}}
	recorder := libevents.NewLoggingEventRecorder("local-storage-operator-tls", clock.RealClock{})

	observedConfig, errors := libapiserver.ObserveTLSSecurityProfile(listers, recorder, previousObservedConfig)
	if len(errors) > 0 {
		return "", "", "", nil, fmt.Errorf("failed to observe TLS security profile: %v", errors)
	}

	minVersion, _, err = unstructured.NestedString(observedConfig, "servingInfo", "minTLSVersion")
	if err != nil {
		return "", "", "", nil, fmt.Errorf("failed to extract minTLSVersion from observed config: %w", err)
	}

	suites, _, err := unstructured.NestedStringSlice(observedConfig, "servingInfo", "cipherSuites")
	if err != nil {
		return "", "", "", nil, fmt.Errorf("failed to extract cipherSuites from observed config: %w", err)
	}

	return minVersion, strings.Join(suites, ","), getCurvePreferences(ctx, c, tlsGroupsEnabled), observedConfig, nil
}

// getCurvePreferences returns the comma-separated list of numeric TLS curve IDs derived from
// the cluster API Server TLS profile's Groups, or an empty string when the TLSGroupPreferences
// feature gate is disabled, no groups are configured, or the profile cannot be read. Unrecognized
// groups are warned-and-skipped.
func getCurvePreferences(ctx context.Context, c client.Client, tlsGroupsEnabled bool) string {
	if !tlsGroupsEnabled {
		return ""
	}

	profile, err := FetchAPIServerTLSProfile(ctx, c)
	if err != nil {
		klog.Warningf("failed to fetch TLS profile for curve preferences, proceeding without: %v", err)
		return ""
	}

	curveIDs, unrecognized := libgocrypto.TLSGroupsToCurvePreferences(profile.Groups)
	if len(unrecognized) > 0 {
		klog.Warningf("ignoring unrecognized TLS groups: %v", unrecognized)
	}
	if len(curveIDs) == 0 {
		return ""
	}

	ids := make([]string, len(curveIDs))
	for i, id := range curveIDs {
		ids[i] = strconv.Itoa(int(id))
	}
	return strings.Join(ids, ",")
}

// clientAPIServerLister implements configlistersv1.APIServerLister backed by a
// controller-runtime client, bridging the informer-based lister interface that
// ObserveTLSSecurityProfile expects.
type clientAPIServerLister struct {
	client client.Client
	ctx    context.Context
}

func (l *clientAPIServerLister) List(selector labels.Selector) ([]*configv1.APIServer, error) {
	list := &configv1.APIServerList{}
	if err := l.client.List(l.ctx, list); err != nil {
		return nil, err
	}
	result := make([]*configv1.APIServer, 0, len(list.Items))
	for i := range list.Items {
		if selector.Matches(labels.Set(list.Items[i].Labels)) {
			result = append(result, &list.Items[i])
		}
	}
	return result, nil
}

func (l *clientAPIServerLister) Get(name string) (*configv1.APIServer, error) {
	obj := &configv1.APIServer{}
	if err := l.client.Get(l.ctx, types.NamespacedName{Name: name}, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// apiServerListers satisfies both configobserver.Listers (the declared parameter
// type of ObserveTLSSecurityProfile) and libapiserver.APIServerLister (what the
// type assertion inside ObserveTLSSecurityProfile requires).
// Only APIServerLister() is called by ObserveTLSSecurityProfile; the rest are stubs.
type apiServerListers struct {
	lister *clientAPIServerLister
}

func (a *apiServerListers) APIServerLister() configlistersv1.APIServerLister {
	return a.lister
}

func (a *apiServerListers) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return nil
}

func (a *apiServerListers) PreRunHasSynced() []cache.InformerSynced {
	return nil
}

// GetTLSConfigFromProfile returns a function that configures a tls.Config based on
// the provided TLS profile spec. The returned function is suitable for use with
// controller-runtime's metricsserver.Options TLSOpts field.
func GetTLSConfigFromProfile(profileSpec configv1.TLSProfileSpec) (func(*tls.Config), []string) {
	configFn, unsupportedCiphers := crcommon.NewTLSConfigFromProfile(profileSpec)
	return configFn, unsupportedCiphers
}

// FetchAPIServerTLSProfile fetches the TLS profile spec from the cluster APIServer CR.
// This is a convenience wrapper around controller-runtime-common's function.
func FetchAPIServerTLSProfile(ctx context.Context, c client.Client) (configv1.TLSProfileSpec, error) {
	return crcommon.FetchAPIServerTLSProfile(ctx, c)
}
