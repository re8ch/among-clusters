package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/re8ch/among-clusters/internal/credential"
	"github.com/re8ch/among-clusters/internal/identity"
	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/protocol"
	"github.com/re8ch/among-clusters/internal/transport"
	"github.com/re8ch/among-clusters/internal/transport/quicmtls"
	"io"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type agent struct {
	client                                                                                           kubernetes.Interface
	clusterID, tenant, trustDomain, endpoint, namespace, secretName, gatewayEndpoint, brokerEndpoint string
	key                                                                                              ed25519.PrivateKey
	sequence                                                                                         uint64
	http                                                                                             *http.Client
	confirmations                                                                                    []model.BundleConfirmation
	links                                                                                            []linkTarget
}

type linkTarget struct {
	LinkRef          string `json:"linkRef"`
	PeerRef          string `json:"peerRef"`
	Endpoint         string `json:"endpoint"`
	ExpectedSPIFFEID string `json:"expectedSPIFFEID"`
}

func main() {
	ctx := context.Background()
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	a := &agent{client: client, clusterID: must("CLUSTER_ID"), tenant: must("TENANT"), trustDomain: must("TRUST_DOMAIN"), endpoint: must("HUB_ENDPOINT"), namespace: env("POD_NAMESPACE", "among-clusters"), secretName: env("IDENTITY_SECRET", "among-clusters-agent-identity"), gatewayEndpoint: os.Getenv("GATEWAY_ENDPOINT"), brokerEndpoint: os.Getenv("BROKER_ENDPOINT"), http: &http.Client{Timeout: 10 * time.Second}}
	if err = json.Unmarshal([]byte(env("PEER_CONFIRMATIONS", "[]")), &a.confirmations); err != nil {
		log.Fatalf("PEER_CONFIRMATIONS: %v", err)
	}
	if err = json.Unmarshal([]byte(env("LINK_OBSERVATIONS", "[]")), &a.links); err != nil {
		log.Fatalf("LINK_OBSERVATIONS: %v", err)
	}
	if err = a.loadIdentity(ctx); err != nil {
		log.Fatal(err)
	}
	if token := os.Getenv("INVITATION_TOKEN"); token != "" {
		if err = a.register(ctx, os.Getenv("INVITATION_ID"), token); err != nil {
			log.Printf("registration: %v", err)
		}
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if err = a.refreshTLSMaterial(ctx); err != nil {
			log.Printf("SVID rotation: %v", err)
		}
		if err = a.heartbeat(ctx); err != nil {
			log.Printf("heartbeat: %v", err)
		}
		if err = a.publishServices(ctx); err != nil {
			log.Printf("service snapshot: %v", err)
		}
		if a.brokerEndpoint != "" {
			if err = a.pollGrants(ctx); err != nil {
				log.Printf("managed access: %v", err)
			}
		}
		for _, confirmation := range a.confirmations {
			if err = a.sendControl(ctx, "peer.bundle.confirm", confirmation); err != nil {
				log.Printf("confirm %s: %v", confirmation.PeerRef, err)
			}
		}
		for _, target := range a.links {
			if err = a.observeLink(ctx, target); err != nil {
				log.Printf("observe %s: %v", target.LinkRef, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func must(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}
func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func (a *agent) spiffeID() string { return "spiffe://" + a.trustDomain + "/cluster/" + a.clusterID }
func (a *agent) loadIdentity(ctx context.Context) error {
	s, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		m, genErr := identity.Generate(a.spiffeID(), time.Now().UTC())
		if genErr != nil {
			return genErr
		}
		s = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: a.secretName, Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters"}, Annotations: map[string]string{"peering.re8ch.com/generation": "0", "peering.re8ch.com/bundle-digest": m.BundleDigest}}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": m.CertificatePEM, "tls.key": m.PrivateKeyPEM, "bundle.pem": m.BundlePEM, "private-key": m.PrivateKey, "public-key": m.PublicKey}}
		s, err = a.client.CoreV1().Secrets(a.namespace).Create(ctx, s, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	if len(s.Data["private-key"]) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid identity key")
	}
	a.key = ed25519.PrivateKey(s.Data["private-key"])
	if err = a.refreshTLSSecret(ctx, s, time.Now().UTC()); err != nil {
		return err
	}
	a.sequence, _ = strconv.ParseUint(s.Annotations["peering.re8ch.com/generation"], 10, 64)
	return nil
}
func (a *agent) refreshTLSMaterial(ctx context.Context) error {
	s, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	return a.refreshTLSSecret(ctx, s, time.Now().UTC())
}
func (a *agent) refreshTLSSecret(ctx context.Context, s *corev1.Secret, now time.Time) error {
	needsRoot := len(s.Data["bundle.pem"]) == 0 || certificateExpiresBefore(s.Data["bundle.pem"], now.AddDate(1, 0, 0))
	needsLeaf := len(s.Data["tls.crt"]) == 0 || len(s.Data["tls.key"]) == 0 || certificateExpiresBefore(s.Data["tls.crt"], now.Add(2*time.Hour))
	if needsRoot || needsLeaf || s.Annotations["peering.re8ch.com/bundle-digest"] == "" {
		var material identity.Material
		var migrateErr error
		if needsRoot {
			material, migrateErr = identity.FromPrivateKey(a.spiffeID(), a.key, now)
		} else {
			material, migrateErr = identity.Rotate(a.spiffeID(), a.key, s.Data["bundle.pem"], now)
		}
		if migrateErr != nil {
			return migrateErr
		}
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		if s.Annotations == nil {
			s.Annotations = map[string]string{}
		}
		// Secret type is immutable. Keep legacy Opaque identity Secrets as-is while
		// adding the TLS material needed by the sovereign peering gateway.
		s.Data["tls.crt"] = material.CertificatePEM
		s.Data["tls.key"] = material.PrivateKeyPEM
		s.Data["bundle.pem"] = material.BundlePEM
		s.Data["public-key"] = material.PublicKey
		s.Annotations["peering.re8ch.com/bundle-digest"] = material.BundleDigest
		if s.Annotations["peering.re8ch.com/generation"] == "" {
			s.Annotations["peering.re8ch.com/generation"] = "0"
		}
		_, err := a.client.CoreV1().Secrets(a.namespace).Update(ctx, s, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}
func certificateExpiresBefore(value []byte, deadline time.Time) bool {
	block, _ := pem.Decode(value)
	if block == nil {
		return true
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	return err != nil || certificate.NotAfter.Before(deadline)
}
func (a *agent) registration(ctx context.Context) (model.IdentityRegistration, error) {
	s, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if err != nil {
		return model.IdentityRegistration{}, err
	}
	endpoints := []string{}
	if a.gatewayEndpoint != "" {
		endpoints = []string{a.gatewayEndpoint}
	}
	return model.IdentityRegistration{ClusterID: a.clusterID, Tenant: a.tenant, TrustDomain: a.trustDomain, SPIFFEID: a.spiffeID(), BundleDigest: s.Annotations["peering.re8ch.com/bundle-digest"], PublicKey: base64.RawStdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey)), Capabilities: []string{"service", "quic-mtls"}, GatewayEndpoints: endpoints}, nil
}
func (a *agent) register(ctx context.Context, id, token string) error {
	if id == "" {
		return fmt.Errorf("invitation ID required")
	}
	registration, err := a.registration(ctx)
	if err != nil {
		return err
	}
	identityBody, _ := json.Marshal(registration)
	proof := ed25519.Sign(a.key, identityBody)
	body, _ := json.Marshal(model.InvitationAcceptance{Token: token, Identity: registration, Proof: base64.RawStdEncoding.EncodeToString(proof)})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/v1/invitations/"+id+"/accept", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 201 && response.StatusCode != 409 {
		return responseStatusError("hub", response)
	}
	return nil
}
func (a *agent) heartbeat(ctx context.Context) error {
	services, err := a.client.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: "peering.re8ch.com/advertise=true"})
	if err != nil {
		return err
	}
	return a.sendControl(ctx, "identity.heartbeat", map[string]any{"services": len(services.Items), "observedAt": time.Now().UTC()})
}

func splitValues(value string) []string {
	result := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func (a *agent) advertisedServices(ctx context.Context) ([]model.AdvertisedService, error) {
	list, err := a.client.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: "peering.re8ch.com/advertise=true"})
	if err != nil {
		return nil, err
	}
	result := make([]model.AdvertisedService, 0, len(list.Items))
	for _, service := range list.Items {
		annotations := service.Annotations
		protocolName := annotations["peering.re8ch.com/protocol"]
		class := annotations["peering.re8ch.com/service-class"]
		policy := annotations["peering.re8ch.com/policy-ref"]
		targets := splitValues(annotations["peering.re8ch.com/target-peers"])
		if protocolName == "" || class == "" || policy == "" || len(targets) == 0 {
			continue
		}
		var selected *corev1.ServicePort
		portName := annotations["peering.re8ch.com/port-name"]
		for index := range service.Spec.Ports {
			if selected == nil || (portName != "" && service.Spec.Ports[index].Name == portName) {
				selected = &service.Spec.Ports[index]
			}
			if portName != "" && service.Spec.Ports[index].Name == portName {
				break
			}
		}
		if selected == nil {
			continue
		}
		ttl, parseErr := strconv.ParseInt(annotations["peering.re8ch.com/ttl-seconds"], 10, 64)
		if parseErr != nil || ttl < 30 {
			ttl = 60
		}
		generation := service.Generation
		if generation < 1 {
			generation = 1
		}
		gatewayTarget := fmt.Sprintf("%s.%s.svc:%d", service.Name, service.Namespace, selected.Port)
		if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != corev1.ClusterIPNone {
			gatewayTarget = net.JoinHostPort(service.Spec.ClusterIP, strconv.Itoa(int(selected.Port)))
		}
		result = append(result, model.AdvertisedService{Name: service.Name, Namespace: service.Namespace, ServiceClass: class, Protocol: protocolName, Port: selected.Port, TargetPeers: targets, TTLSeconds: ttl, PolicyRef: policy, Generation: generation, GatewayTarget: gatewayTarget})
	}
	return result, nil
}

func (a *agent) publishServices(ctx context.Context) error {
	services, err := a.advertisedServices(ctx)
	if err != nil {
		return err
	}
	if err = a.writeGatewayRoutes(ctx, services); err != nil {
		return err
	}
	return a.sendControl(ctx, "service.snapshot", model.ServiceSnapshot{Services: services})
}
func (a *agent) writeGatewayRoutes(ctx context.Context, services []model.AdvertisedService) error {
	routes := []map[string]any{}
	for _, service := range services {
		target := service.GatewayTarget
		if target == "" {
			target = fmt.Sprintf("%s.%s.svc:%d", service.Name, service.Namespace, service.Port)
		}
		routes = append(routes, map[string]any{"serviceIdentity": fmt.Sprintf("spiffe://%s/ns/%s/service/%s", a.trustDomain, service.Namespace, service.Name), "target": target, "targetPeers": service.TargetPeers})
	}
	data, _ := json.Marshal(routes)
	desired := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "among-clusters-service-routes", Namespace: a.namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters"}}, Data: map[string]string{"exports.json": string(data)}}
	current, err := a.client.CoreV1().ConfigMaps(a.namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = a.client.CoreV1().ConfigMaps(a.namespace).Create(ctx, desired, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	desired.ResourceVersion = current.ResourceVersion
	_, err = a.client.CoreV1().ConfigMaps(a.namespace).Update(ctx, desired, metav1.UpdateOptions{})
	return err
}

func grantResourceName(name string) string {
	value := "among-clusters-" + strings.ToLower(name)
	if len(value) > 63 {
		value = value[:63]
	}
	return strings.Trim(value, "-")
}
func (a *agent) pollGrants(ctx context.Context) error {
	body, err := a.sendControlResponse(ctx, "grant.poll", map[string]any{})
	if err != nil {
		return err
	}
	var snapshot model.GrantSnapshot
	if err = json.Unmarshal(body, &snapshot); err != nil {
		return err
	}
	for _, grant := range snapshot.Grants {
		if err = a.reconcileGrant(ctx, grant); err != nil {
			return fmt.Errorf("grant %s: %w", grant.Name, err)
		}
	}
	return nil
}
func (a *agent) reconcileGrant(ctx context.Context, grant model.GrantInstruction) error {
	name := grantResourceName(grant.Name)
	if grant.Revoked || !time.Now().Before(grant.ExpiresAt) {
		_ = a.client.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{})
		_ = a.client.RbacV1().ClusterRoles().Delete(ctx, name, metav1.DeleteOptions{})
		for _, namespace := range grant.Namespaces {
			_ = a.client.RbacV1().RoleBindings(namespace).Delete(ctx, name, metav1.DeleteOptions{})
			_ = a.client.RbacV1().Roles(namespace).Delete(ctx, name, metav1.DeleteOptions{})
		}
		_ = a.client.CoreV1().ServiceAccounts(a.namespace).Delete(ctx, name, metav1.DeleteOptions{})
		return a.revokeCredential(ctx, grant)
	}
	approval, err := a.client.CoreV1().ConfigMaps(a.namespace).Get(ctx, "among-clusters-approval-"+grant.Name, metav1.GetOptions{})
	if err != nil {
		return errors.New("local customer approval required")
	}
	if approval.Data["grantRef"] != grant.Name || approval.Data["generation"] != strconv.FormatInt(grant.Generation, 10) || approval.Data["approved"] != "true" {
		return errors.New("local customer approval invalid")
	}
	labels := map[string]string{"app.kubernetes.io/managed-by": "among-clusters", "peering.re8ch.com/grant": grant.Name}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: a.namespace, Labels: labels}}
	if _, err := a.client.CoreV1().ServiceAccounts(a.namespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	rules := make([]rbacv1.PolicyRule, 0, len(grant.Rules))
	for _, rule := range grant.Rules {
		rules = append(rules, rbacv1.PolicyRule{APIGroups: rule.APIGroups, Resources: rule.Resources, Verbs: rule.Verbs})
	}
	if grant.Scope == "Cluster" {
		role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}, Rules: rules}
		if _, err := a.client.RbacV1().ClusterRoles().Create(ctx, role, metav1.CreateOptions{}); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return err
			}
			current, getErr := a.client.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			current.Rules = rules
			if _, err = a.client.RbacV1().ClusterRoles().Update(ctx, current, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
		binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: name, Namespace: a.namespace}}}
		if _, err := a.client.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	} else if grant.Scope != "" && grant.Scope != "Namespaced" {
		return fmt.Errorf("unsupported grant scope %q", grant.Scope)
	}
	for _, namespace := range grant.Namespaces {
		if grant.Scope == "Cluster" {
			break
		}
		role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels}, Rules: rules}
		if _, err := a.client.RbacV1().Roles(namespace).Create(ctx, role, metav1.CreateOptions{}); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return err
			}
			current, getErr := a.client.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			current.Rules = rules
			if _, err = a.client.RbacV1().Roles(namespace).Update(ctx, current, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
		binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: name}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: name, Namespace: a.namespace}}}
		if _, err := a.client.RbacV1().RoleBindings(namespace).Create(ctx, binding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	seconds := int64(time.Until(grant.ExpiresAt).Seconds())
	if seconds > 3600 {
		seconds = 3600
	}
	if seconds < 600 {
		return errors.New("grant expires too soon")
	}
	token, err := a.client.CoreV1().ServiceAccounts(a.namespace).CreateToken(ctx, name, &authv1.TokenRequest{Spec: authv1.TokenRequestSpec{ExpirationSeconds: &seconds}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	ca, err := a.client.CoreV1().ConfigMaps(a.namespace).Get(ctx, "kube-root-ca.crt", metav1.GetOptions{})
	if err != nil {
		return err
	}
	return a.uploadCredential(ctx, grant, model.CredentialPayload{Token: token.Status.Token, CertificateAuthority: ca.Data["ca.crt"], Server: grant.ProxyURL, TLSServerName: env("KUBERNETES_TLS_SERVER_NAME", "kubernetes.default.svc"), ExpiresAt: token.Status.ExpirationTimestamp.Time})
}
func (a *agent) revokeCredential(ctx context.Context, grant model.GrantInstruction) error {
	raw, _ := json.Marshal(map[string]string{"tenant": a.tenant, "clusterID": a.clusterID, "grantRef": grant.Name})
	now := time.Now().UTC()
	message := model.ControlMessage{Issuer: a.spiffeID(), Audience: "credential-broker", Generation: a.sequence + 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: fmt.Sprintf("%s-revoke-%d", a.clusterID, a.sequence+1), Type: "credential.revoke", Payload: raw}
	if err := protocol.Sign(&message, a.key); err != nil {
		return err
	}
	body, _ := json.Marshal(message)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(a.brokerEndpoint, "/")+"/v1/credentials/revoke", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 204 && response.StatusCode != 404 {
		return fmt.Errorf("credential revoke returned %s", response.Status)
	}
	return nil
}
func (a *agent) uploadCredential(ctx context.Context, grant model.GrantInstruction, payload model.CredentialPayload) error {
	response, err := a.http.Get(strings.TrimSuffix(a.brokerEndpoint, "/") + "/v1/public-key")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var keyDoc struct {
		PublicKey string `json:"publicKey"`
	}
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&keyDoc) != nil {
		return errors.New("credential broker public key unavailable")
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(keyDoc.PublicKey)
	if err != nil {
		return err
	}
	envelope, err := credential.Encrypt(publicKey, payload)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(map[string]any{"tenant": a.tenant, "clusterID": a.clusterID, "grantRef": grant.Name, "envelope": envelope})
	now := time.Now().UTC()
	message := model.ControlMessage{Issuer: a.spiffeID(), Audience: "credential-broker", Generation: a.sequence + 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: fmt.Sprintf("%s-broker-%d", a.clusterID, a.sequence+1), Type: "credential.store", Payload: raw}
	if err = protocol.Sign(&message, a.key); err != nil {
		return err
	}
	encoded, _ := json.Marshal(message)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(a.brokerEndpoint, "/")+"/v1/credentials", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	stored, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer stored.Body.Close()
	var output struct {
		CredentialRef string `json:"credentialRef"`
	}
	if stored.StatusCode != 201 || json.NewDecoder(stored.Body).Decode(&output) != nil {
		return fmt.Errorf("credential broker returned %s", stored.Status)
	}
	return a.sendControl(ctx, "grant.fulfilled", model.GrantFulfillment{GrantRef: grant.Name, CredentialRef: output.CredentialRef, RenewedAt: now})
}

func (a *agent) sendControl(ctx context.Context, messageType string, payloadValue any) error {
	_, err := a.sendControlResponse(ctx, messageType, payloadValue)
	return err
}
func (a *agent) sendControlResponse(ctx context.Context, messageType string, payloadValue any) ([]byte, error) {
	payload, _ := json.Marshal(payloadValue)
	a.sequence++
	now := time.Now().UTC()
	message := model.ControlMessage{Issuer: a.spiffeID(), Audience: "hub", Generation: a.sequence, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: fmt.Sprintf("%s-%d", a.clusterID, a.sequence), Type: messageType, Payload: payload}
	if err := protocol.Sign(&message, a.key); err != nil {
		return nil, err
	}
	body, _ := json.Marshal(message)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/peers/%s/%s/messages", a.endpoint, a.tenant, a.clusterID), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 202 && response.StatusCode != 200 {
		return nil, responseStatusError("hub", response)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil {
		return nil, readErr
	}
	secret, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	secret.Annotations["peering.re8ch.com/generation"] = strconv.FormatUint(a.sequence, 10)
	_, err = a.client.CoreV1().Secrets(a.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return responseBody, err
}

func responseStatusError(upstream string, response *http.Response) error {
	detail, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	message := strings.TrimSpace(string(detail))
	if message == "" {
		return fmt.Errorf("%s returned %s", upstream, response.Status)
	}
	return fmt.Errorf("%s returned %s: %s", upstream, response.Status, message)
}

func (a *agent) observeLink(ctx context.Context, target linkTarget) error {
	observation := model.LinkObservation{LinkRef: target.LinkRef, PeerRef: target.PeerRef, LastHandshakeAt: time.Now().UTC()}
	start := time.Now()
	driver, err := a.driver(target.ExpectedSPIFFEID)
	if err == nil {
		var result transport.Observation
		result, err = driver.Probe(ctx, transport.Peer{ID: target.PeerRef, Endpoints: []string{target.Endpoint}})
		observation.Ready = result.Ready
		observation.LatencyMillis = result.Latency.Milliseconds()
		observation.LastHandshakeAt = result.ObservedAt.UTC()
		if observation.Ready && !a.persistentSessionReady(ctx, target.ExpectedSPIFFEID) {
			observation.Ready = false
			observation.Reason = "PersistentSessionUnavailable"
		}
	}
	if err != nil {
		observation.Ready = false
		observation.Reason = "TransportError"
		observation.LatencyMillis = time.Since(start).Milliseconds()
	}
	return a.sendControl(ctx, "link.observe", observation)
}

func (a *agent) persistentSessionReady(ctx context.Context, identity string) bool {
	endpoint := strings.TrimSuffix(env("GATEWAY_READINESS_ENDPOINT", "http://among-clusters-gateway:8080"), "/")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/readyz?identity="+url.QueryEscape(identity), nil)
	if err != nil {
		return false
	}
	response, err := a.http.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusNoContent
}

func (a *agent) driver(expectedSPIFFEID string) (*quicmtls.Driver, error) {
	secret, err := a.client.CoreV1().Secrets(a.namespace).Get(context.Background(), a.secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, err
	}
	bundle, err := os.ReadFile(env("PEER_BUNDLE_FILE", "/peer-bundles/ca.crt"))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return nil, fmt.Errorf("peer bundle is invalid")
	}
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"among-clusters/1"}, InsecureSkipVerify: true} //nolint:gosec -- URI SAN and private root are verified below.
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("peer certificate missing")
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		if _, verifyErr := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); verifyErr != nil {
			return verifyErr
		}
		if len(state.PeerCertificates[0].URIs) != 1 || strings.TrimSuffix(state.PeerCertificates[0].URIs[0].String(), "/") != strings.TrimSuffix(expectedSPIFFEID, "/") {
			return fmt.Errorf("unexpected peer SPIFFE identity")
		}
		return nil
	}
	return quicmtls.New(config), nil
}
