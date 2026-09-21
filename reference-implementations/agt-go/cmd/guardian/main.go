// Command guardian serves the ACS Guardian with AGT as its policy engine,
// over HTTP: POST /acs, GET /healthz and GET /readyz.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/acs"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/agtbridge"
	"github.com/GenAI-Security-Project/agent-control-standard/reference-implementations/agt-go/guardian"
)

type fileConfig struct {
	Server struct {
		Host              string        `koanf:"host"`
		Port              string        `koanf:"port"`
		ReadHeaderTimeout time.Duration `koanf:"read_header_timeout"`
		ReadTimeout       time.Duration `koanf:"read_timeout"`
		WriteTimeout      time.Duration `koanf:"write_timeout"`
		IdleTimeout       time.Duration `koanf:"idle_timeout"`
		ShutdownGrace     time.Duration `koanf:"shutdown_grace"`
	} `koanf:"server"`
	Policy struct {
		DeploymentDir   string            `koanf:"deployment_dir"`
		Manifest        string            `koanf:"manifest"`
		Mapping         string            `koanf:"mapping"`
		AskSubstitution string            `koanf:"ask_substitution"`
		ToolAliases     map[string]string `koanf:"tool_aliases"`
	} `koanf:"policy"`
	Security struct {
		HMACKeyID      string `koanf:"hmac_key_id"`
		HMACSecretFile string `koanf:"hmac_secret_file"`
	} `koanf:"security"`
	Audit struct {
		EnvelopeLog string `koanf:"envelope_log"`
		EventLog    string `koanf:"event_log"`
	} `koanf:"audit"`
	Protocol struct {
		OnDecisionFailure string        `koanf:"on_decision_failure"`
		DecisionTimeout   time.Duration `koanf:"decision_timeout"`
		SkewWindow        time.Duration `koanf:"skew_window"`
	} `koanf:"protocol"`
	Limits struct {
		MaxSessions         int           `koanf:"max_sessions"`
		MaxEntries          int           `koanf:"max_entries"`
		MaxReservations     int           `koanf:"max_reservations"`
		MaxSkillApprovals   int           `koanf:"max_skill_approvals"`
		MaxEngineCalls      int           `koanf:"max_engine_calls"`
		MaxPolicyStateBytes int           `koanf:"max_policy_state_bytes"`
		MaxBodyBytes        int64         `koanf:"max_body_bytes"`
		MaxDeferrals        int           `koanf:"max_deferrals"`
		SessionRetention    time.Duration `koanf:"session_retention"`
	} `koanf:"limits"`
}

type config struct {
	path              string
	host, port        string
	posture           acs.FailurePosture
	envelopeLog       string
	eventLog          string
	keyID             string
	secret            []byte
	policyDir         string
	manifest          string
	mapping           string
	askSubstitution   guardian.AskSubstitution
	toolAliases       map[string]string
	maxSessions       int
	maxEntries        int
	maxReservations   int
	maxSkillApprovals int
	maxEngineCalls    int
	maxStateBytes     int
	maxBodyBytes      int64
	maxDeferrals      int
	decisionTimeout   time.Duration
	skewWindow        time.Duration
	sessionRetention  time.Duration
	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	idleTimeout       time.Duration
	shutdownGrace     time.Duration
}

func main() {
	if err := run(os.Args[1:], os.Environ()); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "guardian:", err)
		os.Exit(1)
	}
}

func loadConfig(args, environ []string) (config, error) {
	flags := flag.NewFlagSet("guardian", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "path to the Guardian YAML configuration")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *configPath == "" {
		return config{}, errors.New("--config is required")
	}
	absConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		return config{}, fmt.Errorf("resolve configuration path: %w", err)
	}

	k := koanf.New(".")
	if err := k.Load(file.Provider(absConfigPath), yaml.Parser()); err != nil {
		return config{}, fmt.Errorf("load configuration %q: %w", absConfigPath, err)
	}
	if err := k.Load(env.Provider(".", env.Opt{
		Prefix: "ACS__",
		TransformFunc: func(key, value string) (string, any) {
			path := strings.ToLower(strings.TrimPrefix(key, "ACS__"))
			return strings.ReplaceAll(path, "__", "."), value
		},
		EnvironFunc: func() []string { return environ },
	}), nil); err != nil {
		return config{}, fmt.Errorf("load ACS__ environment overrides: %w", err)
	}

	var raw fileConfig
	decoder := &mapstructure.DecoderConfig{
		Result:           &raw,
		TagName:          "koanf",
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
	}
	if err := k.UnmarshalWithConf("", &raw, koanf.UnmarshalConf{Tag: "koanf", DecoderConfig: decoder}); err != nil {
		return config{}, fmt.Errorf("decode configuration %q: %w", absConfigPath, err)
	}

	base := filepath.Dir(absConfigPath)
	policyDir, err := resolvePath(base, raw.Policy.DeploymentDir)
	if err != nil {
		return config{}, fmt.Errorf("policy.deployment_dir: %w", err)
	}
	manifest, err := policyPath("policy.manifest", raw.Policy.Manifest)
	if err != nil {
		return config{}, err
	}
	mapping, err := policyPath("policy.mapping", raw.Policy.Mapping)
	if err != nil {
		return config{}, err
	}
	secretPath, err := resolvePath(base, raw.Security.HMACSecretFile)
	if err != nil {
		return config{}, fmt.Errorf("security.hmac_secret_file: %w", err)
	}
	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return config{}, fmt.Errorf("read security.hmac_secret_file %q: %w", secretPath, err)
	}
	envelopeLog, err := resolvePath(base, raw.Audit.EnvelopeLog)
	if err != nil {
		return config{}, fmt.Errorf("audit.envelope_log: %w", err)
	}
	eventLog, err := resolvePath(base, raw.Audit.EventLog)
	if err != nil {
		return config{}, fmt.Errorf("audit.event_log: %w", err)
	}

	c := config{
		path: absConfigPath, host: raw.Server.Host, port: raw.Server.Port,
		posture:     acs.FailurePosture(raw.Protocol.OnDecisionFailure),
		envelopeLog: envelopeLog, eventLog: eventLog,
		keyID: raw.Security.HMACKeyID, secret: secret,
		policyDir: policyDir, manifest: manifest, mapping: mapping,
		askSubstitution: guardian.AskSubstitution(raw.Policy.AskSubstitution),
		toolAliases:     raw.Policy.ToolAliases,
		maxSessions:     raw.Limits.MaxSessions, maxEntries: raw.Limits.MaxEntries, maxReservations: raw.Limits.MaxReservations,
		maxSkillApprovals: raw.Limits.MaxSkillApprovals, maxEngineCalls: raw.Limits.MaxEngineCalls,
		maxStateBytes: raw.Limits.MaxPolicyStateBytes, maxBodyBytes: raw.Limits.MaxBodyBytes, maxDeferrals: raw.Limits.MaxDeferrals,
		decisionTimeout: raw.Protocol.DecisionTimeout, skewWindow: raw.Protocol.SkewWindow,
		sessionRetention:  raw.Limits.SessionRetention,
		readHeaderTimeout: raw.Server.ReadHeaderTimeout, readTimeout: raw.Server.ReadTimeout,
		writeTimeout: raw.Server.WriteTimeout, idleTimeout: raw.Server.IdleTimeout, shutdownGrace: raw.Server.ShutdownGrace,
	}
	if err := c.validate(); err != nil {
		return config{}, err
	}
	return c, nil
}

func resolvePath(base, value string) (string, error) {
	if value == "" {
		return "", errors.New("must not be empty")
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	return filepath.Join(base, value), nil
}

func policyPath(name, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%s must not be empty", name)
	}
	path := filepath.ToSlash(value)
	if filepath.IsAbs(value) || !fs.ValidPath(path) || path == "." {
		return "", fmt.Errorf("%s must be a non-empty path inside policy.deployment_dir", name)
	}
	return path, nil
}

func (c config) validate() error {
	var errs []error
	if c.host == "" {
		errs = append(errs, errors.New("server.host must not be empty"))
	}
	if c.port == "" {
		errs = append(errs, errors.New("server.port must not be empty"))
	}
	if c.keyID == "" {
		errs = append(errs, errors.New("security.hmac_key_id must not be empty"))
	}
	if len(c.secret) < guardian.MinHMACSecretBytes {
		errs = append(errs, fmt.Errorf("security.hmac_secret_file must hold at least %d bytes of shared keying material", guardian.MinHMACSecretBytes))
	}
	if c.posture != acs.FailureProceed && c.posture != acs.FailureDeny {
		errs = append(errs, fmt.Errorf("protocol.on_decision_failure must be %q or %q", acs.FailureProceed, acs.FailureDeny))
	}
	if c.askSubstitution != guardian.AskSubstitutionNone && c.askSubstitution != guardian.AskSubstitutionDeny && c.askSubstitution != guardian.AskSubstitutionDefer {
		errs = append(errs, errors.New("policy.ask_substitution must be none, deny or defer"))
	}
	if c.decisionTimeout <= 0 {
		errs = append(errs, errors.New("protocol.decision_timeout must be positive"))
	}
	if c.skewWindow <= 0 {
		errs = append(errs, errors.New("protocol.skew_window must be positive"))
	}
	minimumRetention := c.skewWindow + c.skewWindow
	if minimumRetention < c.skewWindow || c.sessionRetention < minimumRetention {
		errs = append(errs, errors.New("limits.session_retention must be at least twice protocol.skew_window"))
	}
	if c.writeTimeout <= c.decisionTimeout {
		errs = append(errs, errors.New("server.write_timeout must exceed protocol.decision_timeout, or a decision in time is cut off before it is sent"))
	}
	for name, value := range map[string]int{
		"limits.max_sessions":           c.maxSessions,
		"limits.max_entries":            c.maxEntries,
		"limits.max_reservations":       c.maxReservations,
		"limits.max_skill_approvals":    c.maxSkillApprovals,
		"limits.max_engine_calls":       c.maxEngineCalls,
		"limits.max_policy_state_bytes": c.maxStateBytes,
		"limits.max_deferrals":          c.maxDeferrals,
	} {
		if value <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	if c.maxBodyBytes <= 0 {
		errs = append(errs, errors.New("limits.max_body_bytes must be positive"))
	}
	for name, value := range map[string]time.Duration{
		"server.read_header_timeout": c.readHeaderTimeout,
		"server.read_timeout":        c.readTimeout,
		"server.idle_timeout":        c.idleTimeout,
		"server.shutdown_grace":      c.shutdownGrace,
	} {
		if value <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	return errors.Join(errs...)
}

func run(args, environ []string) error {
	c, err := loadConfig(args, environ)
	if err != nil {
		return err
	}
	signer, err := guardian.NewHMACSigner(guardian.HMACKey{ID: c.keyID, Secret: c.secret})
	if err != nil {
		return err
	}
	audit, err := guardian.NewJSONLAuditLog(c.envelopeLog, c.eventLog, func(err error) {
		fmt.Fprintln(os.Stderr, "guardian: audit log:", err)
	})
	if err != nil {
		return err
	}
	auditClosed := false
	defer func() {
		if auditClosed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.shutdownGrace)
		defer cancel()
		_ = audit.Close(ctx)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	engine, err := agtbridge.New(ctx, os.DirFS(c.policyDir), c.manifest, c.mapping, agtbridge.Options{ToolAliases: c.toolAliases})
	if err != nil {
		return err
	}
	g, err := guardian.New(guardian.Config{
		Engine: engine, Signer: signer, AuditLog: audit,
		MaxSessions: c.maxSessions, MaxEntries: c.maxEntries, MaxReservations: c.maxReservations, MaxSkillApprovals: c.maxSkillApprovals, SessionRetention: c.sessionRetention,
		MaxEngineCalls: c.maxEngineCalls, MaxPolicyStateBytes: c.maxStateBytes,
		MaxDeferrals:    c.maxDeferrals,
		AskSubstitution: c.askSubstitution,
		DecisionTimeout: c.decisionTimeout, SkewWindow: c.skewWindow,
		OnDecisionFailure: c.posture, MaxBodyBytes: c.maxBodyBytes,
	})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(c.host, c.port))
	if err != nil {
		return err
	}
	endpoints := &guardian.Endpoints{}
	server := &http.Server{
		Handler: endpoints, ReadHeaderTimeout: c.readHeaderTimeout, ReadTimeout: c.readTimeout,
		WriteTimeout: c.writeTimeout, IdleTimeout: c.idleTimeout,
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	endpoints.Ready(g)
	fmt.Printf("Guardian listening at http://%s/acs\n", listener.Addr())
	fmt.Printf("Configuration: %s\n", c.path)
	fmt.Printf("Policy deployment: %s\n", c.policyDir)
	fmt.Printf("Envelope log: %s\n", c.envelopeLog)
	fmt.Printf("Event log: %s\n", c.eventLog)
	fmt.Printf("Failure posture: %s\n", c.posture)

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	if err := shutdown(server, g, c.shutdownGrace); err != nil {
		return err
	}
	auditGrace, auditCancel := context.WithTimeout(context.Background(), c.shutdownGrace)
	err = audit.Close(auditGrace)
	auditCancel()
	auditClosed = true
	if err != nil {
		return err
	}
	return nil
}

func shutdown(server *http.Server, g *guardian.Guardian, grace time.Duration) error {
	serverContext, stopServer := context.WithCancel(context.Background())
	closed := make(chan error, 1)
	go func() { closed <- server.Shutdown(serverContext) }()

	decisionContext, stopDecisions := context.WithTimeout(context.Background(), grace)
	guardianErr := g.Shutdown(decisionContext)
	stopDecisions()
	if guardianErr != nil && !errors.Is(guardianErr, context.DeadlineExceeded) {
		stopServer()
		_ = server.Close()
		return guardianErr
	}

	deliveryContext, stopDelivery := context.WithTimeout(context.Background(), grace)
	defer stopDelivery()
	select {
	case err := <-closed:
		stopServer()
		return err
	case <-deliveryContext.Done():
		stopServer()
		if err := server.Close(); err != nil {
			return err
		}
		<-closed
		return nil
	}
}
