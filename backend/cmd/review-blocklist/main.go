package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var domainLabel = regexp.MustCompile(`^[a-z0-9-]+$`)
var outputKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$`)

const referenceURL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt"

type reviewReport struct {
	Date                     string            `json:"date"`
	Window                   string            `json:"window,omitempty"`
	Timezone                 string            `json:"timezone"`
	From                     time.Time         `json:"from"`
	To                       time.Time         `json:"to"`
	GeneratedAt              time.Time         `json:"generated_at"`
	MatchCriteria            string            `json:"match_criteria"`
	ReferenceVersion         string            `json:"reference_version,omitempty"`
	ReferenceFile            string            `json:"reference_file"`
	ReferenceSHA256          string            `json:"reference_sha256"`
	InstalledSnapshotFile    string            `json:"installed_snapshot_file"`
	InstalledSnapshotSHA256  string            `json:"installed_snapshot_sha256"`
	MergedSourceFile         string            `json:"merged_source_file"`
	MergedSourceSHA256       string            `json:"merged_source_sha256"`
	MergedDomainCount        int               `json:"merged_domain_count"`
	SuccessfulEvents         int64             `json:"successful_events"`
	UnmatchableEventsSkipped int64             `json:"unmatchable_events_skipped"`
	UnmatchableDomainCount   int               `json:"unmatchable_domain_count"`
	UnmatchableDomains       []string          `json:"unmatchable_domains"`
	DistinctDomainsServed    int               `json:"distinct_domains_served"`
	ReferenceMatches         int               `json:"reference_matches"`
	AlreadyInstalled         int               `json:"already_installed"`
	Candidates               []string          `json:"candidates"`
	CandidateProbeDomains    map[string]string `json:"candidate_probe_domains,omitempty"`
}

func main() {
	defaultLocation, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		fatalf("load local timezone: %v", err)
	}
	dateFlag := flag.String("date", "", "local calendar date to review (YYYY-MM-DD; defaults to today in Asia/Kolkata)")
	lookbackFlag := flag.Duration("lookback", 0, "rolling lookback window, for example 48h; mutually exclusive with --date")
	outputKeyFlag := flag.String("output-key", "", "safe filename key for candidate/report files")
	referenceFlag := flag.String("reference", "../outputs/hagezi-pro-plus-onlydomains.txt", "refreshed domains-only reference list")
	refreshFlag := flag.Bool("refresh-reference", false, "download and validate the latest HaGeZi Pro++ reference before reviewing")
	installedFlag := flag.String("installed", "../outputs/installed-pro-plus-onlydomains.txt", "domain snapshot corresponding to the blocklist currently on the ESP32")
	outDirFlag := flag.String("out-dir", "../outputs/candidates", "private directory for candidate list and report")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("unexpected arguments: %s", strings.Join(flag.Args(), " "))
	}

	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		fatalf("DATABASE_URL is not set; load backend/.env.local before running this command")
	}

	date := strings.TrimSpace(*dateFlag)
	lookback := *lookbackFlag
	if lookback < 0 || lookback > 30*24*time.Hour {
		fatalf("--lookback cannot be negative or exceed 30 days")
	}
	if lookback > 0 && date != "" {
		fatalf("--date and --lookback cannot be used together")
	}
	var from, to time.Time
	window := ""
	outputKey := strings.TrimSpace(*outputKeyFlag)
	if lookback > 0 {
		to = time.Now().UTC()
		from = to.Add(-lookback)
		date = to.In(defaultLocation).Format("2006-01-02")
		window = fmt.Sprintf("rolling %s ending %s", lookback, to.Format(time.RFC3339))
		if outputKey == "" {
			durationKey := strings.NewReplacer(".", "p", "+", "", "-", "m").Replace(lookback.String())
			outputKey = fmt.Sprintf("window-%s-ending-%s", durationKey, to.Format("20060102T150405Z"))
		}
	} else {
		if date == "" {
			date = time.Now().In(defaultLocation).Format("2006-01-02")
		}
		localStart, err := time.ParseInLocation("2006-01-02", date, defaultLocation)
		if err != nil {
			fatalf("invalid --date %q; use YYYY-MM-DD", date)
		}
		from = localStart.UTC()
		to = localStart.AddDate(0, 0, 1).UTC()
		window = fmt.Sprintf("local day %s (%s)", date, defaultLocation.String())
		if outputKey == "" {
			outputKey = date
		}
	}
	if !outputKeyPattern.MatchString(outputKey) {
		fatalf("invalid --output-key; use up to 96 letters, numbers, dots, underscores, or hyphens")
	}

	referencePath, err := filepath.Abs(*referenceFlag)
	if err != nil {
		fatalf("resolve reference path: %v", err)
	}
	if *refreshFlag {
		if err := refreshReference(referencePath); err != nil {
			fatalf("refresh reference list: %v", err)
		}
	}
	installedPath, err := filepath.Abs(*installedFlag)
	if err != nil {
		fatalf("resolve installed snapshot path: %v", err)
	}
	outDir, err := filepath.Abs(*outDirFlag)
	if err != nil {
		fatalf("resolve output directory: %v", err)
	}
	reference, referenceVersion, referenceDigest, err := readDomainFile(referencePath)
	if err != nil {
		fatalf("read reference list: %v", err)
	}
	installed, _, installedDigest, err := readDomainFile(installedPath)
	if err != nil {
		fatalf("read installed snapshot: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		fatalf("connect to PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fatalf("ping PostgreSQL: %v", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT domain
		FROM dns_events
		WHERE occurred_at >= $1 AND occurred_at < $2
		  AND action = 'forwarded'
		  AND outcome = 'upstream_response'
		  AND response_code = 0
		  AND domain <> ''`, from, to)
	if err != nil {
		fatalf("query successful forwarded DNS events: %v", err)
	}
	served := make(map[string]struct{})
	unmatchableDomains := make(map[string]struct{})
	var successfulEvents int64
	var unmatchableEventsSkipped int64
	for rows.Next() {
		var rawDomain string
		if err := rows.Scan(&rawDomain); err != nil {
			rows.Close()
			fatalf("read successful DNS event: %v", err)
		}
		domain, err := canonicalDomain(rawDomain)
		if err != nil {
			unmatchableEventsSkipped++
			unmatchableDomains[rawDomain] = struct{}{}
			continue
		}
		successfulEvents++
		served[domain] = struct{}{}
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		fatalf("finish reading DNS events: %v", rowsErr)
	}

	candidateSet := make(map[string]struct{})
	unmatchableDomainList := make([]string, 0, len(unmatchableDomains))
	for domain := range unmatchableDomains {
		unmatchableDomainList = append(unmatchableDomainList, domain)
	}
	sort.Strings(unmatchableDomainList)
	referenceMatches, alreadyInstalled := 0, 0
	for domain := range served {
		if parent := findInstalledCover(domain, installed); parent != "" {
			if findReferenceCover(domain, reference) != "" {
				referenceMatches++
				alreadyInstalled++
			}
			continue
		}
		matchedReference := findReferenceCover(domain, reference)
		if matchedReference == "" {
			continue
		}
		referenceMatches++
		candidateSet[matchedReference] = struct{}{}
	}
	candidates := make([]string, 0, len(candidateSet))
	for domain := range candidateSet {
		candidates = append(candidates, domain)
	}
	sort.Strings(candidates)
	candidateProbeDomains := make(map[string]string, len(candidates))
	servedDomains := make([]string, 0, len(served))
	for domain := range served {
		servedDomains = append(servedDomains, domain)
	}
	sort.Strings(servedDomains)
	for _, domain := range servedDomains {
		matchedReference := findReferenceCover(domain, reference)
		if _, isCandidate := candidateSet[matchedReference]; isCandidate {
			if _, alreadySelected := candidateProbeDomains[matchedReference]; !alreadySelected {
				candidateProbeDomains[matchedReference] = domain
			}
		}
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		fatalf("create output directory: %v", err)
	}
	if err := os.Chmod(outDir, 0o700); err != nil {
		fatalf("secure output directory: %v", err)
	}
	candidatePath := filepath.Join(outDir, "served-domains-"+outputKey+".txt")
	reportPath := filepath.Join(outDir, "served-domains-"+outputKey+".report.json")
	mergedPath := filepath.Join(outDir, "blocklist-source-"+outputKey+".txt")

	var candidateText strings.Builder
	fmt.Fprintf(&candidateText, "# Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&candidateText, "# Date: %s (%s)\n", date, defaultLocation.String())
	candidateText.WriteString("# Source: successful forwarded DNS responses with RCODE NOERROR\n")
	fmt.Fprintf(&candidateText, "# Reference version: %s\n", referenceVersion)
	fmt.Fprintf(&candidateText, "# Candidate domains: %d\n", len(candidates))
	for _, domain := range candidates {
		candidateText.WriteString(domain)
		candidateText.WriteByte('\n')
	}

	mergedDomains := make([]string, 0, len(installed)+len(candidates))
	for domain := range installed {
		mergedDomains = append(mergedDomains, domain)
	}
	mergedDomains = append(mergedDomains, candidates...)
	sort.Strings(mergedDomains)
	var mergedText strings.Builder
	fmt.Fprintf(&mergedText, "# Candidate blocklist source generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&mergedText, "# Base snapshot: %s\n", installedPath)
	fmt.Fprintf(&mergedText, "# Daily candidates from reference version: %s\n", referenceVersion)
	fmt.Fprintf(&mergedText, "# Domain count: %d\n", len(mergedDomains))
	for _, domain := range mergedDomains {
		mergedText.WriteString(domain)
		mergedText.WriteByte('\n')
	}
	mergedDigest := sha256.Sum256([]byte(mergedText.String()))

	report := reviewReport{
		Date:                     date,
		Window:                   window,
		Timezone:                 defaultLocation.String(),
		From:                     from,
		To:                       to,
		GeneratedAt:              time.Now().UTC(),
		MatchCriteria:            "served successfully (action=forwarded, outcome=upstream_response, response_code=0) AND covered by a domain in the refreshed reference list; candidates are the closest matching reference domains not already covered by the installed list",
		ReferenceVersion:         referenceVersion,
		ReferenceFile:            referencePath,
		ReferenceSHA256:          referenceDigest,
		InstalledSnapshotFile:    installedPath,
		InstalledSnapshotSHA256:  installedDigest,
		MergedSourceFile:         mergedPath,
		MergedSourceSHA256:       hex.EncodeToString(mergedDigest[:]),
		MergedDomainCount:        len(mergedDomains),
		SuccessfulEvents:         successfulEvents,
		UnmatchableEventsSkipped: unmatchableEventsSkipped,
		UnmatchableDomainCount:   len(unmatchableDomainList),
		UnmatchableDomains:       unmatchableDomainList,
		DistinctDomainsServed:    len(served),
		ReferenceMatches:         referenceMatches,
		AlreadyInstalled:         alreadyInstalled,
		Candidates:               candidates,
		CandidateProbeDomains:    candidateProbeDomains,
	}
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatalf("encode review report: %v", err)
	}
	if err := writePrivateAtomic(candidatePath, []byte(candidateText.String())); err != nil {
		fatalf("write candidate list: %v", err)
	}
	if err := writePrivateAtomic(mergedPath, []byte(mergedText.String())); err != nil {
		fatalf("write merged blocklist source: %v", err)
	}
	if err := writePrivateAtomic(reportPath, append(reportJSON, '\n')); err != nil {
		fatalf("write review report: %v", err)
	}

	fmt.Printf("Review window: %s\n", window)
	fmt.Printf("Successful DNS events: %d; distinct domains: %d\n", successfulEvents, len(served))
	fmt.Printf("Unmatchable DNS events skipped: %d; distinct names: %d\n",
		unmatchableEventsSkipped, len(unmatchableDomainList))
	for _, domain := range unmatchableDomainList {
		fmt.Printf("  %s\n", domain)
	}
	fmt.Printf("Reference matches: %d; already installed: %d; candidates: %d\n",
		referenceMatches, alreadyInstalled, len(candidates))
	fmt.Printf("Candidate list: %s\nMerged source: %s\nReport: %s\n",
		candidatePath, mergedPath, reportPath)
	fmt.Println("No ESP32 flash or blocklist replacement was performed.")
}

func readDomainFile(path string) (map[string]struct{}, string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", "", err
	}
	digest := sha256.Sum256(data)
	domains := make(map[string]struct{})
	version := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "# Version:") {
				version = strings.TrimSpace(strings.TrimPrefix(line, "# Version:"))
			}
			continue
		}
		domain, err := canonicalDomain(line)
		if err != nil {
			return nil, "", "", fmt.Errorf("line %d: %w", lineNumber, err)
		}
		domains[domain] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, "", "", err
	}
	if len(domains) == 0 {
		return nil, "", "", errors.New("file contains no domain entries")
	}
	return domains, version, hex.EncodeToString(digest[:]), nil
}

func refreshReference(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, referenceURL, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 90 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("source returned HTTP %d", response.StatusCode)
	}
	const maximumSourceBytes = 64 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maximumSourceBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maximumSourceBytes {
		return fmt.Errorf("source exceeds %d-byte safety limit", maximumSourceBytes)
	}
	temporaryPath := path + ".download"
	if err := writePrivateAtomic(temporaryPath, data); err != nil {
		return err
	}
	if _, _, _, err := readDomainFile(temporaryPath); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("downloaded file failed domain-list validation: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	return nil
}

func canonicalDomain(value string) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if domain == "" || len(domain) > 253 {
		return "", errors.New("empty domain or domain exceeds 253 bytes")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || !domainLabel.MatchString(label) {
			return "", fmt.Errorf("invalid DNS label in %q", domain)
		}
	}
	return domain, nil
}

func findReferenceCover(domain string, reference map[string]struct{}) string {
	if _, ok := reference[domain]; ok {
		return domain
	}
	labels := strings.Split(domain, ".")
	for index := 1; index < len(labels)-1; index++ {
		suffix := strings.Join(labels[index:], ".")
		if _, ok := reference[suffix]; ok {
			return suffix
		}
	}
	return ""
}

func findInstalledCover(domain string, installed map[string]struct{}) string {
	return findReferenceCover(domain, installed)
}

func writePrivateAtomic(path string, data []byte) error {
	temporaryPath := path + ".tmp"
	file, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	return os.Rename(temporaryPath, path)
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "blocklist review failed: "+format+"\n", arguments...)
	os.Exit(1)
}
