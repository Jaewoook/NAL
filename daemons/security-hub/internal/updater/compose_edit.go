package updater

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jaewoook/security-hub/internal/fsutil"
)

var (
	validDockerTagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	trailingEnvTagRe = regexp.MustCompile(`^(.*):\$\{([A-Za-z0-9_]+)(:-|-)?([^}]*)\}$`)
	fullImageEnvRe   = regexp.MustCompile(`^\$\{([A-Za-z0-9_]+)(:-|-)?([^}]*)\}$`)
	imageLineRe      = regexp.MustCompile(`^(\s*)(image:\s*)(['"]?)([^'"\s#]+)(['"]?)(\s*(?:#.*)?)$`)
	serviceHeaderRe  = regexp.MustCompile(`^(\s+)([A-Za-z0-9_.-]+):\s*(?:#.*)?$`)
	topLevelHeaderRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+):\s*(?:#.*)?$`)
)

// IsValidDockerTag validates that tag conforms to OCI/Docker tag character and length rules.
func IsValidDockerTag(tag string) bool {
	return validDockerTagRe.MatchString(tag)
}

func replaceImageTagPart(expr, targetTag string) string {
	exprClean := expr
	if atIdx := strings.Index(exprClean, "@"); atIdx != -1 {
		exprClean = exprClean[:atIdx]
	}
	lastColon := strings.LastIndexByte(exprClean, ':')
	lastSlash := strings.LastIndexByte(exprClean, '/')
	if lastColon > lastSlash {
		return exprClean[:lastColon+1] + targetTag
	}
	return exprClean + ":" + targetTag
}

type serviceImageMatch struct {
	lineIdx    int
	svcName    string
	prefix     string
	quoteOpen  string
	expr       string
	quoteClose string
	trailing   string
}

func scanServiceImageLines(lines []string) []serviceImageMatch {
	var out []serviceImageMatch
	inServices := false
	currentSvc := ""
	svcIndent := -1
	propIndent := -1

	for i, line := range lines {
		if top := topLevelHeaderRe.FindStringSubmatch(line); len(top) == 2 {
			inServices = (top[1] == "services")
			currentSvc = ""
			svcIndent = -1
			propIndent = -1
			continue
		}
		if !inServices {
			continue
		}
		if sh := serviceHeaderRe.FindStringSubmatch(line); len(sh) == 3 {
			indentLen := len(sh[1])
			if svcIndent == -1 || indentLen == svcIndent {
				svcIndent = indentLen
				currentSvc = sh[2]
				propIndent = -1
				continue
			}
			if indentLen > svcIndent && propIndent == -1 {
				propIndent = indentLen
			}
		}
		if currentSvc == "" {
			continue
		}
		m := imageLineRe.FindStringSubmatch(line)
		if len(m) == 0 {
			continue
		}
		indentLen := len(m[1])
		if propIndent == -1 && indentLen > svcIndent {
			propIndent = indentLen
		}
		if propIndent == -1 || indentLen != propIndent {
			continue
		}
		out = append(out, serviceImageMatch{
			lineIdx:    i,
			svcName:    currentSvc,
			prefix:     m[1] + m[2],
			quoteOpen:  m[3],
			expr:       m[4],
			quoteClose: m[5],
			trailing:   m[6],
		})
	}
	return out
}

func readOptionalEnvFile(envPath string) ([]byte, os.FileMode, error) {
	envPerm := os.FileMode(0600)
	if envPath == "" {
		return nil, envPerm, nil
	}
	envInfo, err := os.Stat(envPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, envPerm, nil
		}
		return nil, 0, fmt.Errorf("failed to stat env file %s: %w", envPath, err)
	}
	if p := envInfo.Mode().Perm(); p != 0 {
		envPerm = p
	}
	rawEnv, err := os.ReadFile(envPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read env file %s: %w", envPath, err)
	}
	return rawEnv, envPerm, nil
}

func findServiceTargetExpr(matches []serviceImageMatch, serviceKey string) string {
	if serviceKey == "" {
		return ""
	}
	for _, m := range matches {
		if m.svcName == serviceKey {
			return m.expr
		}
	}
	return ""
}

func matchesServiceTarget(m serviceImageMatch, serviceKey, targetExpr string) bool {
	if serviceKey == "" {
		return true
	}
	if targetExpr != "" {
		return m.expr == targetExpr
	}
	return m.svcName == serviceKey
}

func rewriteComposeImageExpr(expr, targetTag string) (newExpr, envVar string, fullImage bool, err error) {
	// Case 1: Image expression ends with `:${VAR:-default}` or `:${VAR-default}`
	if sub := trailingEnvTagRe.FindStringSubmatch(expr); len(sub) == 5 {
		repoPart := sub[1]
		varName := sub[2]
		sep := sub[3]
		if sep == "" {
			sep = ":-"
		}
		return fmt.Sprintf("%s:${%s%s%s}", repoPart, varName, sep, targetTag), varName, false, nil
	}

	// Case 2: Whole image expression is `${VAR:-repo:tag}` or `${VAR}`
	if sub := fullImageEnvRe.FindStringSubmatch(expr); len(sub) == 4 {
		varName := sub[1]
		sep := sub[2]
		defVal := sub[3]
		if defVal == "" {
			return expr, varName, true, nil
		}
		if sep == "" {
			sep = ":-"
		}
		newDef := replaceImageTagPart(defVal, targetTag)
		return fmt.Sprintf("${%s%s%s}", varName, sep, newDef), varName, true, nil
	}

	if strings.ContainsAny(expr, "${}") {
		return "", "", false, fmt.Errorf("unsupported variable interpolation format in image expression %q", expr)
	}

	// Case 3: Standard `repo:tag`, digest-pinned `repo:tag@sha256:...`, or tagless `repo`
	return replaceImageTagPart(expr, targetTag), "", false, nil
}

func updateEnvVarInRawEnv(rawEnv []byte, envVar string, fullImage bool, targetTag string) (updated []byte, changed bool, err error) {
	if len(rawEnv) == 0 || envVar == "" {
		return rawEnv, false, nil
	}
	envLines := strings.Split(string(rawEnv), "\n")
	for i, el := range envLines {
		trimmed := strings.TrimSpace(el)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		idx := strings.IndexByte(el, '=')
		if idx <= 0 || strings.TrimSpace(el[:idx]) != envVar {
			continue
		}
		val := strings.Trim(strings.TrimSpace(el[idx+1:]), `"'`)
		if fullImage {
			if val == "" {
				return nil, false, fmt.Errorf("cannot update empty image env variable %s", envVar)
			}
			envLines[i] = fmt.Sprintf("%s=%s", envVar, replaceImageTagPart(val, targetTag))
		} else {
			envLines[i] = fmt.Sprintf("%s=%s", envVar, targetTag)
		}
		changed = true
	}
	if !changed {
		return rawEnv, false, nil
	}
	return []byte(strings.Join(envLines, "\n")), true, nil
}

// UpdateFileTag surgically updates the image tag in compose.yml and/or .env
// without re-serializing YAML or stripping comments. When serviceKey is set,
// only that service (and any sibling service in the same file sharing the exact
// same image expression, such as authentik server + worker) is updated.
func UpdateFileTag(composePath, envPath, serviceKey, targetTag string) (updatedCompose []byte, updatedEnv []byte, err error) {
	if !IsValidDockerTag(targetTag) {
		return nil, nil, fmt.Errorf("invalid target Docker tag %q", targetTag)
	}
	composeInfo, err := os.Stat(composePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat compose file: %w", err)
	}
	composePerm := composeInfo.Mode().Perm()
	if composePerm == 0 {
		composePerm = 0644
	}
	rawCompose, err := os.ReadFile(composePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read compose file: %w", err)
	}
	rawEnv, envPerm, err := readOptionalEnvFile(envPath)
	if err != nil {
		return nil, nil, err
	}

	lines := strings.Split(string(rawCompose), "\n")
	matches := scanServiceImageLines(lines)
	targetExpr := findServiceTargetExpr(matches, serviceKey)

	var envVarToUpdate string
	var envVarFullImage bool
	matchedLine := false
	for _, m := range matches {
		if !matchesServiceTarget(m, serviceKey, targetExpr) {
			continue
		}
		matchedLine = true
		newExpr, envVar, fullImg, err := rewriteComposeImageExpr(m.expr, targetTag)
		if err != nil {
			return nil, nil, err
		}
		if envVar != "" {
			envVarToUpdate = envVar
			envVarFullImage = fullImg
		}
		lines[m.lineIdx] = m.prefix + m.quoteOpen + newExpr + m.quoteClose + m.trailing
	}
	if !matchedLine {
		return nil, nil, fmt.Errorf("no matching image line found in %s", composePath)
	}

	updatedEnv, envChanged, err := updateEnvVarInRawEnv(rawEnv, envVarToUpdate, envVarFullImage, targetTag)
	if err != nil {
		return nil, nil, err
	}
	if envChanged {
		if err := fsutil.WriteFileAtomic(envPath, updatedEnv, envPerm); err != nil {
			return nil, nil, fmt.Errorf("failed to write env file %s: %w", envPath, err)
		}
	}

	updatedCompose = []byte(strings.Join(lines, "\n"))
	if err := fsutil.WriteFileAtomic(composePath, updatedCompose, composePerm); err != nil {
		return nil, nil, fmt.Errorf("failed to write compose file %s: %w", composePath, err)
	}
	return updatedCompose, updatedEnv, nil
}
