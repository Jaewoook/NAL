package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
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

	var rawEnv []byte
	envPerm := os.FileMode(0600)
	if envPath != "" {
		if envInfo, sErr := os.Stat(envPath); sErr == nil {
			if p := envInfo.Mode().Perm(); p != 0 {
				envPerm = p
			}
			rawEnv, err = os.ReadFile(envPath)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read env file %s: %w", envPath, err)
			}
		} else if !os.IsNotExist(sErr) {
			return nil, nil, fmt.Errorf("failed to stat env file %s: %w", envPath, sErr)
		}
	}

	lines := strings.Split(string(rawCompose), "\n")
	matches := scanServiceImageLines(lines)

	var targetExpr string
	if serviceKey != "" {
		for _, m := range matches {
			if m.svcName == serviceKey {
				targetExpr = m.expr
				break
			}
		}
	}

	var envVarToUpdate string
	var envVarFullImage bool
	matchedLine := false

	for _, m := range matches {
		if serviceKey != "" {
			if targetExpr != "" {
				if m.expr != targetExpr {
					continue
				}
			} else if m.svcName != serviceKey {
				continue
			}
		}
		matchedLine = true

		// Case 1: Image expression ends with `:${VAR:-default}` or `:${VAR-default}`
		if sub := trailingEnvTagRe.FindStringSubmatch(m.expr); len(sub) == 5 {
			repoPart := sub[1]
			varName := sub[2]
			sep := sub[3]
			if sep == "" {
				sep = ":-"
			}
			envVarToUpdate = varName
			envVarFullImage = false
			newExpr := fmt.Sprintf("%s:${%s%s%s}", repoPart, varName, sep, targetTag)
			lines[m.lineIdx] = m.prefix + m.quoteOpen + newExpr + m.quoteClose + m.trailing
			continue
		}

		// Case 2: Whole image expression is `${VAR:-repo:tag}` or `${VAR}`
		if sub := fullImageEnvRe.FindStringSubmatch(m.expr); len(sub) == 4 {
			varName := sub[1]
			sep := sub[2]
			defVal := sub[3]
			envVarToUpdate = varName
			envVarFullImage = true
			if defVal != "" {
				if sep == "" {
					sep = ":-"
				}
				newDef := replaceImageTagPart(defVal, targetTag)
				newExpr := fmt.Sprintf("${%s%s%s}", varName, sep, newDef)
				lines[m.lineIdx] = m.prefix + m.quoteOpen + newExpr + m.quoteClose + m.trailing
			}
			continue
		}

		if strings.ContainsAny(m.expr, "${}") {
			return nil, nil, fmt.Errorf("unsupported variable interpolation format in image expression %q", m.expr)
		}

		// Case 3: Standard `repo:tag`, digest-pinned `repo:tag@sha256:...`, or tagless `repo`
		newExpr := replaceImageTagPart(m.expr, targetTag)
		lines[m.lineIdx] = m.prefix + m.quoteOpen + newExpr + m.quoteClose + m.trailing
	}

	if !matchedLine {
		return nil, nil, fmt.Errorf("no matching image line found in %s", composePath)
	}

	if len(rawEnv) > 0 && envVarToUpdate != "" {
		envLines := strings.Split(string(rawEnv), "\n")
		replaced := false
		for i, el := range envLines {
			trimmed := strings.TrimSpace(el)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			if idx := strings.IndexByte(el, '='); idx > 0 {
				k := strings.TrimSpace(el[:idx])
				if k == envVarToUpdate {
					val := strings.Trim(strings.TrimSpace(el[idx+1:]), `"'`)
					if envVarFullImage {
						if val == "" {
							return nil, nil, fmt.Errorf("cannot update empty image env variable %s", k)
						}
						envLines[i] = fmt.Sprintf("%s=%s", k, replaceImageTagPart(val, targetTag))
					} else {
						envLines[i] = fmt.Sprintf("%s=%s", k, targetTag)
					}
					replaced = true
				}
			}
		}
		if replaced {
			updatedEnv = []byte(strings.Join(envLines, "\n"))
			if err := writeFileAtomic(envPath, updatedEnv, envPerm); err != nil {
				return nil, nil, fmt.Errorf("failed to write env file %s: %w", envPath, err)
			}
		} else {
			updatedEnv = rawEnv
		}
	} else {
		updatedEnv = rawEnv
	}

	updatedCompose = []byte(strings.Join(lines, "\n"))
	if err := writeFileAtomic(composePath, updatedCompose, composePerm); err != nil {
		return nil, nil, fmt.Errorf("failed to write compose file %s: %w", composePath, err)
	}

	return updatedCompose, updatedEnv, nil
}
