package updater

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	trailingEnvTagRe = regexp.MustCompile(`^(.*):\$\{([A-Za-z0-9_]+)(:-|-)?([^}]*)\}$`)
	imageLineRe      = regexp.MustCompile(`^(\s*image:\s*)(['"]?)([^'"\s#]+)(['"]?)(\s*(?:#.*)?)$`)
	serviceHeaderRe  = regexp.MustCompile(`^(\s+)([A-Za-z0-9_.-]+):\s*(?:#.*)?$`)
	topLevelHeaderRe = regexp.MustCompile(`^([A-Za-z0-9_.-]+):\s*(?:#.*)?$`)
)

// UpdateFileTag surgically updates the image tag in compose.yml and/or .env
// without re-serializing YAML or stripping comments. When serviceKey is set,
// only that service (and any sibling service in the same file sharing the exact
// same image expression, such as authentik server + worker) is updated.
func UpdateFileTag(composePath, envPath, serviceKey, targetTag string) (updatedCompose []byte, updatedEnv []byte, err error) {
	rawCompose, err := os.ReadFile(composePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read compose file: %w", err)
	}
	var rawEnv []byte
	if envPath != "" {
		rawEnv, _ = os.ReadFile(envPath)
	}

	lines := strings.Split(string(rawCompose), "\n")

	// First pass: find the image expression for serviceKey if specified
	var targetExpr string
	inServices := false
	currentSvc := ""
	svcIndent := -1
	for _, line := range lines {
		if top := topLevelHeaderRe.FindStringSubmatch(line); len(top) == 2 {
			inServices = (top[1] == "services")
			currentSvc = ""
			svcIndent = -1
			continue
		}
		if inServices {
			if sh := serviceHeaderRe.FindStringSubmatch(line); len(sh) == 3 {
				indentLen := len(sh[1])
				if svcIndent == -1 {
					svcIndent = indentLen
					currentSvc = sh[2]
					continue
				} else if indentLen == svcIndent {
					currentSvc = sh[2]
					continue
				}
				// indentLen > svcIndent indicates a nested mapping (e.g. environment:, volumes:)
			}
			if m := imageLineRe.FindStringSubmatch(line); len(m) > 0 {
				if serviceKey != "" && currentSvc == serviceKey {
					targetExpr = m[3]
					break
				}
			}
		}
	}

	var envVarToUpdate string
	inServices = false
	currentSvc = ""
	svcIndent = -1

	for i, line := range lines {
		if top := topLevelHeaderRe.FindStringSubmatch(line); len(top) == 2 {
			inServices = (top[1] == "services")
			currentSvc = ""
			svcIndent = -1
			continue
		}
		if inServices {
			if sh := serviceHeaderRe.FindStringSubmatch(line); len(sh) == 3 {
				indentLen := len(sh[1])
				if svcIndent == -1 {
					svcIndent = indentLen
					currentSvc = sh[2]
					continue
				} else if indentLen == svcIndent {
					currentSvc = sh[2]
					continue
				}
			}
		}

		m := imageLineRe.FindStringSubmatch(line)
		if len(m) == 0 {
			continue
		}
		prefix, quoteOpen, expr, quoteClose, trailing := m[1], m[2], m[3], m[4], m[5]

		if serviceKey != "" {
			if targetExpr != "" {
				if expr != targetExpr {
					continue
				}
			} else if currentSvc != serviceKey {
				continue
			}
		}

		// Case 1: Image expression ends with `:${VAR:-default}` or `:${VAR-default}`
		if sub := trailingEnvTagRe.FindStringSubmatch(expr); len(sub) == 5 {
			repoPart := sub[1]
			varName := sub[2]
			sep := sub[3]
			if sep == "" {
				sep = ":-"
			}
			envVarToUpdate = varName
			newExpr := fmt.Sprintf("%s:${%s%s%s}", repoPart, varName, sep, targetTag)
			lines[i] = prefix + quoteOpen + newExpr + quoteClose + trailing
			continue
		}

		// Case 2: Standard `repo:tag`, digest-pinned `repo:tag@sha256:...`, or tagless `repo`
		exprClean := expr
		if atIdx := strings.Index(exprClean, "@"); atIdx != -1 {
			exprClean = exprClean[:atIdx]
		}
		lastColon := strings.LastIndexByte(exprClean, ':')
		lastSlash := strings.LastIndexByte(exprClean, '/')
		if lastColon > lastSlash {
			newExpr := exprClean[:lastColon+1] + targetTag
			lines[i] = prefix + quoteOpen + newExpr + quoteClose + trailing
		} else {
			newExpr := exprClean + ":" + targetTag
			lines[i] = prefix + quoteOpen + newExpr + quoteClose + trailing
		}
	}

	updatedCompose = []byte(strings.Join(lines, "\n"))
	if err := os.WriteFile(composePath, updatedCompose, 0644); err != nil {
		return nil, nil, err
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
					envLines[i] = fmt.Sprintf("%s=%s", k, targetTag)
					replaced = true
				}
			}
		}
		if replaced {
			updatedEnv = []byte(strings.Join(envLines, "\n"))
			_ = os.WriteFile(envPath, updatedEnv, 0600)
		} else {
			updatedEnv = rawEnv
		}
	} else {
		updatedEnv = rawEnv
	}

	return updatedCompose, updatedEnv, nil
}
