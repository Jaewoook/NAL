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
)

// UpdateFileTag surgically updates the image tag in compose.yml and/or .env
// without re-serializing YAML or stripping comments.
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
	var envVarToUpdate string

	for i, line := range lines {
		m := imageLineRe.FindStringSubmatch(line)
		if len(m) == 0 {
			continue
		}
		prefix, quoteOpen, expr, quoteClose, trailing := m[1], m[2], m[3], m[4], m[5]

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

		// Case 2: Standard `repo:tag`
		lastColon := strings.LastIndexByte(expr, ':')
		lastSlash := strings.LastIndexByte(expr, '/')
		if lastColon > lastSlash {
			newExpr := expr[:lastColon+1] + targetTag
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
