package web

import (
	"io/fs"
	"sort"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// TestTranslationsAreValidToml unmarshals every embedded translation file so a
// malformed key (e.g. a bad bulk-ops i18n insertion) fails here instead of silently
// breaking i18n at runtime.
func TestTranslationsAreValidToml(t *testing.T) {
	entries, err := fs.ReadDir(i18nFS, "translation")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := i18nFS.ReadFile("translation/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var m map[string]any
		if err := toml.Unmarshal(data, &m); err != nil {
			t.Errorf("%s: invalid TOML: %v", e.Name(), err)
		}
	}
}

func keySet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// knownMissing are en_US keys not yet translated in the other locales (the Core
// Settings + systemd-service panels + setup-required toasts added after the
// fork). They render via the English fallback in web/locale.I18n — readable, not
// blank — so they are tolerated here as a baseline. Shrink this list as
// translations land; TestTranslationKeyParity fails on any en-only key NOT in
// this set, so the gap can never grow silently.
var knownMissing = keySet(
	"pages.inbounds.opDelete", "pages.inbounds.bulkDeleteConfirm",
	"pages.inbounds.opFreeze", "pages.inbounds.opUnfreeze",
	"pages.client.freeze", "pages.client.unfreeze",
	"pages.core.absent", "pages.core.actions", "pages.core.consoleTitle",
	"pages.core.cores", "pages.core.disabled", "pages.core.editConfig",
	"pages.core.enabled", "pages.core.hideLog", "pages.core.inbounds",
	"pages.core.initSetup", "pages.core.ipForward", "pages.core.iproute",
	"pages.core.kernelModules", "pages.core.loaded", "pages.core.logs",
	"pages.core.missing", "pages.core.nftables", "pages.core.noLogs",
	"pages.core.present", "pages.core.provisionDesc", "pages.core.reRunSetup",
	"pages.core.rebootConfirm", "pages.core.rebootDetails", "pages.core.rebootImpact",
	"pages.core.rebootLater", "pages.core.rebootModulesLabel", "pages.core.rebootNow",
	"pages.core.rebootPkgLabel", "pages.core.rebootTitle", "pages.core.rebootWhat",
	"pages.core.rebooting", "pages.core.rebootingDesc", "pages.core.refresh",
	"pages.core.restart", "pages.core.runSetup", "pages.core.setupDone",
	"pages.core.setupNeededDesc", "pages.core.setupNeededTitle", "pages.core.setupRunning",
	"pages.core.showLog", "pages.core.stateError", "pages.core.stateIdle",
	"pages.core.stateNotInstalled", "pages.core.stateRunning", "pages.core.stateStopped",
	"pages.core.status", "pages.core.stepDaemons", "pages.core.stepForward",
	"pages.core.stepIpsec", "pages.core.stepModules", "pages.core.stop",
	"pages.core.subtitle", "pages.core.system", "pages.core.title",
	"pages.core.toasts.provisioned", "pages.core.toasts.rebooting",
	"pages.core.toasts.restarted", "pages.core.toasts.stopped", "pages.core.version",
	"pages.core.newProtocolTitle", "pages.core.newProtocolDesc",
	"pages.inbounds.toasts.setupRequired", "pages.inbounds.toasts.setupRequiredOk",
	"pages.inbounds.toasts.setupRequiredTitle", "pages.inbounds.toasts.setupRequiredForProtocol",
	"pages.settings.service.apply", "pages.settings.service.autoRefresh",
	"pages.settings.service.enable", "pages.settings.service.enableDesc",
	"pages.settings.service.installed", "pages.settings.service.liveLog",
	"pages.settings.service.liveLogDesc", "pages.settings.service.loadDefault",
	"pages.settings.service.name", "pages.settings.service.nameDesc",
	"pages.settings.service.noLog", "pages.settings.service.noSystemd",
	"pages.settings.service.onBoot", "pages.settings.service.start",
	"pages.settings.service.startDesc", "pages.settings.service.status",
	"pages.settings.service.statusDesc", "pages.settings.service.unit",
	"pages.settings.service.unitDesc", "pages.settings.serviceSettings",
)

// flattenKeys collapses nested TOML tables into dotted keys (e.g. "pages.core.title").
func flattenKeys(prefix string, m map[string]any, out map[string]bool) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok {
			flattenKeys(key, sub, out)
		} else {
			out[key] = true
		}
	}
}

func loadTranslationKeys(t *testing.T, name string) map[string]bool {
	t.Helper()
	data, err := i18nFS.ReadFile("translation/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		t.Fatalf("%s: invalid TOML: %v", name, err)
	}
	keys := make(map[string]bool)
	flattenKeys("", m, keys)
	return keys
}

// TestTranslationKeyParity fails when any locale is missing an en_US key that is
// not in the knownMissing baseline — i.e. someone added an English-only string.
// Without this guard such a key renders blank (or English-fallback) for every
// non-English user and nobody notices. Fix a failure by translating the key in
// every locale, or (if intentionally deferred) adding it to knownMissing.
func TestTranslationKeyParity(t *testing.T) {
	const ref = "translate.en_US.toml"
	refKeys := loadTranslationKeys(t, ref)

	entries, err := fs.ReadDir(i18nFS, "translation")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == ref {
			continue
		}
		locKeys := loadTranslationKeys(t, e.Name())
		var newlyMissing []string
		for k := range refKeys {
			if !locKeys[k] && !knownMissing[k] {
				newlyMissing = append(newlyMissing, k)
			}
		}
		if len(newlyMissing) > 0 {
			sort.Strings(newlyMissing)
			t.Errorf("%s: %d en_US key(s) missing and not baselined "+
				"(translate them or add to knownMissing): %v",
				e.Name(), len(newlyMissing), newlyMissing)
		}
	}
}
