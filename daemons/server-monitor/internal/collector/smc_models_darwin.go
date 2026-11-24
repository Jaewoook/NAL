//go:build darwin

package collector

type modelSensorSpec struct {
	cpuKeys []string
	gpuKeys []string
}

// appleSiliconModelSensors maps Apple Silicon hardware models (sysctl hw.model) to their
// active CPU core and GPU cluster SMC sensor keys, avoiding calibration/limit registers
// (such as TCMz, Tp02, Tp06, Tp0A) and idle lower-bound registers.
var appleSiliconModelSensors = func() map[string]modelSensorSpec {
	m := make(map[string]modelSensorSpec)
	register := func(models []string, cpu, gpu []string) {
		spec := modelSensorSpec{cpuKeys: cpu, gpuKeys: gpu}
		for _, mdl := range models {
			m[mdl] = spec
		}
	}

	// M1 Pro / M1 Max / M1 Ultra
	register(
		[]string{"MacBookPro18,1", "MacBookPro18,2", "MacBookPro18,3", "MacBookPro18,4", "MacStudio1,1", "Mac13,1", "MacStudio1,2", "Mac13,2"},
		[]string{"Tp01", "Tp05", "Tp0D", "Tp0H", "Tp0L", "Tp0P", "Tp0X", "Tp0b", "Tp09", "Tp0T", "Tp21", "Tp25", "Tp2D", "Tp2H", "Tp2L", "Tp2P", "Tp2X", "Tp2b", "Tp29", "Tp2T"},
		[]string{"Tg05", "Tg0D", "Tg0L", "Tg0T", "Tg0b", "Tg0j", "Tg0r", "Tg0z"},
	)

	// M2 (Mac mini, MacBook Air 13"/15", MacBook Pro 13")
	register(
		[]string{"MacBookPro17,2", "Mac14,7", "MacBookAir11,1", "Mac14,2", "MacBookAir11,2", "Mac14,15", "Macmini10,1", "Mac14,3"},
		[]string{"Tp01", "Tp09", "Tp0f", "Tp0n", "Tp05", "Tp0D", "Tp0j", "Tp0r"},
		[]string{"Tg0f", "Tg0n"},
	)

	// M2 Pro / M2 Max / M2 Ultra
	register(
		[]string{"MacBookPro19,1", "Mac14,9", "MacBookPro19,2", "Mac14,10", "MacBookPro19,3", "Mac14,5", "MacBookPro19,4", "Mac14,6", "Macmini10,2", "Mac14,12", "MacStudio2,1", "Mac14,13", "MacStudio2,2", "Mac14,14", "MacPro8,1", "Mac14,8"},
		[]string{"Tp01", "Tp09", "Tp0X", "Tp0f", "Tp1B", "Tp1J", "Tp1h", "Tp1p", "Tp05", "Tp0b", "Tp0D", "Tp0j"},
		[]string{"Tg0f", "Tg0j", "Tg1h", "Tg1l", "Tg2f"},
	)

	// M3 (MacBook Pro 14", iMac 24", MacBook Air 13"/15")
	register(
		[]string{"MacBookPro20,1", "Mac15,3", "iMac22,1", "Mac15,4", "iMac22,2", "Mac15,5", "MacBookAir12,1", "Mac15,12", "MacBookAir12,2", "Mac15,13"},
		[]string{"Tp01", "Tp09", "Tp0X", "Tp0f", "Tp05", "Tp0b", "Tp0D", "Tp0j"},
		[]string{"Tg0D", "Tg0P", "Tg0X", "Tg0b", "Tg0j", "Tg0v"},
	)

	// M3 Pro
	register(
		[]string{"MacBookPro20,2", "Mac15,6", "MacBookPro20,5", "Mac15,7"},
		[]string{"Tp05", "Tp0D", "Tp0L", "Tp0S", "Tp17", "Tp1F", "Te05", "Te0P", "Te0H", "Te04", "Te0S", "Te0U"},
		[]string{"Tg05", "Tg0D", "Tg0v", "Tg1B"},
	)

	// M3 Max
	register(
		[]string{"MacBookPro20,3", "Mac15,8", "MacBookPro20,4", "Mac15,10", "MacBookPro20,6", "Mac15,11", "MacBookPro20,7", "Mac15,9"},
		[]string{"Tp05", "Tp0D", "Tp0L", "Tp1F", "Tp17", "Tp0S", "Tp1h", "Tp1p", "Tp1y", "Tp30", "Tp2s", "Tp26", "Te05", "Te0L"},
		[]string{"Tg05", "Tg0z", "Tg34", "Tg3y"},
	)

	// M3 Ultra (Mac Studio)
	register(
		[]string{"MacStudio3,2", "Mac15,14"},
		[]string{"Tp06", "Tp0E", "Tp0M", "Tp0T", "Tp0W", "Tp0c", "Tp0i", "Tp0o", "Tp18", "Tp1G", "Tp1K", "Tp1S", "Te06", "Te0M", "Te0Q", "Te0T"},
		[]string{"Tg05", "Tg0z", "Tg22", "Tg2I", "Tg34", "Tg3K"},
	)

	// M4 (Mac mini, MacBook Pro, iMac, MacBook Air)
	register(
		[]string{"Macmini11,1", "Mac16,10", "MacBookPro21,1", "Mac16,1", "iMac23,1", "Mac16,3", "iMac23,2", "Mac16,2", "MacBookAir13,1", "Mac16,12", "MacBookAir13,2", "Mac16,13"},
		[]string{"Tp01", "Tp05", "Tp09", "Tp0D", "Te05", "Te09", "Te0H", "Te0S", "Te0U", "Te0V"},
		[]string{"Tg0H", "Tg0L", "Tg0Y", "Tg0e", "Tg0k"},
	)

	// M4 Pro / M4 Max
	register(
		[]string{"MacStudio3,1", "Mac16,9", "Macmini11,2", "Mac16,11", "MacBookPro21,2", "Mac16,8", "MacBookPro21,3", "Mac16,6", "MacBookPro21,4", "Mac16,7", "MacBookPro21,5", "Mac16,5"},
		[]string{"Tp01", "Tp0H", "Tp0P", "Tp0X", "Tp1j", "Tp1z", "Tp25", "Tp2B", "Tp09", "Tp1t", "Tp0e", "Tp2J", "Te05", "Te0S"},
		[]string{"Tg05", "Tg0S", "Tg0Y", "Tg0k", "Tg0z"},
	)

	// M5 / Next-gen Apple Silicon families
	register(
		[]string{"MacBookPro22,1", "Mac17,2", "MacBookAir14,1", "Mac17,3", "MacBookAir14,2", "Mac17,4"},
		[]string{"Tp00", "Tp0C", "Tp0O", "Tp0X", "Te04", "Te08", "Te0C"},
		[]string{"Tg0K", "Tg1M"},
	)
	register(
		[]string{"MacBookPro22,2", "Mac17,9", "MacBookPro22,3", "Mac17,7", "MacBookPro22,4", "Mac17,8", "MacBookPro22,5", "Mac17,6", "Macmini12,2", "Mac17,16", "MacStudio4,1", "Mac17,14"},
		[]string{"Tm04", "Tm0G", "Tm0R", "Tm0a", "Tm0j", "Tm1Q", "Tm1c", "Tm1o", "Tm21", "Tm2D", "Tm2P", "Tm0u", "Tp04", "Tp0G", "Tp0R", "Tp0a", "Tp0j", "Tp0u"},
		[]string{"Tg08", "Tg12", "Tg1x", "Tg29"},
	)
	register(
		[]string{"MacStudio4,2", "Mac17,15"},
		[]string{"Tm01", "Tm04", "Tm07", "Tm0a", "Tm0d", "Tm0o", "Tm0r", "Tm0u", "Tm0x", "Tm0A", "Tm0L", "Tm0O", "Tm0R", "Tm0U", "Tm0X", "Tm18", "Tm1b", "Tm1e", "Tm1h", "Tm1k", "Tm0g", "Tm0D", "Tm10", "Tm1n", "Tp01", "Tp04", "Tp07", "Tp0a", "Tp0d", "Tp0u", "Tp0x", "Tp0A", "Tp0D", "Tp0G", "Tp0g", "Tp0J"},
		[]string{"Tg02", "Tg0z", "Tg16", "Tg1D", "Tg2a", "Tg2H", "Tg3e", "Tg3L"},
	)
	register(
		[]string{"MacBookNeo1,1", "Mac17,5"},
		[]string{"Tp01", "Tp09", "Te05", "Te06", "Tex0", "Tex1"},
		[]string{"Tg05", "Tg0D"},
	)
	register(
		[]string{"Macmini12,1", "Mac18,5"},
		[]string{"Tp0g", "Tp0j", "Tp0L", "Tp0I", "Tp0d", "Tp0m", "Te07", "Te08", "Te09"},
		[]string{"Tg0c", "Tg1d"},
	)

	return m
}()

// nonCPUSMCKeys excludes power supply / calibration SMC keys that share prefixes with CPU keys.
var nonCPUSMCKeys = map[string]bool{
	"TCMz": true, // Thermal calibration / max limit register on Apple Silicon
	"Tp0P": true, // Power Supply Proximity (Intel)
	"Tp0C": true, // PSMI Supply AC/DC Supply 1 (Intel)
	"Tp1P": true, // MLB Front Edge / PSU (Intel)
	"Tp1C": true, // PSMI Supply AC/DC Supply 2 (Intel)
	"Tp0T": true, // PSU Secondary Heatsink (Intel)
	"Tp3H": true, // PSU Primary (Intel)
}
