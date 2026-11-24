//go:build darwin

package collector

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

type smcKeyInfoData struct {
	dataSize       uint32
	dataType       uint32
	dataAttributes uint8
}

type smcParamStruct struct {
	key        uint32
	vers       [6]byte
	plimitData [16]byte
	keyInfo    smcKeyInfoData
	result     uint8
	status     uint8
	data8      uint8
	data32     uint32
	bytes      [32]byte
}

type smcKeyDescriptor struct {
	name     string
	key      uint32
	dataType string
	dataSize uint32
}

const (
	kSMCUserClientOpen  = 0
	kSMCHandleYPCEvent  = 2
	kSMCReadKey         = 5
	kSMCGetKeyFromIndex = 8
	kSMCGetKeyInfo      = 9

	// minActiveSMCTempCelsius is the minimum valid live die temperature in Celsius.
	// On Apple Silicon, power-gated (asleep/idle) GPU clusters report ~4.6°C (< 11.0°C);
	// Macs Fan Control treats readings below 11.0°C as power-gated sleep values and
	// substitutes the Te05 SoC thermal sensor.
	minActiveSMCTempCelsius = 11.0
	maxValidSMCTempCelsius  = 150.0
	appleSiliconSleepSubKey = "Te05"
)

type iokitSMC struct {
	once sync.Once
	err  error

	ioServiceMatching           func(string) uintptr
	ioServiceGetMatchingService func(uintptr, uintptr) uint32
	machTaskSelf                func() uint32
	ioServiceOpen               func(uint32, uint32, uint32, *uint32) int32
	ioServiceClose              func(uint32) int32
	ioObjectRelease             func(uint32) int32
	ioConnectCallStructMethod   func(uint32, uint32, unsafe.Pointer, uintptr, unsafe.Pointer, *uintptr) int32
}

func (lib *iokitSMC) load() error {
	lib.once.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				lib.err = fmt.Errorf("failed to register IOKit SMC symbols: %v", r)
			}
		}()

		iokit, err := purego.Dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			lib.err = err
			return
		}

		purego.RegisterLibFunc(&lib.ioServiceMatching, iokit, "IOServiceMatching")
		purego.RegisterLibFunc(&lib.ioServiceGetMatchingService, iokit, "IOServiceGetMatchingService")
		purego.RegisterLibFunc(&lib.machTaskSelf, iokit, "mach_task_self")
		purego.RegisterLibFunc(&lib.ioServiceOpen, iokit, "IOServiceOpen")
		purego.RegisterLibFunc(&lib.ioServiceClose, iokit, "IOServiceClose")
		purego.RegisterLibFunc(&lib.ioObjectRelease, iokit, "IOObjectRelease")
		purego.RegisterLibFunc(&lib.ioConnectCallStructMethod, iokit, "IOConnectCallStructMethod")
	})
	return lib.err
}

func (lib *iokitSMC) open() (uint32, error) {
	if err := lib.load(); err != nil {
		return 0, err
	}

	matching := lib.ioServiceMatching("AppleSMC")
	service := lib.ioServiceGetMatchingService(0, matching)
	if service == 0 {
		return 0, nil
	}
	defer lib.ioObjectRelease(service)

	var conn uint32
	if res := lib.ioServiceOpen(service, lib.machTaskSelf(), kSMCUserClientOpen, &conn); res != 0 {
		return 0, nil
	}
	return conn, nil
}

func (lib *iokitSMC) callStruct(conn uint32, inp *smcParamStruct, out *smcParamStruct) bool {
	inSize := unsafe.Sizeof(*inp)
	outSize := unsafe.Sizeof(*out)
	return lib.ioConnectCallStructMethod(conn, kSMCHandleYPCEvent, unsafe.Pointer(inp), inSize, unsafe.Pointer(out), &outSize) == 0 && out.result == 0
}

// smcReader encapsulates Apple SMC key discovery, caching, and temperature sampling.
type smcReader struct {
	lib iokitSMC

	mu               sync.Mutex
	discovered       bool
	gpuKeys          []smcKeyDescriptor
	cpuKeys          []smcKeyDescriptor
	sleepSubDesc     *smcKeyDescriptor
	lastValidGPUTemp float64
}

var defaultSMCReader = &smcReader{}

func smcToUint32(s string) uint32 {
	if len(s) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32([]byte(s[:4]))
}

func smcToString(v uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return string(b)
}

func (r *smcReader) queryKeyDescriptor(conn uint32, keyName string) (smcKeyDescriptor, bool) {
	keyUint := smcToUint32(keyName)
	if keyUint == 0 {
		return smcKeyDescriptor{}, false
	}

	var inp, out smcParamStruct
	inp.key = keyUint
	inp.data8 = kSMCGetKeyInfo
	if !r.lib.callStruct(conn, &inp, &out) {
		return smcKeyDescriptor{}, false
	}

	typeStr := smcToString(out.keyInfo.dataType)
	size := out.keyInfo.dataSize
	if (typeStr != "flt " || size != 4) && (typeStr != "sp78" || size != 2) {
		return smcKeyDescriptor{}, false
	}

	desc := smcKeyDescriptor{
		name:     keyName,
		key:      keyUint,
		dataType: typeStr,
		dataSize: size,
	}
	// Verify the key is readable (accepting > 0 during discovery because power-gated
	// Apple Silicon GPU clusters report ~4.6°C while asleep).
	if rawVal, ok := r.readRawTemperature(conn, desc); !ok || rawVal <= 0 || rawVal > maxValidSMCTempCelsius {
		return smcKeyDescriptor{}, false
	}
	return desc, true
}

func (r *smcReader) resolveDescriptors(conn uint32, names []string) []smcKeyDescriptor {
	var out []smcKeyDescriptor
	for _, name := range names {
		if desc, ok := r.queryKeyDescriptor(conn, name); ok {
			out = append(out, desc)
		}
	}
	return out
}

func (r *smcReader) discoverKeys(conn uint32) ([]smcKeyDescriptor, []smcKeyDescriptor, *smcKeyDescriptor) {
	var sleepSub *smcKeyDescriptor
	if subDesc, ok := r.queryKeyDescriptor(conn, appleSiliconSleepSubKey); ok {
		sleepSub = &subDesc
	}

	// 1. Check if current hardware model has an exact Apple Silicon sensor specification
	if hwModel, err := syscall.Sysctl("hw.model"); err == nil && hwModel != "" {
		hwModel = strings.TrimRight(hwModel, "\x00")
		if spec, exists := appleSiliconModelSensors[hwModel]; exists {
			gpuDescs := r.resolveDescriptors(conn, spec.gpuKeys)
			cpuDescs := r.resolveDescriptors(conn, spec.cpuKeys)
			if len(gpuDescs) > 0 || len(cpuDescs) > 0 {
				return gpuDescs, cpuDescs, sleepSub
			}
		}
	}

	// 2. Fallback: enumerate SMC key table for M1 / Intel / unknown future Mac models
	var inp, out smcParamStruct
	inp.key = smcToUint32("#KEY")
	inp.data8 = kSMCGetKeyInfo
	if !r.lib.callStruct(conn, &inp, &out) {
		return nil, nil, sleepSub
	}

	inp.keyInfo.dataSize = out.keyInfo.dataSize
	inp.data8 = kSMCReadKey
	if !r.lib.callStruct(conn, &inp, &out) {
		return nil, nil, sleepSub
	}

	totalKeys := binary.BigEndian.Uint32(out.bytes[:4])
	if totalKeys > 2000 {
		totalKeys = 2000
	}

	var gpuKeys, cpuKeys []smcKeyDescriptor
	for i := uint32(0); i < totalKeys; i++ {
		var inpKey, outKey smcParamStruct
		inpKey.data8 = kSMCGetKeyFromIndex
		inpKey.data32 = i
		if !r.lib.callStruct(conn, &inpKey, &outKey) {
			continue
		}

		keyName := smcToString(outKey.key)
		if nonCPUSMCKeys[keyName] {
			continue
		}

		// GPU keys: Tg*, TG*
		if strings.HasPrefix(keyName, "Tg") || strings.HasPrefix(keyName, "TG") {
			if desc, ok := r.queryKeyDescriptor(conn, keyName); ok {
				gpuKeys = append(gpuKeys, desc)
			}
			continue
		}

		// Intel & fallback CPU core keys: TC*, Te*
		if strings.HasPrefix(keyName, "TC") || strings.HasPrefix(keyName, "Te") {
			if desc, ok := r.queryKeyDescriptor(conn, keyName); ok {
				cpuKeys = append(cpuKeys, desc)
			}
		}
	}

	return gpuKeys, cpuKeys, sleepSub
}

// decodeRawSMCTemperature decodes raw SMC key bytes (`flt ` or `sp78`) into a float64,
// rejecting NaN and Inf values.
func decodeRawSMCTemperature(dataType string, dataSize uint32, raw [32]byte) (float64, bool) {
	var val float64
	switch {
	case dataType == "flt " && dataSize == 4:
		bits := binary.LittleEndian.Uint32(raw[:4])
		val = float64(math.Float32frombits(bits))
	case dataType == "sp78" && dataSize == 2:
		val = float64(int8(raw[0])) + float64(raw[1])/256.0
	default:
		return 0, false
	}

	if math.IsNaN(val) || math.IsInf(val, 0) {
		return 0, false
	}
	return val, true
}

// decodeSMCTemperature converts raw SMC key bytes (`flt ` or `sp78`) into a validated
// active Celsius reading in the range [11.0, 150.0], rejecting NaN, Inf, and
// power-gated sleep values (< 11.0°C, such as 4.6°C on idle Apple Silicon GPU clusters).
func decodeSMCTemperature(dataType string, dataSize uint32, raw [32]byte) (float64, bool) {
	val, ok := decodeRawSMCTemperature(dataType, dataSize, raw)
	if !ok || val < minActiveSMCTempCelsius || val > maxValidSMCTempCelsius {
		return 0, false
	}
	return val, true
}

func (r *smcReader) readRawTemperature(conn uint32, desc smcKeyDescriptor) (float64, bool) {
	if desc.dataSize == 0 || desc.dataSize > 32 {
		return 0, false
	}

	var inp, out smcParamStruct
	inp.key = desc.key
	inp.keyInfo.dataSize = desc.dataSize
	inp.data8 = kSMCReadKey
	if !r.lib.callStruct(conn, &inp, &out) {
		return 0, false
	}

	return decodeRawSMCTemperature(desc.dataType, desc.dataSize, out.bytes)
}

func (r *smcReader) readActiveTemperature(conn uint32, desc smcKeyDescriptor) (float64, bool) {
	val, ok := r.readRawTemperature(conn, desc)
	if !ok || val < minActiveSMCTempCelsius || val > maxValidSMCTempCelsius {
		return 0, false
	}
	return val, true
}

func meanFloat64(vals []float64) (float64, bool) {
	if len(vals) == 0 {
		return 0, false
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals)), true
}

func (r *smcReader) readTemperatures() (cpuTemp float64, hasCPU bool, gpuTemp float64, hasGPU bool) {
	conn, err := r.lib.open()
	if err != nil || conn == 0 {
		return 0, false, 0, false
	}
	defer r.lib.ioServiceClose(conn)

	r.mu.Lock()
	if !r.discovered {
		r.gpuKeys, r.cpuKeys, r.sleepSubDesc = r.discoverKeys(conn)
		r.discovered = true
	}
	gpuKeys := append([]smcKeyDescriptor(nil), r.gpuKeys...)
	cpuKeys := append([]smcKeyDescriptor(nil), r.cpuKeys...)
	sleepSub := r.sleepSubDesc
	prevGPUTemp := r.lastValidGPUTemp
	r.mu.Unlock()

	var gpuTemps []float64
	for _, desc := range gpuKeys {
		if val, ok := r.readActiveTemperature(conn, desc); ok {
			gpuTemps = append(gpuTemps, val)
		}
	}

	// When Apple Silicon GPU clusters are power-gated in idle state (raw reading ~4.6°C < 11.0°C),
	// substitute the Apple Silicon sleep_substitute sensor (Te05) just like Macs Fan Control,
	// or fall back to the last valid active GPU temperature reading.
	if len(gpuTemps) == 0 && len(gpuKeys) > 0 {
		if sleepSub != nil {
			if subVal, ok := r.readActiveTemperature(conn, *sleepSub); ok {
				gpuTemps = append(gpuTemps, subVal)
			}
		}
		if len(gpuTemps) == 0 && prevGPUTemp >= minActiveSMCTempCelsius {
			gpuTemps = append(gpuTemps, prevGPUTemp)
		}
	}

	var cpuTemps []float64
	for _, desc := range cpuKeys {
		if val, ok := r.readActiveTemperature(conn, desc); ok {
			cpuTemps = append(cpuTemps, val)
		}
	}

	if avg, ok := meanFloat64(gpuTemps); ok {
		gpuTemp = avg
		hasGPU = true

		r.mu.Lock()
		r.lastValidGPUTemp = gpuTemp
		r.mu.Unlock()
	}

	if avg, ok := meanFloat64(cpuTemps); ok {
		cpuTemp = avg
		hasCPU = true
	}

	return cpuTemp, hasCPU, gpuTemp, hasGPU
}

func readDarwinSMCTemperatures() (cpuTemp float64, hasCPU bool, gpuTemp float64, hasGPU bool) {
	return defaultSMCReader.readTemperatures()
}
