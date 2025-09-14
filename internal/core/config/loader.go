package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfigLoader handles loading configuration from multiple sources
// with priority: ENV > YAML/JSON > CLI flags > Vault
type ConfigLoader struct {
	configPaths []string
	vaultClient VaultClient
	envPrefix   string
}

// VaultClient interface for secret management
type VaultClient interface {
	GetSecret(path string) (map[string]interface{}, error)
}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader(envPrefix string, configPaths ...string) *ConfigLoader {
	return &ConfigLoader{
		configPaths: configPaths,
		envPrefix:   envPrefix,
	}
}

// SetVaultClient sets the vault client for secret management
func (cl *ConfigLoader) SetVaultClient(client VaultClient) {
	cl.vaultClient = client
}

// Load loads configuration into the provided struct
// Priority: ENV > YAML/JSON > CLI flags > Vault
func (cl *ConfigLoader) Load(config interface{}, cliFlags map[string]interface{}) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	v := reflect.ValueOf(config)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("config must be a pointer to struct")
	}

	// 1. Load from Vault (lowest priority)
	if cl.vaultClient != nil {
		if err := cl.loadFromVault(config); err != nil {
			return fmt.Errorf("failed to load from vault: %w", err)
		}
	}

	// 2. Load from CLI flags
	if cliFlags != nil {
		if err := cl.loadFromFlags(config, cliFlags); err != nil {
			return fmt.Errorf("failed to load from CLI flags: %w", err)
		}
	}

	// 3. Load from YAML/JSON files
	if err := cl.loadFromFiles(config); err != nil {
		return fmt.Errorf("failed to load from files: %w", err)
	}

	// 4. Load from environment variables (highest priority)
	if err := cl.loadFromEnv(config); err != nil {
		return fmt.Errorf("failed to load from environment: %w", err)
	}

	return nil
}

// loadFromEnv loads configuration from environment variables
func (cl *ConfigLoader) loadFromEnv(config interface{}) error {
	v := reflect.ValueOf(config).Elem()
	t := v.Type()

	return cl.loadFromEnvRecursive(v, t, cl.envPrefix)
}

func (cl *ConfigLoader) loadFromEnvRecursive(v reflect.Value, t reflect.Type, prefix string) error {
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}

		// Get field name from tag or use field name
		fieldName := fieldType.Name
		if envTag := fieldType.Tag.Get("env"); envTag != "" {
			fieldName = envTag
		}

		envKey := strings.ToUpper(prefix + "_" + fieldName)
		envValue := os.Getenv(envKey)

		if envValue == "" {
			// If it's a struct, recurse
			if field.Kind() == reflect.Struct {
				if err := cl.loadFromEnvRecursive(field, fieldType.Type, envKey); err != nil {
					return err
				}
			}
			continue
		}

		if err := cl.setFieldValue(field, envValue); err != nil {
			return fmt.Errorf("failed to set field %s from env %s: %w", fieldName, envKey, err)
		}
	}

	return nil
}

// loadFromFiles loads configuration from YAML/JSON files
func (cl *ConfigLoader) loadFromFiles(config interface{}) error {
	for _, configPath := range cl.configPaths {
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			continue
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}

		ext := strings.ToLower(filepath.Ext(configPath))
		switch ext {
		case ".yaml", ".yml":
			if err := yaml.Unmarshal(data, config); err != nil {
				return fmt.Errorf("failed to unmarshal YAML config %s: %w", configPath, err)
			}
		case ".json":
			if err := json.Unmarshal(data, config); err != nil {
				return fmt.Errorf("failed to unmarshal JSON config %s: %w", configPath, err)
			}
		default:
			return fmt.Errorf("unsupported config file format: %s", ext)
		}
	}

	return nil
}

// loadFromFlags loads configuration from CLI flags
func (cl *ConfigLoader) loadFromFlags(config interface{}, flags map[string]interface{}) error {
	v := reflect.ValueOf(config).Elem()
	t := v.Type()

	return cl.loadFromFlagsRecursive(v, t, flags, "")
}

func (cl *ConfigLoader) loadFromFlagsRecursive(v reflect.Value, t reflect.Type, flags map[string]interface{}, prefix string) error {
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		if !field.CanSet() {
			continue
		}

		fieldName := fieldType.Name
		if flagTag := fieldType.Tag.Get("flag"); flagTag != "" {
			fieldName = flagTag
		}

		flagKey := strings.ToLower(prefix + fieldName)
		if prefix != "" {
			flagKey = prefix + "." + strings.ToLower(fieldName)
		}

		if flagValue, exists := flags[flagKey]; exists {
			if err := cl.setFieldValueFromInterface(field, flagValue); err != nil {
				return fmt.Errorf("failed to set field %s from flag %s: %w", fieldName, flagKey, err)
			}
		} else if field.Kind() == reflect.Struct {
			if err := cl.loadFromFlagsRecursive(field, fieldType.Type, flags, flagKey); err != nil {
				return err
			}
		}
	}

	return nil
}

// loadFromVault loads configuration from Vault
func (cl *ConfigLoader) loadFromVault(config interface{}) error {
	if cl.vaultClient == nil {
		return nil
	}

	v := reflect.ValueOf(config).Elem()
	t := v.Type()

	return cl.loadFromVaultRecursive(v, t, "")
}

func (cl *ConfigLoader) loadFromVaultRecursive(v reflect.Value, t reflect.Type, prefix string) error {
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		if !field.CanSet() {
			continue
		}

		vaultPath := fieldType.Tag.Get("vault")
		if vaultPath == "" {
			if field.Kind() == reflect.Struct {
				if err := cl.loadFromVaultRecursive(field, fieldType.Type, prefix+fieldType.Name+"."); err != nil {
					return err
				}
			}
			continue
		}

		secrets, err := cl.vaultClient.GetSecret(vaultPath)
		if err != nil {
			return fmt.Errorf("failed to get secret from vault path %s: %w", vaultPath, err)
		}

		fieldName := fieldType.Name
		if vaultKey := fieldType.Tag.Get("vault_key"); vaultKey != "" {
			fieldName = vaultKey
		}

		if secretValue, exists := secrets[strings.ToLower(fieldName)]; exists {
			if err := cl.setFieldValueFromInterface(field, secretValue); err != nil {
				return fmt.Errorf("failed to set field %s from vault: %w", fieldName, err)
			}
		}
	}

	return nil
}

// setFieldValue sets a field value from string
func (cl *ConfigLoader) setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetInt(intVal)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uintVal, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetUint(uintVal)
	case reflect.Float32, reflect.Float64:
		floatVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		field.SetFloat(floatVal)
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		field.SetBool(boolVal)
	case reflect.Slice:
		// Handle string slices
		if field.Type().Elem().Kind() == reflect.String {
			sliceVal := strings.Split(value, ",")
			for i, v := range sliceVal {
				sliceVal[i] = strings.TrimSpace(v)
			}
			field.Set(reflect.ValueOf(sliceVal))
		} else {
			return fmt.Errorf("unsupported slice type: %s", field.Type())
		}
	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}

	return nil
}

// setFieldValueFromInterface sets a field value from interface{}
func (cl *ConfigLoader) setFieldValueFromInterface(field reflect.Value, value interface{}) error {
	if value == nil {
		return nil
	}

	valueReflect := reflect.ValueOf(value)
	if field.Type() == valueReflect.Type() {
		field.Set(valueReflect)
		return nil
	}

	// Try to convert to string first, then use setFieldValue
	if str, ok := value.(string); ok {
		return cl.setFieldValue(field, str)
	}

	// Handle other types
	switch field.Kind() {
	case reflect.String:
		field.SetString(fmt.Sprintf("%v", value))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if intVal, ok := value.(int64); ok {
			field.SetInt(intVal)
		} else if intVal, ok := value.(int); ok {
			field.SetInt(int64(intVal))
		} else {
			return fmt.Errorf("cannot convert %T to int", value)
		}
	case reflect.Float32, reflect.Float64:
		if floatVal, ok := value.(float64); ok {
			field.SetFloat(floatVal)
		} else if floatVal, ok := value.(float32); ok {
			field.SetFloat(float64(floatVal))
		} else {
			return fmt.Errorf("cannot convert %T to float", value)
		}
	case reflect.Bool:
		if boolVal, ok := value.(bool); ok {
			field.SetBool(boolVal)
		} else {
			return fmt.Errorf("cannot convert %T to bool", value)
		}
	default:
		return fmt.Errorf("unsupported field type for interface conversion: %s", field.Kind())
	}

	return nil
}