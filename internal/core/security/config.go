package security

import (
	"time"
)

// ProductionSecurityConfig returns production-ready security configuration
func ProductionSecurityConfig() SecuritySystemConfig {
	return SecuritySystemConfig{
		Enabled: true,
		DDoSProtectionConfig: DDoSProtectionConfig{
			Enabled:                true,
			RateLimitConfig: RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 10,
				BurstSize:         20,
				WindowSize:        time.Minute,
				CleanupInterval:   5 * time.Minute,
			},
			IPFilterConfig: IPFilterConfig{
				Enabled:           true,
				WhitelistEnabled:  true,
				BlacklistEnabled:  true,
				AutoBlacklistEnabled: true,
				MaxFailedAttempts: 5,
				BlockDuration:     time.Hour,
				Whitelist:         []string{"127.0.0.1", "::1"},
				Blacklist:         []string{},
			},
			GeoBlockConfig: GeoBlockConfig{
				Enabled:           true,
				BlockedCountries:  []string{"CN", "RU", "KP"},
				AllowedCountries:  []string{"US", "CA", "GB", "DE", "FR", "JP", "AU", "ID"},
				DefaultAction:     "allow",
				StrictMode:        false,
			},
			CDNIntegration: CDNIntegrationConfig{
				Enabled:           true,
				Provider:          "cloudflare",
				AutoMitigation:    true,
				SensitivityLevel:  "medium",
				ChallengeEnabled:  true,
			},
			AdvancedConfig: AdvancedDDoSConfig{
				ConnectionTracking:    true,
				MaxConnectionsPerIP:   100,
				ConnectionTimeout:     30 * time.Second,
				SlowLorisProtection:   true,
				SynFloodProtection:    true,
				UDPFloodProtection:    true,
				ICMPFloodProtection:   true,
				BandwidthLimiting:     true,
				MaxBandwidthPerIP:     "10MB",
				AdaptiveThrottling:    true,
				MachineLearningEnabled: true,
			},
			MonitoringConfig: DDoSMonitoringConfig{
				Enabled:              true,
				MetricsInterval:      time.Minute,
				AlertThreshold:       1000,
				NotificationEnabled:  true,
				WebhookURL:           "",
				SlackWebhook:         "",
				EmailNotification:    true,
				LogLevel:             "info",
			},
		},
		BruteForceConfig: EnhancedBruteForceConfig{
			Enabled:                true,
			MaxAttempts:            5,
			LockoutDuration:        15 * time.Minute,
			WindowSize:             time.Hour,
			CleanupInterval:        10 * time.Minute,
			ProgressiveLockout:     true,
			AccountLockoutEnabled:  true,
			AccountLockoutThreshold: 10,
			AccountLockoutDuration: 24 * time.Hour,
			CaptchaConfig: CaptchaIntegrationConfig{
				Enabled:              true,
				TriggerAfterAttempts: 3,
				RequiredForLogin:     false,
				Difficulty:           "medium",
				Timeout:              5 * time.Minute,
			},
			TwoFAConfig: TwoFAIntegrationConfig{
				Enabled:              true,
				RequiredForSuspicious: true,
				RequiredForAdmin:     true,
				GracePeriod:          24 * time.Hour,
				BackupCodesEnabled:   true,
			},
			IPReputationConfig: IPReputationConfig{
				Enabled:              true,
				TrackingEnabled:      true,
				ReputationThreshold:  -50,
				DecayRate:            0.1,
				UpdateInterval:       time.Hour,
			},
			NotificationConfig: NotificationConfig{
				Enabled:              true,
				EmailEnabled:         true,
				SMSEnabled:           false,
				WebhookEnabled:       true,
				SlackEnabled:         false,
				ImmediateNotification: true,
				BatchNotification:    false,
				NotificationThreshold: 5,
			},
			AdvancedConfig: AdvancedBruteForceConfig{
				BehaviorAnalysis:     true,
				DeviceFingerprinting: true,
				GeoLocationTracking:  true,
				TimeBasedAnalysis:    true,
				MachineLearning:      true,
				HoneypotIntegration:  false,
				ThreatIntelligence:   true,
			},
		},
		SQLInjectionConfig: SQLInjectionConfig{
			Enabled:                true,
			StrictMode:             true,
			ValidationConfig: ValidationConfig{
				Enabled:               true,
				MaxInputLength:        1000,
				AllowedCharacters:     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@+",
				BlockSQLKeywords:      true,
				BlockScriptTags:       true,
				BlockComments:         true,
				NormalizeInput:        true,
				CaseSensitive:         false,
			},
			SanitizationConfig: SanitizationConfig{
				Enabled:               true,
				EscapeHTML:            true,
				EscapeSQL:             true,
				EscapeJavaScript:      true,
				RemoveNullBytes:       true,
				NormalizeUnicode:      true,
				TrimWhitespace:        true,
				ConvertToLowercase:    false,
			},
			DetectionConfig: DetectionConfig{
				Enabled:               true,
				PatternMatching:       true,
				HeuristicAnalysis:     true,
				MachineLearning:       true,
				SyntaxAnalysis:        true,
				SemanticAnalysis:      true,
				BehaviorAnalysis:      true,
				ConfidenceThreshold:   0.8,
			},
			RateLimitConfig: SQLRateLimitConfig{
				Enabled:               true,
				MaxAttemptsPerMinute:  10,
				MaxAttemptsPerHour:    50,
				BlockDuration:         time.Hour,
				WhitelistEnabled:      true,
				WhitelistedIPs:        []string{"127.0.0.1"},
			},
			LoggingConfig: SQLLoggingConfig{
				Enabled:               true,
				LogAllQueries:         false,
				LogSuspiciousQueries:  true,
				LogBlockedQueries:     true,
				IncludeStackTrace:     true,
				IncludeUserAgent:      true,
				IncludeReferer:        true,
				LogLevel:              "warn",
			},
		},
		WAFConfig: WAFConfig{
			Enabled:                true,
			StrictMode:             false,
			RateLimitConfig: WAFRateLimitConfig{
				Enabled:               true,
				RequestsPerSecond:     20,
				BurstSize:             50,
				WindowSize:            time.Minute,
				BlockDuration:         10 * time.Minute,
				WhitelistEnabled:      true,
				WhitelistedIPs:        []string{"127.0.0.1"},
			},
			GeoBlockingConfig: WAFGeoBlockingConfig{
				Enabled:               true,
				BlockedCountries:      []string{"CN", "RU", "KP", "IR"},
				AllowedCountries:      []string{"US", "CA", "GB", "DE", "FR", "JP", "AU", "ID", "SG", "MY"},
				DefaultAction:         "allow",
				StrictMode:            false,
				WhitelistEnabled:      true,
				WhitelistedIPs:        []string{"127.0.0.1"},
			},
			AntiAutomationConfig: AntiAutomationConfig{
				Enabled:               true,
				BotDetectionEnabled:   true,
				CrawlerDetectionEnabled: true,
				ScraperDetectionEnabled: true,
				ChallengeEnabled:      true,
				ChallengeThreshold:    5,
				ChallengeType:         "captcha",
				UserAgentValidation:   true,
				JavaScriptChallenge:   true,
				BehaviorAnalysis:      true,
			},
			ContentFilteringConfig: ContentFilteringConfig{
				Enabled:               true,
				XSSProtection:         true,
				SQLInjectionProtection: true,
				CSRFProtection:        true,
				LFIProtection:         true,
				RFIProtection:         true,
				CommandInjectionProtection: true,
				PathTraversalProtection: true,
				MalwareDetection:      true,
				VirusScanning:         false,
				ContentTypeValidation: true,
				FileSizeLimit:         10 * 1024 * 1024, // 10MB
				AllowedFileTypes:      []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx"},
			},
			CustomRulesConfig: CustomRulesConfig{
				Enabled:               true,
				RulesFile:             "./config/waf_rules.json",
				AutoReload:            true,
				ReloadInterval:        5 * time.Minute,
				ValidateRules:         true,
				DefaultAction:         "block",
			},
			LoggingConfig: WAFLoggingConfig{
				Enabled:               true,
				LogAllRequests:        false,
				LogBlockedRequests:    true,
				LogSuspiciousRequests: true,
				IncludeHeaders:        true,
				IncludeBody:           false,
				IncludeUserAgent:      true,
				IncludeReferer:        true,
				LogLevel:              "info",
				MaxLogSize:            100 * 1024 * 1024, // 100MB
				LogRotation:           true,
				RetentionDays:         30,
			},
		},
		MonitoringConfig: SecurityMonitorConfig{
			Enabled:                true,
			MetricsInterval:        time.Minute,
			AlertThreshold:         100,
			CriticalThreshold:      500,
			NotificationConfig: MonitoringNotificationConfig{
				Enabled:               true,
				WebhookURL:            "",
				SlackWebhook:          "",
				EmailEnabled:          true,
				SMSEnabled:            false,
				ImmediateAlerts:       true,
				BatchAlerts:           false,
				AlertCooldown:         5 * time.Minute,
			},
			MetricsConfig: MetricsConfig{
				Enabled:               true,
				CollectionInterval:    30 * time.Second,
				RetentionPeriod:       7 * 24 * time.Hour,
				AggregationEnabled:    true,
				AggregationInterval:   time.Hour,
				ExportEnabled:         true,
				ExportFormat:          "prometheus",
				ExportEndpoint:        "/metrics",
			},
			EventConfig: EventConfig{
				Enabled:               true,
				BufferSize:            1000,
				FlushInterval:         10 * time.Second,
				MaxEventSize:          1024,
				CompressionEnabled:    true,
				EncryptionEnabled:     false,
				RetentionPeriod:       30 * 24 * time.Hour,
			},
			DashboardConfig: DashboardConfig{
				Enabled:               true,
				Port:                  8080,
				Path:                  "/security-dashboard",
				AuthEnabled:           true,
				Username:              "admin",
				Password:              "secure_password_123",
				TLSEnabled:            true,
				RefreshInterval:       5 * time.Second,
				Theme:                 "dark",
			},
		},
		LoggingConfig: SecurityLoggerConfig{
			Enabled:                true,
			LogLevel:               "info",
			OutputTargets: []LogOutputTarget{
				{
					Type:     "file",
					Path:     "./logs/security.log",
					Enabled:  true,
					Format:   "json",
				},
				{
					Type:     "console",
					Enabled:  true,
					Format:   "text",
				},
				{
					Type:     "syslog",
					Enabled:  false,
					Address:  "localhost:514",
					Format:   "json",
				},
			},
			SamplingConfig: SamplingConfig{
				Enabled:               false,
				SampleRate:            0.1,
				MaxSamplesPerSecond:   100,
				PriorityBasedSampling: true,
			},
			EncryptionConfig: LogEncryptionConfig{
				Enabled:               false,
				Algorithm:             "AES-256-GCM",
				KeyRotationEnabled:    true,
				KeyRotationInterval:   24 * time.Hour,
			},
			MaskingConfig: DataMaskingConfig{
				Enabled:               true,
				MaskPasswords:         true,
				MaskCreditCards:       true,
				MaskSSN:               true,
				MaskEmails:            false,
				MaskIPs:               false,
				CustomPatterns:        []string{},
				MaskingCharacter:      "*",
			},
			RotationConfig: LogRotationConfig{
				Enabled:               true,
				MaxSize:               100 * 1024 * 1024, // 100MB
				MaxAge:                7 * 24 * time.Hour,
				MaxBackups:            10,
				Compress:              true,
				RotationSchedule:      "daily",
			},
			BufferConfig: LogBufferConfig{
				Enabled:               true,
				BufferSize:            1000,
				FlushInterval:         5 * time.Second,
				MaxBufferSize:         10000,
				FlushOnShutdown:       true,
			},
		},
		TestingConfig: SecurityTestConfig{
			Enabled:                true,
			TestTimeout:            30 * time.Minute,
			MaxConcurrentTests:     5,
			PenetrationTestConfig: PenetrationTestConfig{
				Enabled:               true,
				TargetURL:             "http://localhost:8080",
				TestSuites:            []string{"owasp-top10", "sql-injection", "xss", "csrf", "authentication"},
				MaxTestDuration:       15 * time.Minute,
				ConcurrentTests:       3,
				ReportFormat:          "json",
				ReportPath:            "./reports/pentest",
				VerboseOutput:         true,
			},
			LoadTestConfig: LoadTestConfig{
				Enabled:               true,
				TargetURL:             "http://localhost:8080",
				ConcurrentUsers:       100,
				RequestsPerSecond:     50,
				TestDuration:          5 * time.Minute,
				RampUpTime:            30 * time.Second,
				RampDownTime:          30 * time.Second,
				ReportFormat:          "json",
				ReportPath:            "./reports/loadtest",
				Thresholds: LoadTestThresholds{
					MaxResponseTime:       2 * time.Second,
					MaxErrorRate:          0.01, // 1%
					MinThroughput:         45,
				},
			},
			VulnerabilityTestConfig: VulnerabilityTestConfig{
				Enabled:               true,
				TargetURL:             "http://localhost:8080",
				ScanDepth:             3,
				MaxScanTime:           20 * time.Minute,
				ScanTypes:             []string{"sql-injection", "xss", "csrf", "lfi", "rfi", "command-injection"},
				ReportFormat:          "json",
				ReportPath:            "./reports/vulnscan",
				SeverityThreshold:     "medium",
				IncludeInformational:  false,
			},
			FuzzTestConfig: FuzzTestConfig{
				Enabled:               true,
				TargetURL:             "http://localhost:8080",
				MaxIterations:         10000,
				MaxTestTime:           10 * time.Minute,
				PayloadSets:           []string{"sql-injection", "xss", "buffer-overflow", "format-string"},
				MutationStrategies:    []string{"random", "boundary", "format", "encoding"},
				ReportFormat:          "json",
				ReportPath:            "./reports/fuzztest",
				CrashDetection:        true,
				MemoryLeakDetection:   true,
			},
			ScheduleConfig: TestScheduleConfig{
				Enabled:               true,
				RunOnStart:            true,
				DailyTests:            true,
				DailyTestTime:         "02:00",
				WeeklyTests:           true,
				WeeklyTestDay:         "sunday",
				WeeklyTestTime:        "03:00",
				MonthlyTests:          true,
				MonthlyTestDay:        1,
				MonthlyTestTime:       "04:00",
			},
			NotificationConfig: TestNotificationConfig{
				Enabled:               true,
				EmailEnabled:          true,
				SlackEnabled:          false,
				WebhookEnabled:        true,
				NotifyOnFailure:       true,
				NotifyOnSuccess:       false,
				NotifyOnCritical:      true,
				IncludeReports:        true,
			},
		},
		CaptchaConfig: CaptchaConfig{
			Enabled:                true,
			Provider:               "internal",
			Difficulty:             "medium",
			Length:                 6,
			Width:                  200,
			Height:                 80,
			Expiration:             5 * time.Minute,
			MaxAttempts:            3,
			CaseSensitive:          false,
			NoiseLevel:             0.3,
			DistortionLevel:        0.2,
			FontSize:               24,
			BackgroundColor:        "#FFFFFF",
			TextColor:              "#000000",
			NoiseColor:             "#CCCCCC",
			MathCaptchaEnabled:     true,
			ImageCaptchaEnabled:    true,
			AudioCaptchaEnabled:    false,
			ReCaptchaConfig: ReCaptchaConfig{
				Enabled:               false,
				SiteKey:               "",
				SecretKey:             "",
				Version:               "v2",
				Theme:                 "light",
				Size:                  "normal",
			},
			HCaptchaConfig: HCaptchaConfig{
				Enabled:               false,
				SiteKey:               "",
				SecretKey:             "",
				Theme:                 "light",
				Size:                  "normal",
			},
			CleanupConfig: CaptchaCleanupConfig{
				Enabled:               true,
				CleanupInterval:       10 * time.Minute,
				MaxAge:                time.Hour,
				MaxEntries:            10000,
			},
		},
		TwoFAConfig: TwoFAConfig{
			Enabled:                true,
			Issuer:                 "SecureApp",
			AccountName:            "user@example.com",
			SecretLength:           32,
			CodeLength:             6,
			TimeStep:               30 * time.Second,
			Skew:                   1,
			BackupCodesEnabled:     true,
			BackupCodesCount:       10,
			BackupCodeLength:       8,
			SessionTimeout:         24 * time.Hour,
			MaxSessions:            5,
			RequireForAdmin:        true,
			RequireForSensitive:    true,
			GracePeriod:            7 * 24 * time.Hour,
			QRCodeConfig: QRCodeConfig{
				Enabled:               true,
				Size:                  256,
				ErrorCorrectionLevel:  "medium",
				BorderSize:            4,
			},
			NotificationConfig: TwoFANotificationConfig{
				Enabled:               true,
				EmailEnabled:          true,
				SMSEnabled:            false,
				NotifyOnSetup:         true,
				NotifyOnDisable:       true,
				NotifyOnBackupUse:     true,
				NotifyOnSuspicious:    true,
			},
			CleanupConfig: TwoFACleanupConfig{
				Enabled:               true,
				CleanupInterval:       time.Hour,
				MaxSessionAge:         7 * 24 * time.Hour,
				MaxSecretAge:          90 * 24 * time.Hour,
			},
		},
		GeoIPConfig: GeoIPConfig{
			Enabled:                true,
			Provider:               "enhanced",
			DatabasePath:           "./data/GeoLite2-Country.mmdb",
			APIKey:                 "",
			CacheEnabled:           true,
			CacheTTL:               24 * time.Hour,
			UpdateInterval:         7 * 24 * time.Hour,
		},
		CDNConfig: CDNConfig{
			Enabled:                true,
			Provider:               "cloudflare",
			APIKey:                 "",
			Email:                  "",
			ZoneID:                 "",
			BaseURL:                "https://api.cloudflare.com/client/v4",
			Timeout:                30 * time.Second,
			RetryAttempts:          3,
			RetryDelay:             time.Second,
			RateLimitConfig: CDNRateLimitConfig{
				Enabled:               true,
				RequestsPerSecond:     10,
				BurstSize:             20,
			},
			CacheConfig: CDNCacheConfig{
				Enabled:               true,
				DefaultTTL:            24 * time.Hour,
				MaxTTL:                7 * 24 * time.Hour,
				MinTTL:                time.Hour,
				PurgeOnUpdate:         true,
			},
			SecurityConfig: CDNSecurityConfig{
				Enabled:               true,
				DDoSProtection:        true,
				WAFEnabled:            true,
				BotManagement:         true,
				SSLEnabled:            true,
				HSTSEnabled:           true,
			},
		},
		GlobalSettings: GlobalSecuritySettings{
			SecurityLevel:          "high",
			StrictMode:             false,
			MaintenanceMode:        false,
			EmergencyMode:          false,
			DebugMode:              false,
			HealthCheckInterval:    30 * time.Second,
			MetricsRetention:       7 * 24 * time.Hour,
			AutoUpdate:             false,
			FailsafeMode:           true,
			PerformanceMode:        false,
		},
	}
}

// DevelopmentSecurityConfig returns development-friendly security configuration
func DevelopmentSecurityConfig() SecuritySystemConfig {
	config := ProductionSecurityConfig()
	
	// Relax settings for development
	config.GlobalSettings.SecurityLevel = "medium"
	config.GlobalSettings.DebugMode = true
	config.GlobalSettings.StrictMode = false
	
	// More permissive rate limiting
	config.DDoSProtectionConfig.RateLimitConfig.RequestsPerSecond = 100
	config.DDoSProtectionConfig.RateLimitConfig.BurstSize = 200
	
	// Disable geo-blocking for development
	config.DDoSProtectionConfig.GeoBlockConfig.Enabled = false
	config.WAFConfig.GeoBlockingConfig.Enabled = false
	
	// More lenient brute force protection
	config.BruteForceConfig.MaxAttempts = 10
	config.BruteForceConfig.LockoutDuration = 5 * time.Minute
	
	// Disable some advanced features
	config.BruteForceConfig.AdvancedConfig.MachineLearning = false
	config.SQLInjectionConfig.DetectionConfig.MachineLearning = false
	
	// Reduce testing frequency
	config.TestingConfig.ScheduleConfig.DailyTests = false
	config.TestingConfig.ScheduleConfig.WeeklyTests = false
	config.TestingConfig.ScheduleConfig.MonthlyTests = false
	
	// Enable console logging
	for i := range config.LoggingConfig.OutputTargets {
		if config.LoggingConfig.OutputTargets[i].Type == "console" {
			config.LoggingConfig.OutputTargets[i].Enabled = true
		}
	}
	
	return config
}

// TestingSecurityConfig returns configuration optimized for testing
func TestingSecurityConfig() SecuritySystemConfig {
	config := DevelopmentSecurityConfig()
	
	// Minimal security for testing
	config.GlobalSettings.SecurityLevel = "low"
	
	// Very permissive rate limiting
	config.DDoSProtectionConfig.RateLimitConfig.RequestsPerSecond = 1000
	config.DDoSProtectionConfig.RateLimitConfig.BurstSize = 2000
	
	// Disable most protections
	config.DDoSProtectionConfig.Enabled = false
	config.WAFConfig.Enabled = false
	config.BruteForceConfig.Enabled = false
	
	// Keep only basic monitoring and logging
	config.MonitoringConfig.Enabled = true
	config.LoggingConfig.Enabled = true
	
	// Disable testing during tests
	config.TestingConfig.Enabled = false
	
	return config
}

// MaximumSecurityConfig returns maximum security configuration
func MaximumSecurityConfig() SecuritySystemConfig {
	config := ProductionSecurityConfig()
	
	// Maximum security level
	config.GlobalSettings.SecurityLevel = "maximum"
	config.GlobalSettings.StrictMode = true
	
	// Very strict rate limiting
	config.DDoSProtectionConfig.RateLimitConfig.RequestsPerSecond = 5
	config.DDoSProtectionConfig.RateLimitConfig.BurstSize = 10
	
	// Enable all advanced features
	config.DDoSProtectionConfig.AdvancedConfig.MachineLearningEnabled = true
	config.BruteForceConfig.AdvancedConfig.MachineLearning = true
	config.SQLInjectionConfig.DetectionConfig.MachineLearning = true
	
	// Strict brute force protection
	config.BruteForceConfig.MaxAttempts = 3
	config.BruteForceConfig.LockoutDuration = time.Hour
	config.BruteForceConfig.AccountLockoutThreshold = 5
	
	// Enable all WAF protections
	config.WAFConfig.StrictMode = true
	config.WAFConfig.AntiAutomationConfig.ChallengeThreshold = 1
	
	// Enable all monitoring and alerting
	config.MonitoringConfig.AlertThreshold = 10
	config.MonitoringConfig.CriticalThreshold = 50
	
	// Enable comprehensive testing
	config.TestingConfig.ScheduleConfig.DailyTests = true
	config.TestingConfig.ScheduleConfig.WeeklyTests = true
	config.TestingConfig.ScheduleConfig.MonthlyTests = true
	
	return config
}