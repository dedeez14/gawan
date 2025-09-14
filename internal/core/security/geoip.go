package security

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// SimpleGeoIPResolver implements a simple GeoIP resolver using free services
type SimpleGeoIPResolver struct {
	databasePath string
	client       *http.Client
}

// GeoIPResponse represents the response from GeoIP service
type GeoIPResponse struct {
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Region      string `json:"region"`
	City        string `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// NewGeoIPResolver creates a new GeoIP resolver
func NewGeoIPResolver(databasePath string) GeoIPResolver {
	return &SimpleGeoIPResolver{
		databasePath: databasePath,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// GetCountryCode returns the country code for the given IP
func (g *SimpleGeoIPResolver) GetCountryCode(ip string) (string, error) {
	// Validate IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}
	
	// Skip private/local IPs
	if isPrivateIP(parsedIP) {
		return "LOCAL", nil
	}
	
	// If database path is provided, try to use local database first
	if g.databasePath != "" {
		if countryCode, err := g.getCountryFromDatabase(ip); err == nil {
			return countryCode, nil
		}
	}
	
	// Fall back to online service
	return g.getCountryFromOnlineService(ip)
}

// getCountryFromDatabase gets country from local GeoIP database
func (g *SimpleGeoIPResolver) getCountryFromDatabase(ip string) (string, error) {
	// This would integrate with MaxMind GeoIP2 or similar database
	// For now, return error to fall back to online service
	return "", fmt.Errorf("local database not implemented")
}

// getCountryFromOnlineService gets country from online GeoIP service
func (g *SimpleGeoIPResolver) getCountryFromOnlineService(ip string) (string, error) {
	// Use ip-api.com (free service with rate limits)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=countryCode", ip)
	
	resp, err := g.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query GeoIP service: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GeoIP service returned status %d", resp.StatusCode)
	}
	
	var geoResp struct {
		CountryCode string `json:"countryCode"`
		Status      string `json:"status"`
		Message     string `json:"message"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&geoResp); err != nil {
		return "", fmt.Errorf("failed to decode GeoIP response: %w", err)
	}
	
	if geoResp.Status != "success" {
		return "", fmt.Errorf("GeoIP service error: %s", geoResp.Message)
	}
	
	return geoResp.CountryCode, nil
}

// isPrivateIP checks if an IP is private/local
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	
	// Check private IPv4 ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	
	// Check private IPv6 ranges
	if ip.To4() == nil {
		// fc00::/7 (Unique Local Addresses)
		if ip[0] >= 0xfc && ip[0] <= 0xfd {
			return true
		}
	}
	
	return false
}

// MockGeoIPResolver is a mock implementation for testing
type MockGeoIPResolver struct {
	mappings map[string]string
}

// NewMockGeoIPResolver creates a new mock GeoIP resolver
func NewMockGeoIPResolver(mappings map[string]string) GeoIPResolver {
	return &MockGeoIPResolver{
		mappings: mappings,
	}
}

// GetCountryCode returns the country code for the given IP from mappings
func (m *MockGeoIPResolver) GetCountryCode(ip string) (string, error) {
	if countryCode, exists := m.mappings[ip]; exists {
		return countryCode, nil
	}
	
	// Default to US for unknown IPs
	return "US", nil
}

// EnhancedGeoIPResolver implements enhanced GeoIP resolution with caching
type EnhancedGeoIPResolver struct {
	resolver GeoIPResolver
	cache    map[string]geoIPCacheEntry
	cacheTTL time.Duration
}

type geoIPCacheEntry struct {
	countryCode string
	expiry      time.Time
}

// NewEnhancedGeoIPResolver creates an enhanced GeoIP resolver with caching
func NewEnhancedGeoIPResolver(resolver GeoIPResolver, cacheTTL time.Duration) GeoIPResolver {
	return &EnhancedGeoIPResolver{
		resolver: resolver,
		cache:    make(map[string]geoIPCacheEntry),
		cacheTTL: cacheTTL,
	}
}

// GetCountryCode returns the country code with caching
func (e *EnhancedGeoIPResolver) GetCountryCode(ip string) (string, error) {
	// Check cache first
	if entry, exists := e.cache[ip]; exists && time.Now().Before(entry.expiry) {
		return entry.countryCode, nil
	}
	
	// Get from underlying resolver
	countryCode, err := e.resolver.GetCountryCode(ip)
	if err != nil {
		return "", err
	}
	
	// Cache the result
	e.cache[ip] = geoIPCacheEntry{
		countryCode: countryCode,
		expiry:      time.Now().Add(e.cacheTTL),
	}
	
	// Clean expired entries periodically
	go e.cleanExpiredEntries()
	
	return countryCode, nil
}

// cleanExpiredEntries removes expired cache entries
func (e *EnhancedGeoIPResolver) cleanExpiredEntries() {
	now := time.Now()
	for ip, entry := range e.cache {
		if now.After(entry.expiry) {
			delete(e.cache, ip)
		}
	}
}

// GetCountryName returns the full country name for a country code
func GetCountryName(countryCode string) string {
	countryNames := map[string]string{
		"AD": "Andorra",
		"AE": "United Arab Emirates",
		"AF": "Afghanistan",
		"AG": "Antigua and Barbuda",
		"AI": "Anguilla",
		"AL": "Albania",
		"AM": "Armenia",
		"AO": "Angola",
		"AQ": "Antarctica",
		"AR": "Argentina",
		"AS": "American Samoa",
		"AT": "Austria",
		"AU": "Australia",
		"AW": "Aruba",
		"AX": "Åland Islands",
		"AZ": "Azerbaijan",
		"BA": "Bosnia and Herzegovina",
		"BB": "Barbados",
		"BD": "Bangladesh",
		"BE": "Belgium",
		"BF": "Burkina Faso",
		"BG": "Bulgaria",
		"BH": "Bahrain",
		"BI": "Burundi",
		"BJ": "Benin",
		"BL": "Saint Barthélemy",
		"BM": "Bermuda",
		"BN": "Brunei Darussalam",
		"BO": "Bolivia",
		"BQ": "Bonaire, Sint Eustatius and Saba",
		"BR": "Brazil",
		"BS": "Bahamas",
		"BT": "Bhutan",
		"BV": "Bouvet Island",
		"BW": "Botswana",
		"BY": "Belarus",
		"BZ": "Belize",
		"CA": "Canada",
		"CC": "Cocos (Keeling) Islands",
		"CD": "Congo, Democratic Republic of the",
		"CF": "Central African Republic",
		"CG": "Congo",
		"CH": "Switzerland",
		"CI": "Côte d'Ivoire",
		"CK": "Cook Islands",
		"CL": "Chile",
		"CM": "Cameroon",
		"CN": "China",
		"CO": "Colombia",
		"CR": "Costa Rica",
		"CU": "Cuba",
		"CV": "Cabo Verde",
		"CW": "Curaçao",
		"CX": "Christmas Island",
		"CY": "Cyprus",
		"CZ": "Czechia",
		"DE": "Germany",
		"DJ": "Djibouti",
		"DK": "Denmark",
		"DM": "Dominica",
		"DO": "Dominican Republic",
		"DZ": "Algeria",
		"EC": "Ecuador",
		"EE": "Estonia",
		"EG": "Egypt",
		"EH": "Western Sahara",
		"ER": "Eritrea",
		"ES": "Spain",
		"ET": "Ethiopia",
		"FI": "Finland",
		"FJ": "Fiji",
		"FK": "Falkland Islands (Malvinas)",
		"FM": "Micronesia, Federated States of",
		"FO": "Faroe Islands",
		"FR": "France",
		"GA": "Gabon",
		"GB": "United Kingdom",
		"GD": "Grenada",
		"GE": "Georgia",
		"GF": "French Guiana",
		"GG": "Guernsey",
		"GH": "Ghana",
		"GI": "Gibraltar",
		"GL": "Greenland",
		"GM": "Gambia",
		"GN": "Guinea",
		"GP": "Guadeloupe",
		"GQ": "Equatorial Guinea",
		"GR": "Greece",
		"GS": "South Georgia and the South Sandwich Islands",
		"GT": "Guatemala",
		"GU": "Guam",
		"GW": "Guinea-Bissau",
		"GY": "Guyana",
		"HK": "Hong Kong",
		"HM": "Heard Island and McDonald Islands",
		"HN": "Honduras",
		"HR": "Croatia",
		"HT": "Haiti",
		"HU": "Hungary",
		"ID": "Indonesia",
		"IE": "Ireland",
		"IL": "Israel",
		"IM": "Isle of Man",
		"IN": "India",
		"IO": "British Indian Ocean Territory",
		"IQ": "Iraq",
		"IR": "Iran, Islamic Republic of",
		"IS": "Iceland",
		"IT": "Italy",
		"JE": "Jersey",
		"JM": "Jamaica",
		"JO": "Jordan",
		"JP": "Japan",
		"KE": "Kenya",
		"KG": "Kyrgyzstan",
		"KH": "Cambodia",
		"KI": "Kiribati",
		"KM": "Comoros",
		"KN": "Saint Kitts and Nevis",
		"KP": "Korea, Democratic People's Republic of",
		"KR": "Korea, Republic of",
		"KW": "Kuwait",
		"KY": "Cayman Islands",
		"KZ": "Kazakhstan",
		"LA": "Lao People's Democratic Republic",
		"LB": "Lebanon",
		"LC": "Saint Lucia",
		"LI": "Liechtenstein",
		"LK": "Sri Lanka",
		"LR": "Liberia",
		"LS": "Lesotho",
		"LT": "Lithuania",
		"LU": "Luxembourg",
		"LV": "Latvia",
		"LY": "Libya",
		"MA": "Morocco",
		"MC": "Monaco",
		"MD": "Moldova, Republic of",
		"ME": "Montenegro",
		"MF": "Saint Martin (French part)",
		"MG": "Madagascar",
		"MH": "Marshall Islands",
		"MK": "North Macedonia",
		"ML": "Mali",
		"MM": "Myanmar",
		"MN": "Mongolia",
		"MO": "Macao",
		"MP": "Northern Mariana Islands",
		"MQ": "Martinique",
		"MR": "Mauritania",
		"MS": "Montserrat",
		"MT": "Malta",
		"MU": "Mauritius",
		"MV": "Maldives",
		"MW": "Malawi",
		"MX": "Mexico",
		"MY": "Malaysia",
		"MZ": "Mozambique",
		"NA": "Namibia",
		"NC": "New Caledonia",
		"NE": "Niger",
		"NF": "Norfolk Island",
		"NG": "Nigeria",
		"NI": "Nicaragua",
		"NL": "Netherlands",
		"NO": "Norway",
		"NP": "Nepal",
		"NR": "Nauru",
		"NU": "Niue",
		"NZ": "New Zealand",
		"OM": "Oman",
		"PA": "Panama",
		"PE": "Peru",
		"PF": "French Polynesia",
		"PG": "Papua New Guinea",
		"PH": "Philippines",
		"PK": "Pakistan",
		"PL": "Poland",
		"PM": "Saint Pierre and Miquelon",
		"PN": "Pitcairn",
		"PR": "Puerto Rico",
		"PS": "Palestine, State of",
		"PT": "Portugal",
		"PW": "Palau",
		"PY": "Paraguay",
		"QA": "Qatar",
		"RE": "Réunion",
		"RO": "Romania",
		"RS": "Serbia",
		"RU": "Russian Federation",
		"RW": "Rwanda",
		"SA": "Saudi Arabia",
		"SB": "Solomon Islands",
		"SC": "Seychelles",
		"SD": "Sudan",
		"SE": "Sweden",
		"SG": "Singapore",
		"SH": "Saint Helena, Ascension and Tristan da Cunha",
		"SI": "Slovenia",
		"SJ": "Svalbard and Jan Mayen",
		"SK": "Slovakia",
		"SL": "Sierra Leone",
		"SM": "San Marino",
		"SN": "Senegal",
		"SO": "Somalia",
		"SR": "Suriname",
		"SS": "South Sudan",
		"ST": "Sao Tome and Principe",
		"SV": "El Salvador",
		"SX": "Sint Maarten (Dutch part)",
		"SY": "Syrian Arab Republic",
		"SZ": "Eswatini",
		"TC": "Turks and Caicos Islands",
		"TD": "Chad",
		"TF": "French Southern Territories",
		"TG": "Togo",
		"TH": "Thailand",
		"TJ": "Tajikistan",
		"TK": "Tokelau",
		"TL": "Timor-Leste",
		"TM": "Turkmenistan",
		"TN": "Tunisia",
		"TO": "Tonga",
		"TR": "Turkey",
		"TT": "Trinidad and Tobago",
		"TV": "Tuvalu",
		"TW": "Taiwan, Province of China",
		"TZ": "Tanzania, United Republic of",
		"UA": "Ukraine",
		"UG": "Uganda",
		"UM": "United States Minor Outlying Islands",
		"US": "United States of America",
		"UY": "Uruguay",
		"UZ": "Uzbekistan",
		"VA": "Holy See",
		"VC": "Saint Vincent and the Grenadines",
		"VE": "Venezuela, Bolivarian Republic of",
		"VG": "Virgin Islands, British",
		"VI": "Virgin Islands, U.S.",
		"VN": "Viet Nam",
		"VU": "Vanuatu",
		"WF": "Wallis and Futuna",
		"WS": "Samoa",
		"YE": "Yemen",
		"YT": "Mayotte",
		"ZA": "South Africa",
		"ZM": "Zambia",
		"ZW": "Zimbabwe",
		"LOCAL": "Local/Private Network",
	}
	
	if name, exists := countryNames[strings.ToUpper(countryCode)]; exists {
		return name
	}
	return "Unknown"
}