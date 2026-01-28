module github.com/code-security-auditor

go 1.25.6

require (
	// Web Framework
	github.com/gin-gonic/gin v1.10.0

	// Git Operations
	github.com/go-git/go-git/v5 v5.12.0
	github.com/google/go-github/v57 v57.0.0

	// Static Analysis
	golang.org/x/tools v0.27.0
	github.com/securego/gosec/v2 v2.21.4
	honnef.co/go/tools v0.5.1

	// Database
	github.com/lib/pq v1.10.9
	github.com/go-redis/redis/v8 v8.11.5
	github.com/jmoiron/sqlx v1.4.0

	// Configuration
	github.com/spf13/viper v1.19.0
	github.com/joho/godotenv v1.5.1

	// Queue (Redis-based)
	github.com/hibiken/asynq v0.25.0

	// ADK/AI - Google Cloud
	google.golang.org/api v0.209.0
	cloud.google.com/go/aiplatform v1.68.0
	google.golang.org/genai v0.2.0

	// Utilities
	github.com/google/uuid v1.6.0
	github.com/sirupsen/logrus v1.9.3
	gopkg.in/yaml.v3 v3.0.1

	// PDF Generation
	github.com/jung-kurt/gofpdf v1.16.2

	// Testing
	github.com/stretchr/testify v1.9.0
	github.com/DATA-DOG/go-sqlmock v1.5.2

	// CLI
	github.com/spf13/cobra v1.8.1
)

require (
	// Indirect dependencies will be added by go mod tidy
	github.com/bytedance/sonic v1.12.6 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.7 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.6.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.23.0 // indirect
	github.com/goccy/go-json v0.10.4 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/magiconair/properties v1.8.9 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/sagikazarmark/locafero v0.6.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/arch v0.12.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/exp v0.0.0-20241217172543-b2144cdd0a67 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.8.0 // indirect
	google.golang.org/protobuf v1.36.0 // indirect
)
