package dependency

// DependencyFileType represents the type of dependency file
type DependencyFileType string

const (
	ManifestFile DependencyFileType = "manifest" // e.g. package.json, go.mod
	LockFile     DependencyFileType = "lockfile" // e.g. package-lock.json, go.sum
	ConfigFile   DependencyFileType = "config"   // e.g. pyproject.toml
	BinaryFile   DependencyFileType = "binary"   // e.g. .jar
)

// PackageManager represents the package manager used
type PackageManager string

const (
	NPM      PackageManager = "npm"
	Yarn     PackageManager = "yarn"
	Pip      PackageManager = "pip"
	Poetry   PackageManager = "poetry"
	GoMod    PackageManager = "go"
	Bundler  PackageManager = "bundler"
	Maven    PackageManager = "maven"
	Gradle   PackageManager = "gradle"
	Cargo    PackageManager = "cargo"
	Composer PackageManager = "composer"
	Unknown  PackageManager = "unknown"
)

// Language represents the programming language
type Language string

const (
	JavaScript Language = "javascript"
	TypeScript Language = "typescript"
	Python     Language = "python"
	Go         Language = "go"
	Ruby       Language = "ruby"
	Java       Language = "java"
	Rust       Language = "rust"
	PHP        Language = "php"
	CSharp     Language = "csharp"
)

// DependencyFile represents a detected dependency file
type DependencyFile struct {
	Path           string
	Type           DependencyFileType
	PackageManager PackageManager
	Language       Language
}

// ManifestMetadata contains metadata about the project from the manifest
type ManifestMetadata struct {
	ProjectName    string
	ProjectVersion string
	Language       string
	LockFileExists bool
	LockFilePath   string
}

// DependencyType represents the type of dependency relation
type DependencyType string

const (
	Production  DependencyType = "production"
	Development DependencyType = "development"
	Optional    DependencyType = "optional"
	Peer        DependencyType = "peer"
)

// Dependency represents a single package dependency
type Dependency struct {
	Name              string
	Version           string
	VersionConstraint string // e.g., "^1.2.3", ">=2.0.0"
	Type              DependencyType
	IsDirect          bool
	IsTransitive      bool
	Parent            string // Name of the parent dependency if transitive
	License           string
	Repository        string
	Deprecated        bool
	Vulnerabilities   []Vulnerability
}

// Vulnerability represents a security issue in a dependency
type Vulnerability struct {
	ID          string // CVE or GHSA ID
	Title       string
	Description string
	Severity    string
	CVSS        float64
	FixedIn     string
	Dismissed   bool
}

// DependencyManifest represents the parsed result of a dependency file
type DependencyManifest struct {
	FilePath           string
	PackageManager     PackageManager
	DirectDependencies []Dependency
	DevDependencies    []Dependency
	AllDependencies    []Dependency // Flattened list including transitive
	Metadata           ManifestMetadata
}
