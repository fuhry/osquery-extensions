package flatpak

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"regexp"
	"strings"

	"github.com/linuxdeepin/go-lib/users/passwd"
)

type PackageType string

type IPackage interface {
	Id() string
	Name() string
	Version() string
	Architecture() string
	Branch() string
	Hash() string
	Type() PackageType
	User() string
}

type packagePrimitive struct {
	id     string
	user   string
	t      PackageType
	arch   string
	branch string
	hash   string
}

type ArchitectureBranch struct {
	Architecture string
	Branch       string
}

const (
	TypeApp     PackageType = "app"
	TypeRuntime PackageType = "runtime"
)

const (
	SymlinkCurrentArchitecture = "current"
	SymlinkActiveHash          = "active"
)

var (
	systemLocation = "/var/lib/flatpak"
	userLocation   = ".local/share/flatpak"

	subpaths = []PackageType{
		TypeApp,
		TypeRuntime,
	}
	applicationIdRegexp = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?))*$`)
)

func Packages() (out []IPackage) {
	type scanLocation struct {
		baseDir string
		user    string
	}

	scanLocations := []scanLocation{
		{systemLocation, ""},
	}

	for _, entry := range passwd.GetPasswdEntry() {
		userDir := path.Join(entry.Home, userLocation)
		if st, err := os.Stat(userDir); err == nil && st.IsDir() {
			scanLocations = append(scanLocations, scanLocation{userDir, entry.Name})
		}
	}

	for _, loc := range scanLocations {
		for _, sub := range subpaths {
			dir := path.Join(loc.baseDir, string(sub))
			if entries, err := os.ReadDir(dir); err == nil {
				for _, entry := range entries {
					if !entry.IsDir() || !applicationIdRegexp.MatchString(entry.Name()) {
						continue
					}
					pp := &packagePrimitive{
						id:   entry.Name(),
						user: loc.user,
						t:    sub,
					}

					if ab, err := pp.architecturesAndBranches(); err == nil {
						for _, ab := range ab {
							out = append(out, pp.WithArchBranch(ab.Architecture, ab.Branch))
						}
					}
				}
			}
		}
	}

	return
}

// Id implements IPackage
func (pp *packagePrimitive) Id() string {
	return pp.id
}

// Name implements IPackage
func (pp *packagePrimitive) Name() string {
	return pp.getMetadataString(kAppName)
}

// Version implements IPackage
func (pp *packagePrimitive) Version() string {
	return pp.getMetadataString(kAppVersion)
}

func (pp *packagePrimitive) getMetadataString(k string) string {
	deploy, err := pp.parseDeployFile()
	if err != nil {
		log.Printf("failed to parseDeployFile: %+v", err)
		return ""
	}

	if key, ok := deploy.GetMetadata(k); ok {
		if v, err := VariantValue(key, binary.BigEndian); err == nil {
			if name, ok := v.(string); ok {
				return name
			}
		}
	}

	return ""
}

// Architecture implements IPackage
func (pp *packagePrimitive) Architecture() string {
	a, _, _ := pp.currentArchitectureAndBranch()
	return a
}

// Branch implements IPackage
func (pp *packagePrimitive) Branch() string {
	b, _, _ := pp.currentArchitectureAndBranch()
	return b
}

// Hash implements IPackage
func (pp *packagePrimitive) Hash() string {
	h, _ := pp.activeHash()
	return h
}

// Type implements IPackage
func (pp *packagePrimitive) Type() PackageType {
	return pp.t
}

// User implements IPackage
func (pp *packagePrimitive) User() string {
	return pp.user
}

func (pp *packagePrimitive) dir() (string, error) {
	if pp.user == "" {
		return path.Join(systemLocation, string(pp.t), pp.id), nil
	}

	u, err := user.Lookup(pp.user)
	if err != nil {
		return "", err
	}

	return path.Join(u.HomeDir, userLocation, string(pp.t), pp.id), nil
}

func (pp *packagePrimitive) currentArchitectureAndBranch() (string, string, error) {
	if pp.arch != "" && pp.branch != "" {
		return pp.arch, pp.branch, nil
	}

	dir, err := pp.dir()
	if err != nil {
		return "", "", err
	}

	if link, err := os.Readlink(path.Join(dir, SymlinkCurrentArchitecture)); err == nil {
		parts := strings.Split(link, string(os.PathSeparator))
		if len(parts) == 2 {
			pp.arch = parts[0]
			pp.branch = parts[1]
		} else {
			return "", "", fmt.Errorf("invalid format of %q symlink: %s: expected arch/branch",
				SymlinkCurrentArchitecture, link)
		}
	} else {
		archs, err := subdirs(dir)
		if err != nil {
			return "", "", fmt.Errorf("failed to list architectures for package %s: %v", pp.id, err)
		}
		if len(archs) != 1 {
			return "", "", fmt.Errorf("package %s does not have exactly 1 architecture", pp.id)
		}

		pp.arch = archs[0]

		branches, err := subdirs(path.Join(dir, archs[0]))
		if err != nil {
			return "", "", fmt.Errorf("failed to list branches for package %s and arch %s: %v", pp.id, archs[0], err)
		}

		if len(branches) != 1 {
			return "", "", fmt.Errorf("package %s does not have exactly 1 branch for arch %s", pp.id, archs[0])
		}

		pp.branch = branches[0]
	}

	return pp.arch, pp.branch, err
}

func (pp *packagePrimitive) architecturesAndBranches() (out []ArchitectureBranch, err error) {
	dir, err := pp.dir()
	if err != nil {
		return
	}

	arches, err := subdirs(dir)
	if err != nil {
		return
	}
	for _, arch := range arches {
		branches, err := subdirs(path.Join(dir, arch))
		if err != nil {
			continue
		}
		for _, branch := range branches {
			out = append(out, ArchitectureBranch{arch, branch})
		}
	}

	return
}

func (pp *packagePrimitive) WithArchBranch(architecture, branch string) *packagePrimitive {
	npp := *pp
	npp.arch = architecture
	npp.branch = branch
	return &npp
}

func (pp *packagePrimitive) activeHash() (string, error) {
	if pp.hash != "" {
		return pp.hash, nil
	}

	dir, err := pp.dir()
	if err != nil {
		return "", err
	}

	arch, branch, err := pp.currentArchitectureAndBranch()
	if err != nil {
		return "", err
	}

	hash, err := os.Readlink(path.Join(dir, arch, branch, SymlinkActiveHash))
	pp.hash = hash
	return hash, err
}

func (pp *packagePrimitive) parseDeployFile() (*DeployData, error) {
	if pp.branch == "" {
		return nil, errors.New("branch is not set")
	}

	dir, err := pp.dir()
	if err != nil {
		return nil, err
	}

	arch, branch, err := pp.currentArchitectureAndBranch()
	if err != nil {
		return nil, err
	}

	hash, err := pp.activeHash()
	if err != nil {
		return nil, err
	}

	deployPath := path.Join(dir, arch, branch, hash, "deploy")
	contents, err := os.ReadFile(deployPath)
	if err != nil {
		return nil, err
	}

	return LoadDeployData(contents)
}

func subdirs(dir string) (out []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "." && entry.Name() != ".." {
			out = append(out, entry.Name())
		}
	}

	return
}

func init() {
	flag.StringVar(
		&systemLocation,
		"flatpak.system-dir",
		systemLocation,
		"directory where system-wide flatpak packages are installed")
}
