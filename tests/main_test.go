//go:build integration

package main_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/flags"
	"github.com/docker/compose/v5/pkg/api"
	"github.com/docker/compose/v5/pkg/compose"
	clientapi "github.com/moby/moby/client"
)

const (
	MAX_LEVELS = 4
	MAX_SIZE   = 1024 * 10 // 10 KB
	MAX_DIRS   = 5
	MAX_FILES  = 8
)

const rootDir = "./.test-source"

func randInt(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(fmt.Sprintf("failed to generate random int: %v", err))
	}
	return n.Int64()
}

func generateTree(currentPath string, currentLevel int, maxLevels int) error {
	numFiles := int(randInt(MAX_FILES + 1))
	for i := 0; i < numFiles; i++ {
		fileName := fmt.Sprintf("file_%d.bin", i)
		filePath := filepath.Join(currentPath, fileName)
		size := int(randInt(MAX_SIZE + 1))
		data := make([]byte, size)
		rand.Read(data)
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write file %s: %w", filePath, err)
		}
	}

	if currentLevel >= maxLevels {
		return nil
	}

	numDirs := int(randInt(MAX_DIRS + 1))
	for i := 0; i < numDirs; i++ {
		dirName := fmt.Sprintf("dir_%d", i)
		dirPath := filepath.Join(currentPath, dirName)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create dir %s: %w", dirPath, err)
		}
		if err := generateTree(dirPath, currentLevel+1, maxLevels); err != nil {
			return err
		}
	}

	return nil
}

func mktree() {
	if err := os.RemoveAll(rootDir); err != nil {
		fmt.Fprintf(os.Stderr, "failed to remove existing root dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create root dir: %v\n", err)
		os.Exit(1)
	}

	maxLevels := 1 + int(randInt(MAX_LEVELS))
	fmt.Printf("Generating file tree in %s (max levels: %d)...\n", rootDir, maxLevels)

	if err := generateTree(rootDir, 1, maxLevels); err != nil {
		fmt.Fprintf(os.Stderr, "error generating tree: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Done.")
}

func cleanupProjectContainers(ctx context.Context, dockerCLI *command.DockerCli, projectName string) error {
	projectFilters := make(clientapi.Filters).Add("label", api.ProjectLabel+"="+projectName)
	containers, err := dockerCLI.Client().ContainerList(ctx, clientapi.ContainerListOptions{
		All:     true,
		Filters: projectFilters,
	})
	if err != nil {
		return err
	}

	for _, ctr := range containers.Items {
		if _, err := dockerCLI.Client().ContainerRemove(ctx, ctr.ID, clientapi.ContainerRemoveOptions{
			Force:         true,
			RemoveVolumes: true,
		}); err != nil {
			return err
		}
	}

	return nil
}

func composeCreatePxars() error {
	ctx := context.Background()

	dockerCLI, err := command.NewDockerCli()
	if err != nil {
		return fmt.Errorf("failed to create docker CLI: %w", err)
	}
	err = dockerCLI.Initialize(&flags.ClientOptions{})
	if err != nil {
		return fmt.Errorf("failed to initialize docker CLI: %w", err)
	}

	service, err := compose.NewComposeService(dockerCLI)
	if err != nil {
		return fmt.Errorf("failed to create compose service: %w", err)
	}

	project, err := service.LoadProject(ctx, api.ProjectLoadOptions{
		ConfigPaths: []string{"compose.yml"},
	})
	if err != nil {
		return fmt.Errorf("failed to load project: %w", err)
	}

	project.Environment = project.Environment.Merge(types.Mapping{
		"UID": fmt.Sprintf("%d", os.Getuid()),
		"GID": fmt.Sprintf("%d", os.Getgid()),
	})

	defer func() {
		if cleanupErr := cleanupProjectContainers(ctx, dockerCLI, project.Name); cleanupErr != nil {
			log.Printf("Final cleanup failed for project %s: %v", project.Name, cleanupErr)
		}
	}()

	err = cleanupProjectContainers(ctx, dockerCLI, project.Name)
	if err != nil {
		return fmt.Errorf("failed to clean existing project containers: %w", err)
	}

	_, err = service.RunOneOffContainer(ctx, project, api.RunOptions{
		Service:       "pbs",
		AutoRemove:    true,
		RemoveOrphans: true,
		Detach:        false,
	})

	if err != nil {
		return fmt.Errorf("failed to run one-off container for pbs: %w", err)
	}

	_, err = service.RunOneOffContainer(ctx, project, api.RunOptions{
		Service:       "tizbac",
		AutoRemove:    true,
		RemoveOrphans: true,
		Detach:        false,
	})

	if err != nil {
		return fmt.Errorf("failed to run one-off container for tizbac: %w", err)
	}

	cleanupProjectContainers(ctx, dockerCLI, project.Name)

	_, err = service.RunOneOffContainer(ctx, project, api.RunOptions{
		Service:       "gopxar",
		AutoRemove:    true,
		RemoveOrphans: true,
		Detach:        false,
	})

	if err != nil {
		return fmt.Errorf("failed to run one-off container for gopxar: %w", err)
	}

	log.Printf("Successfully created pxar: %s", project.Name)
	return nil
}

func rmAll() {
	files, err := os.ReadDir(".test-pxar")
	if err != nil {
		log.Fatalf("Failed to read .test-pxar directory: %v", err)
	}
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".pxar") || strings.Contains(file.Name(), ".pxar.")) {
			err := os.Remove(filepath.Join(".test-pxar", file.Name()))
			if err != nil {
				log.Printf("Failed to remove file %s: %v", file.Name(), err)
			}
		}
	}

	files, err = os.ReadDir(".test-source")
	if err != nil {
		log.Fatalf("Failed to read .test-source directory: %v", err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "file_") || strings.HasPrefix(file.Name(), "dir_") {
			err := os.RemoveAll(filepath.Join(".test-source", file.Name()))
			if err != nil {
				log.Printf("Failed to remove %s: %v", file.Name(), err)
			}
		}
	}

	files, err = os.ReadDir(".test-restore")
	if err != nil {
		log.Fatalf("Failed to read .test-restore directory: %v", err)
	}
	for _, file := range files {
		if file.Name() != ".gitkeep" {
			err := os.RemoveAll(filepath.Join(".test-restore", file.Name()))
			if err != nil {
				log.Printf("Failed to remove %s: %v", file.Name(), err)
			}
		}
	}

}

// Compares two directory trees for equality in structure and content. Returns true if they are identical, false otherwise.
func CompareDirectoryTree(dir1, dir2 string) (bool, error) {
	type fileEntry struct {
		relPath string
		isDir   bool
		hash    string
	}

	collectEntries := func(root string) ([]fileEntry, error) {
		var entries []fileEntry
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if rel == "." {
				return nil
			}
			entry := fileEntry{relPath: rel, isDir: info.IsDir()}
			if !info.IsDir() {
				f, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("failed to open %s: %w", path, err)
				}
				defer f.Close()
				h := sha256.New()
				if _, err := io.Copy(h, f); err != nil {
					return fmt.Errorf("failed to hash %s: %w", path, err)
				}
				entry.hash = fmt.Sprintf("%x", h.Sum(nil))
			}
			entries = append(entries, entry)
			return nil
		})
		return entries, err
	}

	entries1, err := collectEntries(dir1)
	if err != nil {
		return false, fmt.Errorf("failed to collect entries from %s: %w", dir1, err)
	}
	entries2, err := collectEntries(dir2)
	if err != nil {
		return false, fmt.Errorf("failed to collect entries from %s: %w", dir2, err)
	}

	if len(entries1) != len(entries2) {
		return false, nil
	}

	index := make(map[string]struct {
		isDir bool
		hash  string
	}, len(entries2))
	for _, e := range entries2 {
		index[e.relPath] = struct {
			isDir bool
			hash  string
		}{e.isDir, e.hash}
	}

	for _, e := range entries1 {
		e2, ok := index[e.relPath]
		if !ok || e2.isDir != e.isDir || e2.hash != e.hash {
			return false, nil
		}
	}

	return true, nil
}

func TestMain(m *testing.M) {
	rmAll()

	mktree()

	if err := composeCreatePxars(); err != nil {
		log.Fatalf("composeCreatePxars failed: %v", err)
	}

	ex := m.Run()

	// rmAll()
	os.Exit(ex)
}

// Ensure that the two PXARs created by tizbac/pxar-cli are identical in content and structure
func TestComparison(t *testing.T) {
	// Extract all files
	ctx := context.Background()

	dockerCLI, err := command.NewDockerCli()
	if err != nil {
		t.Fatalf("failed to create docker CLI: %v", err)
	}
	err = dockerCLI.Initialize(&flags.ClientOptions{})
	if err != nil {
		t.Fatalf("failed to initialize docker CLI: %v", err)
	}

	service, err := compose.NewComposeService(dockerCLI)
	if err != nil {
		t.Fatalf("failed to create compose service: %v", err)
	}

	project, err := service.LoadProject(ctx, api.ProjectLoadOptions{
		ConfigPaths: []string{"compose.yml"},
	})
	if err != nil {
		t.Fatalf("failed to load project: %v", err)
	}

	project.Environment = project.Environment.Merge(types.Mapping{
		"UID": fmt.Sprintf("%d", os.Getuid()),
		"GID": fmt.Sprintf("%d", os.Getgid()),
	})

	defer func() {
		if cleanupErr := cleanupProjectContainers(ctx, dockerCLI, project.Name); cleanupErr != nil {
			log.Printf("Final cleanup failed for project %s: %v", project.Name, cleanupErr)
		}
	}()

	err = cleanupProjectContainers(ctx, dockerCLI, project.Name)
	if err != nil {
		t.Fatalf("failed to clean existing project containers: %v", err)
	}

	_, err = service.RunOneOffContainer(ctx, project, api.RunOptions{
		Service:       "restore",
		AutoRemove:    true,
		RemoveOrphans: true,
		Detach:        false,
	})

	if err != nil {
		t.Fatalf("failed to run one-off container for restore: %v", err)
	}

	equal, err := CompareDirectoryTree(".test-restore/tizbac", ".test-restore/pbs")
	if err != nil {
		t.Fatalf("failed to compare directory trees: %v", err)
	}
	if !equal {
		t.Fatalf("directory trees are not identical")
	}

	equal, err = CompareDirectoryTree(".test-restore/gopxar", ".test-restore/pbs")
	if err != nil {
		t.Fatalf("failed to compare directory trees: %v", err)
	}
	if !equal {
		t.Fatalf("directory trees are not identical")
	}
}
