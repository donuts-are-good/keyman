package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	sshDir      = ".ssh"
	configFile  = "config"
	keyFileExt  = ".pub"
	commentLine = "Comment: "
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	switch os.Args[1] {
	case "list":
		listKeys()
	case "config":
		showConfig()
	case "unused":
		listUnusedKeys()
	case "map":
		if len(os.Args) < 4 {
			log.Fatal("Usage: sshkeymanager map <key> <host>")
		}
		mapKey(os.Args[2], os.Args[3])
	case "unmap":
		if len(os.Args) < 4 {
			log.Fatal("Usage: sshkeymanager unmap <key> <host>")
		}
		unmapKey(os.Args[2], os.Args[3])
	case "generate":
		generateKey()
	case "delete":
		if len(os.Args) < 3 {
			log.Fatal("Usage: sshkeymanager delete <key>")
		}
		deleteKey(os.Args[2])
	case "audit":
		audit()
	case "help":
		printHelp()
	default:
		log.Fatal("Unknown command")
	}
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println(" - list:\n\tLists all SSH keys found in the ~/.ssh directory, along with their creation dates and comments if available.")
	fmt.Println("\n - config:\n\tShows a summary of the SSH configuration from ~/.ssh/config including mappings of keys to hosts.")
	fmt.Println("\n - unused:\n\tIdentifies and lists SSH keys that are not mapped to any hosts in the SSH configuration.")
	fmt.Println("\n - map <key> <host>:\n\tMaps an SSH key to a host in the SSH configuration.")
	fmt.Println("\n - unmap <key> <host>:\n\tRemoves a mapping of an SSH key from a host in the SSH configuration.")
	fmt.Println("\n - generate:\n\tGenerates a new SSH key using a guided interactive process.")
	fmt.Println("\n - delete <key>:\n\tDeletes an SSH key and removes it from any mappings in the SSH configuration.")
	fmt.Println("\n - audit:\n\tPerforms an audit of SSH keys and configuration, providing information like key age, unused keys, keys mapped to multiple hosts, etc.")
}

func listKeys() {
	keys, err := getKeys()
	if err != nil {
		log.Fatal(err)
	}

	for _, key := range keys {
		if key.comment != "" {
			fmt.Printf("Key: %s\nCreated: %s\nComment: %s\n\n", key.name, key.created.Format(time.RFC3339), key.comment)
		} else {
			fmt.Printf("Key: %s\nCreated: %s\n\n", key.name, key.created.Format(time.RFC3339))
		}
	}
}

func getKeys() ([]sshKey, error) {
	sshPath, err := getSSHPath()
	if err != nil {
		return nil, err
	}

	files, err := os.ReadDir(sshPath)
	if err != nil {
		return nil, err
	}

	var keys []sshKey
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), keyFileExt) {
			keyName := strings.TrimSuffix(file.Name(), keyFileExt)
			keyPath := filepath.Join(sshPath, file.Name())
			created, err := getFileCreationTime(keyPath)
			if err != nil {
				return nil, err
			}
			comment, err := getKeyComment(keyPath)
			if err != nil {
				return nil, err
			}

			keys = append(keys, sshKey{
				name:    keyName,
				path:    keyPath,
				created: created,
				comment: comment,
			})
		}
	}

	return keys, nil
}

func getSSHPath() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}

	return filepath.Join(usr.HomeDir, sshDir), nil
}

func getFileCreationTime(path string) (time.Time, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}

	return fileInfo.ModTime(), nil
}

func getKeyComment(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, commentLine) {
			return strings.TrimPrefix(line, commentLine), nil
		}
	}

	return "", nil
}

type sshKey struct {
	name    string
	path    string
	created time.Time
	comment string
}

func showConfig() {
	configPath, err := getConfigPath()
	if err != nil {
		log.Fatal(err)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(content))
}

func getConfigPath() (string, error) {
	sshPath, err := getSSHPath()
	if err != nil {
		return "", err
	}

	return filepath.Join(sshPath, configFile), nil
}

func listUnusedKeys() {
	keys, err := getKeys()
	if err != nil {
		log.Fatal(err)
	}

	config, err := parseConfig()
	if err != nil {
		log.Fatal(err)
	}

	usedKeys := make(map[string]bool)
	for _, keyPaths := range config {
		for _, keyPath := range keyPaths {
			usedKeys[filepath.Base(keyPath)] = true
		}
	}

	var unusedKeys []sshKey
	for _, key := range keys {
		if !usedKeys[key.name] {
			unusedKeys = append(unusedKeys, key)
		}
	}

	for _, key := range unusedKeys {
		if key.comment != "" {
			fmt.Printf("Key: %s\nCreated: %s\nComment: %s\n\n", key.name, key.created.Format(time.RFC3339), key.comment)
		} else {
			fmt.Printf("Key: %s\nCreated: %s\n\n", key.name, key.created.Format(time.RFC3339))
		}
	}
}

func isKeyUsed(key sshKey, config map[string][]string) bool {
	for _, keyPaths := range config {
		for _, keyPath := range keyPaths {
			keyBase := strings.TrimSuffix(filepath.Base(key.path), ".pub")
			if keyBase == filepath.Base(keyPath) {
				return true
			}
		}
	}
	return false
}

func parseConfig() (map[string][]string, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	config := make(map[string][]string)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Host ") {
			host := strings.TrimSpace(strings.TrimPrefix(line, "Host "))
			config[host] = nil
		} else if strings.HasPrefix(line, "IdentityFile ") {
			keyPath := strings.TrimSpace(strings.TrimPrefix(line, "IdentityFile "))
			keyPath, err = expandPath(keyPath)
			if err != nil {
				return nil, err
			}
			host := getLastHost(config)
			config[host] = append(config[host], keyPath)
		}
	}

	return config, nil
}

func getLastHost(config map[string][]string) string {
	var lastHost string
	for host := range config {
		lastHost = host
	}
	return lastHost
}

func mapKey(key, host string) {
	configPath, err := getConfigPath()
	if err != nil {
		log.Fatal(err)
	}

	config, err := parseConfig()
	if err != nil {
		log.Fatal(err)
	}

	if len(config[host]) >= 1 {
		fmt.Printf("The host %s already has a key mapped. Please unmap the current key before mapping a new one.\n", host)
		return
	}

	config[host] = append(config[host], key)

	err = writeConfig(configPath, config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Mapped key %s to host %s\n", key, host)
}

// func mapKey(key, host string) {
// 	configPath, err := getConfigPath()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	config, err := parseConfig()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	config[host] = append(config[host], key)

// 	err = writeConfig(configPath, config)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Printf("Mapped key %s to host %s\n", key, host)
// }

func unmapKey(key, host string) {
	configPath, err := getConfigPath()
	if err != nil {
		log.Fatal(err)
	}

	config, err := parseConfig()
	if err != nil {
		log.Fatal(err)
	}

	keyPaths := config[host]
	for i, keyPath := range keyPaths {
		if keyPath == key {
			config[host] = append(keyPaths[:i], keyPaths[i+1:]...)
			break
		}
	}

	err = writeConfig(configPath, config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Unmapped key %s from host %s\n", key, host)
}

func writeConfig(path string, config map[string][]string) error {
	var lines []string

	hosts := make([]string, 0, len(config))
	for host := range config {
		hosts = append(hosts, host)
	}

	sort.Strings(hosts)

	for _, host := range hosts {
		lines = append(lines, fmt.Sprintf("Host %s", host))
		keyPaths := config[host]
		for _, keyPath := range keyPaths {
			lines = append(lines, fmt.Sprintf("  IdentityFile %s", keyPath))
		}
		lines = append(lines, "")
	}

	content := strings.Join(lines, "\n")
	return os.WriteFile(path, []byte(content), 0644)
}

// func writeConfig(path string, config map[string]string) error {
// 	var lines []string

// 	hosts := make([]string, 0, len(config))
// 	for host := range config {
// 		hosts = append(hosts, host)
// 	}

// 	sort.Strings(hosts)

// 	for _, host := range hosts {
// 		lines = append(lines, fmt.Sprintf("Host %s", host))
// 		keyPath := config[host]
// 		lines = append(lines, fmt.Sprintf("  IdentityFile %s", keyPath))
// 		lines = append(lines, "")
// 	}

// 	content := strings.Join(lines, "\n")
// 	return os.WriteFile(path, []byte(content), 0644)
// }

// func writeConfig(path string, config map[string][]string) error {
// 	var lines []string

// 	hosts := make([]string, 0, len(config))
// 	for host := range config {
// 		hosts = append(hosts, host)
// 	}

// 	sort.Strings(hosts)

// 	for _, host := range hosts {
// 		lines = append(lines, fmt.Sprintf("Host %s", host))
// 		keyPaths := config[host]

// 		sort.Strings(keyPaths)

// 		for _, keyPath := range keyPaths {
// 			lines = append(lines, fmt.Sprintf("  IdentityFile %s", keyPath))
// 		}
// 		lines = append(lines, "")
// 	}

// 	content := strings.Join(lines, "\n")
// 	return os.WriteFile(path, []byte(content), 0644)
// }

func generateKey() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Let's generate a new SSH key.")
	fmt.Println("You will be asked for some information to help configure the key.")

	fmt.Println("Choose a key type:")
	fmt.Println("1. ed25519 (best)")
	fmt.Println("2. rsa (better)")
	fmt.Println("3. ecdsa (good)")
	fmt.Println("4. dsa (bad)")
	fmt.Print("Your choice (default is 1): ")

	keyTypeChoice, _ := reader.ReadString('\n')
	keyTypeChoice = strings.TrimSpace(keyTypeChoice)

	var keyType string
	switch keyTypeChoice {
	case "2":
		keyType = "rsa"
	case "3":
		keyType = "ecdsa"
	case "4":
		keyType = "dsa"
	default:
		keyType = "ed25519"
	}

	fmt.Print("Key name (default is id_ed25519_timestamp): ")
	keyName, _ := reader.ReadString('\n')
	keyName = strings.TrimSpace(keyName)
	if keyName == "" {
		keyName = fmt.Sprintf("id_ed25519_%d", time.Now().Unix())
	}

	fmt.Print("Comment: ")
	comment, _ := reader.ReadString('\n')
	comment = strings.TrimSpace(comment)

	sshPath, err := getSSHPath()
	if err != nil {
		log.Fatal(err)
	}

	keyPath := filepath.Join(sshPath, keyName)

	err = runCommand("ssh-keygen", "-o", "-a", "100", "-t", keyType, "-f", keyPath, "-C", comment)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated key %s\n", keyName)
}

func runCommand(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

// deleteKey deletes a key and removes it from the SSH config.
func deleteKey(key string) {
	fullKeyPath, err := getFullKeyPath(key)
	if err != nil {
		log.Fatal(err)
	}

	err = os.Remove(fullKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	pubFilePath := fullKeyPath + ".pub"
	err = os.Remove(pubFilePath)
	if err != nil {
		log.Fatal(err)
	}

	configPath, err := getConfigPath()
	if err != nil {
		log.Fatal(err)
	}

	config, err := parseConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Iterate over each host and its keys.
	for host, keyPaths := range config {
		// Iterate over the keys of this host.
		for i, keyPath := range keyPaths {
			if keyPath == fullKeyPath {
				// Remove the key from the host's key paths.
				keyPaths = append(keyPaths[:i], keyPaths[i+1:]...)

				if len(keyPaths) == 0 {
					// If the host has no more keys, delete the host from the config.
					delete(config, host)
				} else {
					// Otherwise, update the host's keys.
					config[host] = keyPaths
				}

				break
			}
		}
	}

	err = writeConfig(configPath, config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Deleted key %s\n", key)
}

func getFullKeyPath(key string) (string, error) {
	sshPath, err := getSSHPath()
	if err != nil {
		return "", err
	}

	if filepath.IsAbs(key) {
		return key, nil
	} else {
		return filepath.Join(sshPath, key), nil
	}
}

// func deleteKey(key string) {
// 	var fullKeyPath string
// 	if filepath.IsAbs(key) {
// 		fullKeyPath = key
// 	} else {
// 		sshPath, err := getSSHPath()
// 		if err != nil {
// 			log.Fatal(err)
// 		}

// 		fullKeyPath = filepath.Join(sshPath, key)
// 	}

// 	err := os.Remove(fullKeyPath)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	pubFilePath := fullKeyPath + ".pub"
// 	err = os.Remove(pubFilePath)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	configPath, err := getConfigPath()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	content, err := os.ReadFile(configPath)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	configLines := strings.Split(string(content), "\n")

// 	newConfigLines := make([]string, 0, len(configLines))
// 	for _, line := range configLines {
// 		if strings.Contains(line, fullKeyPath) {
// 			newConfigLines = append(newConfigLines, "#"+line)
// 		} else {
// 			newConfigLines = append(newConfigLines, line)
// 		}
// 	}

// 	newContent := strings.Join(newConfigLines, "\n")
// 	err = os.WriteFile(configPath, []byte(newContent), 0644)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Printf("Deleted key %s\n", key)
// }

func audit() {
	keys, err := getKeys()
	if err != nil {
		log.Fatal(err)
	}

	config, err := parseConfig()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("SSH Key Audit:")
	fmt.Println("==============")

	fmt.Println("\n--- Keys ---")
	for _, key := range keys {
		keyUsed := isKeyUsed(key, config)
		timeSinceCreation := time.Since(key.created)
		timeSinceCreationHours := timeSinceCreation.Hours()
		timeString := ""
		if timeSinceCreationHours < 24 {
			timeString = fmt.Sprintf("%.1f hours ago", timeSinceCreationHours)
		} else {
			timeString = fmt.Sprintf("%.1f days ago", timeSinceCreationHours/24)
		}

		if key.comment != "" {
			fmt.Printf("Key: %s\nCreated: %s (%s)\nIn Use: %t\nComment: %s\n\n", key.name, key.created.Format(time.RFC3339), timeString, keyUsed, key.comment)
		} else {
			fmt.Printf("Key: %s\nCreated: %s (%s)\nIn Use: %t\n\n", key.name, key.created.Format(time.RFC3339), timeString, keyUsed)
		}
	}

	fmt.Println("\n--- Unused Keys ---")
	var unusedKeys []sshKey
	for _, key := range keys {
		if !isKeyUsed(key, config) {
			unusedKeys = append(unusedKeys, key)
		}
	}
	if len(unusedKeys) == 0 {
		fmt.Println("No unused keys found")
	} else {
		for _, key := range unusedKeys {
			if key.comment != "" {
				fmt.Printf("Key: %s\nCreated: %s\nComment: %s\n\n", key.name, key.created.Format(time.RFC3339), key.comment)
			} else {
				fmt.Printf("Key: %s\nCreated: %s\n\n", key.name, key.created.Format(time.RFC3339))
			}
		}
	}

	fmt.Println("\n--- Multiple Mappings ---")
	multipleMappings := findMultipleMappings(config)
	if len(multipleMappings) == 0 {
		fmt.Println("No keys with multiple mappings found")
	} else {
		for key, hosts := range multipleMappings {
			fmt.Printf("Key: %s\nMapped to Hosts: %s\n\n", key, strings.Join(hosts, ", "))
		}
	}
}

func findMultipleMappings(config map[string][]string) map[string][]string {
	keyMappings := make(map[string][]string)
	for host, keyPaths := range config {
		for _, keyPath := range keyPaths {
			keyMappings[keyPath] = append(keyMappings[keyPath], host)
		}
	}

	multipleMappings := make(map[string][]string)
	for key, hosts := range keyMappings {
		if len(hosts) > 1 {
			multipleMappings[key] = hosts
		}
	}

	return multipleMappings
}

func expandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}
		return filepath.Join(usr.HomeDir, path[1:]), nil
	}
	return filepath.Abs(path)
}
