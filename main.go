package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jimsnab/go-cmdline"
)

type fileEntry struct {
	fullPath string
	modTime time.Time
}

var nameTable = map[string]bool{}
var sizeTable = map[int64]*fileEntry{}
var crcTable = map[string]*fileEntry{}
var hashTable = map[string]*fileEntry{}
var dups = []*fileEntry{}
var files int64
var bytesProcessed int64
var minSize = int64(10 * 1024)

func main() {
	cl := cmdline.NewCommandLine()

	cl.RegisterCommand(
		singleCommand,
		"~",
		"[--delete]?Delete the duplicates",
		"[--move <path-base>]?Move the duplicates under base",
		"[--size:<int-size>]?Minimum size of file to consider (default: 10K bytes)",
	)

	args := os.Args[1:] // exclude executable name in os.Args[0]
	err := cl.Process(args)
	if err != nil {
		cl.Help(err, "dupfinder", args)
	}
}

func singleCommand(args cmdline.Values) error {
	if args["--size"].(bool) {
		minSize = int64(args["size"].(int))
	}

	currentDirectory, err := os.Getwd()
	if err != nil {
		return err
	}

	stopCh := make(chan bool)

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go statusPrinter(args, currentDirectory, stopCh, wg)

	iterate(currentDirectory)
	stopCh <- true

	wg.Wait()
	return nil
}

func formatCommas(num int64) string {
	str := fmt.Sprintf("%d", num)
	re := regexp.MustCompile(`(\d+)(\d{3})`)
	for n := ""; n != str; {
			n = str
			str = re.ReplaceAllString(str, "$1,$2")
	}
	return str
}

func statusPrinter(args cmdline.Values, basePath string, ch chan bool, wg *sync.WaitGroup) {
	for {
		select {
		case <- ch:
			fmt.Fprintf(os.Stderr, "\rFiles: %s  Bytes: %s", formatCommas(files), formatCommas(bytesProcessed))
			goto end

		case <- time.After(time.Second * 1):
			fmt.Fprintf(os.Stderr, "\rFiles: %s  Bytes: %s", formatCommas(files), formatCommas(bytesProcessed))
		}
	}

end:
	fmt.Fprintf(os.Stderr, "\n\n")
	if args["--move"].(bool) {
		moveDups(basePath, args["base"].(string))
	} else {
		deleteDups(args["--delete"].(bool))
	}
	wg.Done()
} 

func iterate(basePath string) {
	filepath.WalkDir(basePath, func(fullPath string, de os.DirEntry, err error) error {
		if err != nil {
			log.Fatalf(err.Error())
			return err
		}

		_, nameExists := nameTable[fullPath]
		if nameExists {
			return nil
		}
		nameTable[fullPath] = true

		if de.IsDir() {
			name := de.Name()
			if name != "." && name != ".." && fullPath != basePath {
				iterate(fullPath)
			}
			return nil
		}

		files++

		fi, err := os.Stat(fullPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nCan't get stat of %s\n", fullPath)
			return nil
		}

		if fi.Size() < minSize {
			return nil
		}

		thisFile := &fileEntry{
			fullPath: fullPath,
			modTime: fi.ModTime(),
		}

		matchingSize, exists := sizeTable[fi.Size()]
		if exists {
			_, hasCrc := crcTable[matchingSize.fullPath]
			if !hasCrc {
				crc, err := fileCrc(matchingSize)
				if err != nil {
					fmt.Fprintf(os.Stderr, "\nCan't get CRC of %s - %s\n", matchingSize.fullPath, err.Error())
					return nil
				}
				crcTable[crc] = matchingSize
			}
			
			crc, err := fileCrc(thisFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nCan't get CRC of %s - %s\n", fullPath, err.Error())
				return nil
			}
	
			matchingCrc, exists := crcTable[crc]
			if exists {
				_, hasHash := hashTable[matchingCrc.fullPath]
				if !hasHash {
					hash, err := fileHash(matchingCrc)
					if err != nil {
						fmt.Fprintf(os.Stderr, "\nCan't get SHA hash of %s - %s\n", matchingCrc.fullPath, err.Error())
						return nil
					}
					hashTable[hash] = matchingCrc
				}

				hash, err := fileHash(thisFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "\nCan't get SHA hash of %s - %s\n", fullPath, err.Error())
					return nil
				}

				other, exists := hashTable[hash]
				if exists {
					if other.modTime.After(thisFile.modTime) {
						dups = append(dups, other)
						hashTable[hash] = thisFile
					} else {
						dups = append(dups, thisFile)
					}
				}
			} else {
				crcTable[crc] = thisFile
			}
		} else {
			sizeTable[fi.Size()] = thisFile
		}

		bytesProcessed += fi.Size()

		return nil
	})
}

func fileHash(entry *fileEntry) (hash string, err error) {
	var file *os.File
	file, err = os.Open(entry.fullPath)
	if err != nil {
		return
	}
	defer file.Close()

	h := sha256.New()
	if _, err = io.Copy(h, file); err != nil {
		return
	}

	hash = base64.StdEncoding.EncodeToString(h.Sum(nil))
	return
}

func fileCrc(entry *fileEntry) (crc string, err error) {
	var file *os.File
	file, err = os.Open(entry.fullPath)
	if err != nil {
		return
	}
	defer file.Close()

	h := crc32.NewIEEE()
	if _, err = io.Copy(h, file); err != nil {
		return
	}

	crc = base64.StdEncoding.EncodeToString(h.Sum(nil))
	return
}

func dumpCrc() {
	fmt.Println("CRC Table")
	for crc,entry := range crcTable {
		fmt.Println(crc, ": ", entry.fullPath)
	}
	fmt.Println()
}

func dumpHash() {
	fmt.Println("Hash Table")
	for hash,entry := range hashTable {
		fmt.Println(hash, ": ", entry.fullPath)
	}
	fmt.Println()
}

func deleteDups(delete bool) {
	fmt.Println("Duplicates")

	if len(dups) == 0 {
		fmt.Println("  (none)")
		return
	}

	for _,dup := range dups {
		fmt.Println(dup.fullPath)
		if delete {
			err := os.Remove(dup.fullPath)
			if err != nil {
				fmt.Println("  ERROR: ", err.Error())
			}
		}
	}
}

func moveDups(sourceBasePath, targetBasePath string) {
	fmt.Println("Duplicates")

	if len(dups) == 0 {
		fmt.Println("  (none)")
		return
	}

	targetBasePath = strings.ReplaceAll(targetBasePath, "\\", "/")

	for _,dup := range dups {
		subPath := strings.ReplaceAll(dup.fullPath[len(sourceBasePath):], "\\", "/")
		subPath = strings.TrimPrefix(subPath, "/")
		fmt.Println(subPath)

		targetPath := path.Join(targetBasePath, subPath)

		if _, err := os.Stat(targetPath); err == nil {
			fmt.Printf("  ERROR: Target file already exists: %s\n", targetPath)
		} else {
			os.MkdirAll(path.Dir(targetPath), 0755)
			err := os.Rename(dup.fullPath, targetPath)
			if err != nil {
				fmt.Println("  ERROR: ", err.Error())
			}
		}
	}	
}