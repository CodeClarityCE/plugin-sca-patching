package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"

	"slices"
)

// SplitOnLastOccurence splits the target string on the last occurrence of the specified delimiter.
// It returns a slice of strings where the first element is the substring before the delimiter,
// and the second element is the substring after the delimiter. If the delimiter is not found,
// it returns a slice containing the target string itself.
func SplitOnLastOccurence(target string, delimiter rune) []string {

	var lastIndex int = -1

	for idx, char := range target {
		if char == delimiter {
			lastIndex = idx
		}
	}

	if lastIndex > -1 {

		slices := []string{}
		slices = append(slices, target[0:lastIndex])
		if len(target) >= lastIndex+1 {
			slices = append(slices, target[lastIndex+1:])
		}

		return slices

	} else {
		return []string{target}
	}

}

// GetNEvenlySpacedElements returns n evenly spaced elements from the given array.
// The function takes an array of any type and an integer n as input.
// If the array is empty, it returns an empty array.
// The function calculates the step size based on the length of the array and n.
// It then selects the elements at the calculated indices and returns them in a new array.
func GetNEvenlySpacedElements[T any](array []T, n int) []T {

	if len(array) == 0 {
		return array
	}

	indicies := []int{}

	stepSize := int(math.Ceil(float64(len(array)) / float64(n)))

	indicies = append(indicies, 0)

	for i := stepSize; len(indicies) < n && i < len(array); i += stepSize {
		indicies = append(indicies, i)
	}

	if !slices.Contains(indicies, len(array)-1) {
		indicies = append(indicies, len(array)-1)
	}

	arrayToReturn := []T{}

	for idx := range indicies {
		arrayToReturn = append(arrayToReturn, array[idx])
	}

	return arrayToReturn

}

type PackageFile struct {
	Name                 string            `json:"name,omitempty"`
	Version              string            `json:"version,omitempty"`
	Description          string            `json:"description,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	BundleDependencies   []string          `json:"bundleDependencies,omitempty"`
	BundledDependencies  []string          `json:"bundledDependencies,omitempty"`
	WorkSpaces           []string          `json:"workspaces"`
}

// ParsePackageFile parses the package file located at the given file path and returns the parsed package file data, the raw package file data as a string, and any error encountered during the parsing process.
// The package file is expected to be in JSON format.
func ParsePackageFile(filePath string) (PackageFile, string, error) {

	packageFileData, err := getPackageFileData(filePath)

	if err != nil {
		return PackageFile{}, "", err
	}

	var packageFile PackageFile
	// Unmarshal the YAML string into the data map
	err = json.Unmarshal(packageFileData, &packageFile)
	if err != nil {
		return PackageFile{}, "", err
	}

	return packageFile, string(packageFileData), nil

}

// getPackageFileData reads the contents of a package file specified by the given file path.
// It returns the byte slice containing the file data and any error encountered during the process.
func getPackageFileData(filePath string) ([]byte, error) {
	packageFilePath := filePath

	packageFileData, err := ReadFile(packageFilePath)
	if err != nil {
		return nil, err
	}

	return packageFileData, err
}

// ReadFile reads the content of a file specified by the filePath parameter.
// It returns the content of the file as a byte slice and an error if any occurred.
func ReadFile(filePath string) ([]byte, error) {
	// Read the file and return content
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error when opening file: %s", err)
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	content, err := io.ReadAll(r)
	if err != nil {
		log.Printf("Error when opening file: %s", err)
		return nil, err
	}
	return content, nil
}

type MapItem struct {
	Key, Value interface{}
}

type MapSlice []MapItem

// MarshalJSON converts the MapSlice to its JSON representation.
// It marshals each key-value pair in the MapSlice to JSON and returns the resulting byte slice.
// The keys are converted to strings using the default formatting.
// The returned byte slice represents a JSON object.
// If an error occurs during marshaling, it returns nil and the error.
func (ms MapSlice) MarshalJSON() ([]byte, error) {
	buf := &bytes.Buffer{}
	buf.Write([]byte{'{'})
	for i, mi := range ms {
		b, err := json.Marshal(&mi.Value)
		if err != nil {
			return nil, err
		}
		buf.WriteString(fmt.Sprintf("%q:", fmt.Sprintf("%v", mi.Key)))
		buf.Write(b)
		if i < len(ms)-1 {
			buf.Write([]byte{','})
		}
	}
	buf.Write([]byte{'}'})
	return buf.Bytes(), nil
}
