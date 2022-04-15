package main

import (
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io"
    "os"
    "strings"
)

func main() {
    file := "list_trusted_cas/public_cacerts.txt"
    certs, errs := loadCerts(file)
    fmt.Println("Certs: ", len(certs))
    fmt.Println("Errors: ", len(errs))

   /* if len(errs) > 0 {
        for _, err := range errs {
            fmt.Println(err.Error())
        }
    }*/

    if len(certs) == 0 {
        fmt.Println("Got no certificates")
        return
    }

    certParentsMap, certChildrenMap, subjectCertsMap := buildGraph(certs)
    fmt.Println("Distinct subjects: ", len(subjectCertsMap))

    pathLengths := computePathLenghts(certs, certChildrenMap)
    var maxLengthPath = 0
    var maxLengthCert = 0
    for cert, length := range pathLengths {
        if length > maxLengthPath {
            maxLengthPath = length
            maxLengthCert = cert
        }
    }
    fmt.Println("Max path lengths: ", maxLengthPath, " starting from ", maxLengthCert)

    outputFile := "graphs/combined.dot"
    outputGraph(outputFile, certChildrenMap, certs)

    outputFile = "graphs/longest.dot"
    outputGraphFromNode(outputFile, certParentsMap, certChildrenMap, certs, maxLengthCert)

    for node, length := range pathLengths {
        if length <= 5 {
            continue
        }

        outputFile = fmt.Sprintf("graphs/node-%v.dot", node)
        outputGraphFromNode(outputFile, certParentsMap, certChildrenMap, certs, node)
    }
}

func loadCerts(allCerts string) ([]*x509.Certificate, []error) {
    fileHandle, err := os.Open(allCerts)
    if err != nil {
        return nil, []error{ err }
    }

    pemBytes, err := io.ReadAll(fileHandle)
    if err != nil {
        return nil, []error{ err }
    }

    var certIndex = 0
    var certs []*x509.Certificate
    var errs []error
    for len(pemBytes) > 0 {
        certIndex += 1

        var pemBlock *pem.Block
        pemBlock, pemBytes = pem.Decode(pemBytes)
        if pemBlock == nil {
            break
        }

        newCerts, err := x509.ParseCertificates(pemBlock.Bytes)
        if err != nil {
            certPem := pem.EncodeToMemory(pemBlock)
            certString := "\t" + strings.ReplaceAll(string(certPem), "\n", "\n\t")
            thisErr := fmt.Errorf("cert %v: %v\n%v", certIndex, err, certString)
            errs = append(errs, thisErr)
            continue
        }

        if len(newCerts) > 1 {
            thisErr := fmt.Errorf("got multiple certs at index %v: %v\n", certIndex, len(newCerts))
            errs = append(errs, thisErr)
            continue
        }

        certs = append(certs, newCerts...)
    }

    return certs, errs
}

func buildGraph(certs []*x509.Certificate) (map[int][]int, map[int][]int, map[string][]int) {
	certParentsMap := make(map[int][]int, len(certs))
	certChildrenMap := make(map[int][]int, len(certs))
    subjectCertsMap := make(map[string][]int, len(certs))

    for index, cert := range certs {
        subjectCertsMap[string(cert.RawSubject)] = append(subjectCertsMap[string(cert.RawSubject)], index)
    }

    for child, childCert := range certs {
        issuer := string(childCert.RawIssuer)
        for _, parent := range subjectCertsMap[issuer] {
            if child == parent {
                continue
            }

            parentCert := certs[parent]
            if err := childCert.CheckSignatureFrom(parentCert); err != nil {
                continue
            }

            certParentsMap[child] = append(certParentsMap[child], parent)
            certChildrenMap[parent] = append(certChildrenMap[parent], child)
        }
    }

    return certParentsMap, certChildrenMap, subjectCertsMap
}

func computePathLenghts(certs []*x509.Certificate, certChildrenMap map[int][]int) (map[int]int) {
    maxPathLengths := make(map[int]int, len(certs))

    for starting := range certs {
        pathLengths := computePathLengthsFromNode(certs, certChildrenMap, starting)

        for cert, length := range pathLengths {
            current, ok := maxPathLengths[cert]
            if !ok || length > current {
                current = length
            }
            maxPathLengths[cert] = current
        }
    }

    return maxPathLengths
}

func computePathLengthsFromNode(certs []*x509.Certificate, certChildrenMap map[int][]int, starting int) map[int]int {
    visited := make(map[int]bool, len(certs))
    pathLengths := make(map[int]int, len(certs))
    var toVisit = []int{starting}
    pathLengths[starting] = 1

    for len(toVisit) > 0 {
        var cert int
        cert, toVisit = toVisit[0], toVisit[1:]

        if processed, ok := visited[cert]; ok && processed {
            continue
        }

        visited[cert] = true
        newLength := pathLengths[cert] + 1

        for _, child := range certChildrenMap[cert] {
            existingLength, ok := pathLengths[child]
            if !ok || existingLength < newLength {
                existingLength = newLength
            }

            pathLengths[child] = existingLength

            toVisit = append(toVisit, child)
        }
    }

    return pathLengths
}

func outputGraph(outputFile string, certChildrenMap map[int][]int, certs []*x509.Certificate) {
    file, err := os.OpenFile(outputFile, os.O_CREATE | os.O_WRONLY | os.O_TRUNC, 0644)
    if err != nil {
        fmt.Println("error opening %v: %v", outputFile, err)
        return
    }

    file.WriteString("digraph forest {\n")
    for index /*, cert*/ := range certs {
        //subject := cert.Subject.String()
        file.WriteString(fmt.Sprintf(" c%v;\n", index))
    }

    for source, sinks := range certChildrenMap {
        for _, sink := range sinks {
            file.WriteString(fmt.Sprintf(" c%v -> c%v;\n", source, sink))
        }
    }

    file.WriteString("}\n")
}

func outputGraphFromNode(outputFile string, certParentsMap map[int][]int, certChildrenMap map[int][]int, certs []*x509.Certificate, node int) {
    pathLengths := computePathLengthsFromNode(certs, certParentsMap, node)
    fmt.Println("Total reachable from", node, ":", len(pathLengths))

    file, err := os.OpenFile(outputFile, os.O_CREATE | os.O_WRONLY | os.O_TRUNC, 0644)
    if err != nil {
        fmt.Printf("error opening %v: %v\n", outputFile, err)
        return
    }

    file.WriteString("digraph forest {\n")

    for index := range pathLengths {
        cert := certs[index]
        subject := cert.Subject.String()
        file.WriteString(fmt.Sprintf(" c%v [label=\"%v\"];\n", index, subject))
    }

    for parent := range pathLengths {
        for _, child := range certChildrenMap[parent] {
            if _, ok := pathLengths[child]; !ok {
                continue
            }
            file.WriteString(fmt.Sprintf(" c%v -> c%v;\n", parent, child))
        }
    }

    file.WriteString("}\n")
}
